#!/usr/bin/env python3
"""Internet Receipt Printer: your public web form -> your own relay's receipt queue -> a network ESC/POS receipt printer
on raw TCP port 9100. Stdlib only. Outbound only (no port forwarding).

How it behaves:
- Checks the queue (GET <queue_url>/bridge/next, Bearer queue_token) with one short request a minute, and ONLY while
  the printer is ready, so jobs are never taken off the queue early. After a print it reports back (/bridge/ack).
- Finds the printer by itself (or uses printer_ip): it never sends bytes to a page printer. Any host that answers on
  IPP (port 631) is skipped before anything is sent, because whatever reaches a page printer's port 9100 gets printed.
- Daily paper guard (daily_receipts). Missing/offline printer = polite re-checks, no spinning, no burned jobs.
- Reports its state in sensor.internet_receipt_printer.
- Optional pairing (no pasting): with queue_url/queue_token empty and nothing saved, it opens a 30-minute pairing
  window: publishes a one-time PUBLIC key in sensor.internet_receipt_printer_pairing_request and prints its
  fingerprint in this app's own log. Whoever set up your relay (Hark: `gw.py pair-receipt`) checks the fingerprint
  against the log, then answers with the relay address + receipt token sealed to that key. Saved in /data (0600).
  Options always win over a saved pairing; `reset_pairing` forgets the saved one (once per switch-on).
"""
import ipaddress, json, os, re, socket, subprocess, textwrap, threading, time, urllib.error, urllib.parse, urllib.request
import pairing

os.umask(0o077)
VERSION = "1.0.3"
COLS = 42
PORT = 9100
SCAN_EVERY = 600        # full search for a missing printer: every 10 minutes
CHECK_EVERY = 30        # known-but-offline printer: re-check every 30 s (home network only, no relay request)
POLL_EVERY = 60         # printer ready: check the relay's queue once a minute
DATA_DIR = os.environ.get("DATA_DIR", "/data")
STATE_FILE = os.path.join(DATA_DIR, "state.json")
SENSOR = "sensor.internet_receipt_printer"
RELAY_FILE = os.path.join(DATA_DIR, "relay.json")     # relay address + receipt token from pairing (0600, never printed)
PAIR_REQUEST = "sensor.internet_receipt_printer_pairing_request"
PAIR_ANSWER = "sensor.internet_receipt_printer_pairing"
PAIR_WINDOW = int(os.environ.get("IRP_PAIR_WINDOW", "1800"))   # 30 min after start
TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-.~+/=]{16,200}$")


def load_opts():
    try:
        return json.load(open(os.environ.get("OPTIONS_FILE", "/data/options.json")))
    except Exception as e:
        print("no options file", e)
        return {}


def valid_queue_url(u):
    """https only (http allowed for 127.0.0.1 in tests), no credentials, query or fragment in the address."""
    try:
        p = urllib.parse.urlsplit(str(u or "").strip())
    except Exception:
        return None
    local_test = os.environ.get("IRP_TEST_ALLOW_HTTP") == "1" and p.hostname == "127.0.0.1"
    if (p.scheme != "https" and not local_test) or not p.hostname or p.username or p.password or p.query or p.fragment:
        return None
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?", p.hostname) or not re.fullmatch(r"[A-Za-z0-9/_.~-]*", p.path):
        return None   # plain host names and paths only (nothing that could fake a log line)
    try:
        p.port
    except ValueError:
        return None
    return f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "") + p.path.rstrip("/")


# ---------------- Home Assistant (status sensor only) ----------------
def _sup_token():
    t = os.environ.get("SUPERVISOR_TOKEN") or os.environ.get("HASSIO_TOKEN")
    for p in ("/run/s6/container_environment/SUPERVISOR_TOKEN", "/var/run/s6/container_environment/SUPERVISOR_TOKEN"):
        if not t:
            try:
                t = open(p).read().strip()
            except Exception:
                pass
    return t or ""


HA_BASE = os.environ.get("HA_API_BASE", "http://supervisor/core/api")


def ha(method, path, body=None, timeout=10):
    req = urllib.request.Request(HA_BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {_sup_token()}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"null")


# ---------------- daily paper guard ----------------
_cap_lock = threading.Lock()


def _counts():
    try:
        d = json.load(open(os.path.join(DATA_DIR, "counts.json")))
    except Exception:
        d = {}
    today = time.strftime("%Y-%m-%d")
    return d if d.get("date") == today else {"date": today, "receipts": 0}


def receipts_allowed(opts):
    try:
        cap = max(1, int(opts.get("daily_receipts") or 200))
    except (TypeError, ValueError):
        cap = 200
    with _cap_lock:
        return _counts()["receipts"] < cap


def count_receipt():
    with _cap_lock:
        d = _counts()
        d["receipts"] += 1
        fd = os.open(os.path.join(DATA_DIR, "counts.json"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(d, f)
        return d


# ---------------- printer ----------------
def query_id(ip, timeout=1.5):
    """Ask an ESC/POS printer for its model name (GS I 67). Returns name or None."""
    try:
        with socket.create_connection((ip, PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"\x1dI\x43")
            data, end = b"", time.time() + timeout
            while time.time() < end:
                try:
                    chunk = s.recv(64)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if b"\x00" in data:
                    break
            m = re.search(rb"_([ -~]+?)\x00", data)
            return m.group(1).decode() if m else None
    except Exception:
        return None


def local_nets():
    nets = set()
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True).stdout
        for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out):
            ip = m.group(1)
            if ip.startswith(("127.", "172.30.", "172.17.", "169.254.")):   # loopback, HA internal and Docker networks
                continue
            nets.add(ipaddress.ip_network(f"{ip}/{max(int(m.group(2)), 24)}", strict=False))
    except Exception as e:
        print("ip addr failed", e)
    return list(nets)


def home_ip(ip):
    """printer_ip must be a private home-network address (never loopback, link-local or HA's internal networks)."""
    try:
        a = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return False
    if a.version != 4 or a.is_loopback or a.is_link_local or a.is_multicast:
        return False
    for bad in ("172.30.32.0/23", "172.30.33.0/24", "172.17.0.0/16"):
        if a in ipaddress.ip_network(bad):
            return False
    return any(a in ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def _port_open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def is_page_printer(ip):
    return _port_open(ip, 631, timeout=1)


def discover(nets=None):
    """Finds the ESC/POS receipt printer WITHOUT printing on other printers: skip any host that speaks IPP (631)."""
    hits, lock = [], threading.Lock()

    def probe(ip):
        if not _port_open(ip, PORT) or _port_open(ip, 631):
            return
        name = query_id(ip)
        with lock:
            hits.append((ip, name))

    for net in (nets if nets is not None else local_nets()):
        ths = []
        for h in net.hosts():
            t = threading.Thread(target=probe, args=(str(h),), daemon=True); t.start(); ths.append(t)
            if len(ths) >= 32:
                for t in ths: t.join()
                ths = []
        for t in ths: t.join()
    for ip, name in hits:
        if name:
            return ip, name
    return None, None


def status(ip):
    """'ready', 'no_paper', 'cover_open', 'not_receipt' or 'unreachable'."""
    if is_page_printer(ip):
        return "not_receipt"      # a page printer: status bytes would print junk pages
    try:
        with socket.create_connection((ip, PORT), timeout=3) as s:
            s.settimeout(3)
            s.sendall(b"\x10\x04\x02"); off = s.recv(1)[0]
            s.sendall(b"\x10\x04\x04"); pap = s.recv(1)[0]
            if pap & 0x60 or off & 0x20:
                return "no_paper"
            if off & 0x04:
                return "cover_open"
            return "ready"
    except Exception:
        return "unreachable"


def receipt(j):
    b = bytearray(b"\x1b@\x1bt\x00")
    t = lambda s: b.extend(str(s).encode("ascii", "replace"))   # noqa: E731
    b += b"\x1ba\x01\x1bE\x01\x1d!\x11"; t(str(j.get("title") or "INCOMING").upper()[:40] + "\n")
    b += b"\x1d!\x00\x1bE\x00"; t(f"#{int(j.get('number') or 0):04d}   {str(j.get('when') or '')[:30]}\n" + "-" * COLS + "\n\n")
    b += b"\x1ba\x00\x1d!\x00"   # message text at normal size
    body = re.sub(r"[\x00-\x09\x0b-\x1f\x7f]", "", str(j.get("body") or ""))[:2000]   # no printer control codes from the web
    for para in body.split("\n")[:40]:
        t((textwrap.fill(para, COLS) if para else "") + "\n")
    b += b"\x1d!\x00\x1ba\x01"; t("\n" + "-" * COLS + "\n")
    author = re.sub(r"[\x00-\x1f\x7f]", "", str(j.get("author") or ""))[:24]
    if author:
        b += b"\x1ba\x02\x1bE\x01"; t(f"- {author}\n"); b += b"\x1bE\x00"
    b += b"\x1bd\x03\x1dV\x42\x00"
    return bytes(b)


def send(ip, data):
    with socket.create_connection((ip, PORT), timeout=10) as s:
        s.sendall(data)
        s.settimeout(10)
        s.sendall(b"\x10\x04\x01")
        s.recv(1)


# ---------------- pairing (relay address + receipt token, sealed, through Home Assistant) ----------------
PAIRING = {"priv": None, "pub": None, "opened": 0, "closed": False, "published": False}


def _write_private(path, text):
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(path + ".tmp", path)


def load_relay():
    """Saved pairing, or (None, None). Re-checks the address and token format every time."""
    try:
        d = json.load(open(RELAY_FILE))
    except Exception:
        return None, None
    base, tok = valid_queue_url(d.get("queue_url")), str(d.get("queue_token") or "")
    return (base, tok) if base and TOKEN_RE.match(tok) else (None, None)


def parse_answer(text):
    """The sealed pairing payload: {"v":1,"kind":"receipt_relay","queue_url":"https://...","queue_token":"..."}."""
    d = json.loads(text)
    if not isinstance(d, dict) or d.get("kind") != "receipt_relay":
        raise ValueError("pairing answer is not for this app")
    base, tok = valid_queue_url(d.get("queue_url")), str(d.get("queue_token") or "")
    if not base:
        raise ValueError("pairing answer has a bad relay address (https only)")
    if not TOKEN_RE.match(tok):
        raise ValueError("pairing answer has a bad receipt token")
    return base, tok


def _ha_get(entity):
    try:
        return ha("GET", "/states/" + entity)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def _ha_delete(entity):
    try:
        ha("DELETE", "/states/" + entity)
    except Exception:
        pass


def reset_requested(opts, st):
    """reset_pairing: forget the saved relay once per switch-on (the app remembers it used the switch)."""
    if opts.get("reset_pairing"):
        if not st.get("reset_used"):
            try:
                os.remove(RELAY_FILE)
            except FileNotFoundError:
                pass
            st["reset_used"] = True; save_state(st)
            print("reset_pairing: forgot the saved relay; a new pairing window opens (switch reset_pairing off afterwards)")
            return True
        print("reset_pairing is still on but was already used; switch it off")
    elif st.get("reset_used"):
        st["reset_used"] = False; save_state(st)
    return False


def pair_step(now=None):
    """One pass of the pairing window. Returns (queue_url, token) once paired, else None.
    Only the PUBLIC key is ever written to Home Assistant; the answer must be sealed to this run's own key pair."""
    now = time.time() if now is None else now
    P = PAIRING
    if P["closed"]:
        return None
    if P["priv"] is None:
        P["priv"], pub = pairing.keypair(); P["pub"] = pub; P["opened"] = now; P["published"] = False
        print(f"receipt pairing: window open for {PAIR_WINDOW // 60} min; request fingerprint "
              f"{pairing.fingerprint(format(pub, 'x'))} (Hark checks this)")
        _ha_delete(PAIR_ANSWER)          # an answer left over from an older request can never be used
    if now - P["opened"] > PAIR_WINDOW:
        P["closed"] = True; P["priv"] = None
        _ha_delete(PAIR_REQUEST); _ha_delete(PAIR_ANSWER)
        print("receipt pairing: window closed without an answer; restart the app to open it again (or fill in the options)")
        return None
    pub_hex = format(P["pub"], "x")
    if not P["published"]:
        try:
            ha("POST", "/states/" + PAIR_REQUEST, {"state": "waiting", "attributes": {
                "app_public": pub_hex, "fingerprint": pairing.fingerprint(pub_hex), "app": "internet_receipt_printer",
                "friendly_name": "Internet Receipt Printer pairing request", "icon": "mdi:link-variant",
                "note": "Public key only. The answer arrives sealed in sensor.internet_receipt_printer_pairing."}})
            P["published"] = True
        except Exception as e:
            print("receipt pairing: could not publish request", e)
            return None
    try:
        ans = _ha_get(PAIR_ANSWER)
    except Exception as e:
        print("receipt pairing: HA read failed", e); return None
    if not ans or not (ans.get("attributes") or {}).get("ciphertext"):
        return None
    try:
        a = ans["attributes"]
        base, tok = parse_answer(pairing.open_sealed(P["priv"], P["pub"], a))
    except Exception as e:
        print("receipt pairing: answer not usable:", e)
        _ha_delete(PAIR_ANSWER)
        return None
    _write_private(RELAY_FILE, json.dumps({"queue_url": base, "queue_token": tok, "paired_at": int(now)}))
    _ha_delete(PAIR_ANSWER); _ha_delete(PAIR_REQUEST)
    P["closed"] = True; P["priv"] = None
    host = urllib.parse.urlsplit(base).hostname
    print(f"receipt pairing: done; relay {host}; answered by key {pairing.fingerprint(str(a.get('hark_public', '')))}")
    return base, tok


# ---------------- main loop ----------------
def queue_req(base, token, path, body=None, timeout=20):
    req = urllib.request.Request(base + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                          "User-Agent": f"internet_receipt_printer/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, (json.loads(r.read() or b"null") if r.status == 200 else None)


def load_state():
    try:
        return json.load(open(STATE_FILE))
    except Exception:
        return {}


def save_state(st):
    try:
        fd = os.open(STATE_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(st, f)
    except Exception as e:
        print("state save failed", e)


def run(opts, once=False, sleep=time.sleep, nets=None):
    base = valid_queue_url(opts.get("queue_url"))
    token = str(opts.get("queue_token") or "").strip()
    fixed = str(opts.get("printer_ip") or "").strip()
    if fixed and not home_ip(fixed):
        print("printer_ip must be a home-network address like 10.20.30.40; ignoring it")
        fixed = ""
    st = load_state()
    from_options = bool(base and token)
    reset_requested(opts, st)
    if not from_options:
        base, token = load_relay()       # saved pairing (options always win)
    can_pair = not from_options and not (base and token) and opts.get("pairing", True)
    counters = {"printed": 0, "err": None}
    last = {"v": None, "t": 0}

    def report(s, **attrs):
        a = {"friendly_name": "Internet receipt printer", "icon": "mdi:printer-pos", "printer_ip": st.get("ip"),
             "model": st.get("model"), "printed_since_start": counters["printed"], "last_error": counters["err"],
             "version": VERSION, **attrs}
        if (s, a) == last["v"] and time.time() - last["t"] < 300:
            return
        try:
            ha("POST", "/states/" + SENSOR, {"state": s, "attributes": a})
            last.update(v=(s, a), t=time.time())
        except Exception as e:
            print("status sensor failed", e)

    print(f"Internet Receipt Printer {VERSION} starting;", "relay from options" if from_options else
          ("relay from pairing" if base and token else "no relay yet"))
    if not base or not token:
        print("set queue_url (https://...) and queue_token in the app's Configuration tab and restart"
              + (", or let Hark pair it (window open 30 min)" if can_pair else ""))
    last_scan, backoff = 0, 5
    while True:
        try:
            if (not base or not token) and can_pair and not PAIRING["closed"]:
                got = pair_step()
                if got:
                    base, token = got
                elif not PAIRING["closed"]:
                    report("waiting for pairing", hint="Ask Hark to pair the receipt printer, or set queue_url and queue_token")
                    if once:
                        return "waiting for pairing"
                    sleep(5); continue
            if not base or not token:
                report("needs setup", hint="Set queue_url and queue_token in the app's Configuration tab")
                if once:
                    return "needs setup"
                sleep(60); continue
            ip = fixed or st.get("ip")
            if not ip:
                if time.time() - last_scan < SCAN_EVERY:
                    report("printer not found", hint="Plug the receipt printer into the network and turn it on")
                    if once:
                        return "printer not found"
                    sleep(CHECK_EVERY); continue
                report("searching for printer"); last_scan = time.time()
                ip, name = discover(nets)
                if ip:
                    st.update(ip=ip, model=name); save_state(st); print("found receipt printer", ip, name)
                else:
                    print("no receipt printer on the network yet; next search in 10 min")
                    if once:
                        return "printer not found"
                    continue
            s = status(ip)
            if s == "not_receipt":
                print(ip, "is a page printer, not a receipt printer; it will not be used")
                st.pop("ip", None); save_state(st)
                report("printer not found", hint="That address is a page printer, not a receipt printer")
                if once:
                    return s
                sleep(SCAN_EVERY); continue
            if s == "unreachable":
                report("offline")
                if not fixed and time.time() - last_scan > SCAN_EVERY:
                    st.pop("ip", None); save_state(st)   # may have moved: search again
                if once:
                    return s
                sleep(CHECK_EVERY); continue
            if s != "ready":
                report(s)
                if once:
                    return s
                sleep(CHECK_EVERY); continue
            if opts.get("hello_receipt", True) and not st.get("hello"):
                try:
                    send(ip, receipt({"title": "Hello", "number": 0, "when": time.strftime("%b %d, %I:%M %p"),
                                      "body": "Internet Receipt Printer is connected to this printer."}))
                    st["hello"] = True; save_state(st)
                except Exception as e:
                    print("hello print failed", e)
            if not receipts_allowed(opts):   # paper guard: receipts wait on the relay until tomorrow
                report("daily limit reached")
                if once:
                    return "daily limit reached"
                sleep(600); continue
            report("ready")
            code, j = queue_req(base, token, "/bridge/next")
            backoff = 5
            if code == 200 and j and j.get("id"):
                ok = True
                try:
                    count_receipt()
                    send(ip, receipt(j)); counters["printed"] += 1; counters["err"] = None
                except Exception as e:
                    ok = False; counters["err"] = f"print: {e}"; print("print failed", e)
                queue_req(base, token, "/bridge/ack", {"id": j["id"], "ok": ok})
                if once:
                    return "printed" if ok else "print failed"
                continue   # more may be waiting
            if once:
                return "idle"
            sleep(POLL_EVERY)
        except urllib.error.HTTPError as e:
            counters["err"] = f"relay HTTP {e.code}" + (" (401 = queue_token does not match the relay)" if e.code == 401 else "")
            print("queue check failed:", counters["err"])
            report("relay error")
            if once:
                return "relay error"
            sleep(backoff); backoff = min(backoff * 2, 600)
        except Exception as e:
            counters["err"] = f"{e}"[:200]; print("error", e)
            if once:
                return "error"
            sleep(backoff); backoff = min(backoff * 2, 600)


if __name__ == "__main__":
    run(load_opts())

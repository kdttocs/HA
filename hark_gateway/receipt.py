"""Receipt printing: Worker /bridge/* queue -> network ESC/POS receipt printer on raw TCP 9100. Stdlib only.
Same protocol and token as the old Hark Printer Bridge. Receipts come from the public web form (no Hark in the loop),
so this checks the queue with one short request a minute, and only while the printer is ready. When the printer is missing or offline it never takes
jobs off the queue (they wait safely in the Worker) and it re-checks politely instead of spinning."""
import ipaddress, json, re, socket, subprocess, textwrap, threading, time, urllib.error, urllib.request

import caps

COLS = 42
PORT = 9100
SCAN_EVERY = 600        # full /24 search for a missing printer: every 10 minutes
CHECK_EVERY = 30        # known-but-offline printer: re-check every 30 s (local network only, no Worker request)
POLL_EVERY = 60         # printer ready: check the Worker's receipt queue once a minute (short request, no long-poll)


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
        print("receipt: ip addr failed", e)
    return list(nets)


def _port_open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def _skip_ips():
    """Hosts that must never get ESC/POS bytes: the document printer and anything already known as one."""
    out = set()
    try:
        import docs
        if docs.STATE.get("ip"):
            out.add(docs.STATE["ip"])
    except Exception:
        pass
    return out


def discover():
    """Finds the ESC/POS receipt printer WITHOUT printing on other printers.
    Any byte sent to a page printer's port 9100 is printed as text (the old GS I query printed a page reading
    the query bytes on a laser printer every search). So: skip the known document printer, and skip any host that
    speaks IPP (port 631) - page printers do, ESC/POS receipt printers do not - before sending anything."""
    hits, lock = [], threading.Lock()
    skip = _skip_ips()

    def probe(ip):
        if ip in skip or not _port_open(ip, PORT):
            return
        if _port_open(ip, 631):     # IPP = a page printer; never send it ESC/POS bytes
            return
        name = query_id(ip)
        with lock:
            hits.append((ip, name))

    for net in local_nets():
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
    """Returns 'ready', 'no_paper', 'cover_open', 'not_receipt' or 'unreachable'."""
    if ip in _skip_ips() or _port_open(ip, 631, timeout=1):
        return "not_receipt"      # a page printer: sending status bytes would print junk pages
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
    t = lambda s: b.extend(s.encode("ascii", "replace"))
    b += b"\x1ba\x01\x1bE\x01\x1d!\x11"; t(j.get("title", "INCOMING").upper() + "\n")
    b += b"\x1d!\x00\x1bE\x00"; t(f"#{int(j.get('number') or 0):04d}   {j.get('when', '')}\n" + "-" * COLS + "\n\n")
    b += b"\x1ba\x00\x1d!\x01"
    for para in str(j.get("body", "")).split("\n"):
        t((textwrap.fill(para, COLS) if para else "") + "\n")
    b += b"\x1d!\x00\x1ba\x01"; t("\n" + "-" * COLS + "\n")
    if j.get("author"):
        b += b"\x1ba\x02\x1bE\x01"; t(f"- {j['author']}\n"); b += b"\x1bE\x00"
    b += b"\x1bd\x03\x1dV\x42\x00"
    return bytes(b)


def send(ip, data):
    with socket.create_connection((ip, PORT), timeout=10) as s:
        s.sendall(data)
        s.settimeout(10)
        s.sendall(b"\x10\x04\x01")
        s.recv(1)


def run(ctx):
    """ctx: dict with ha, site_cfg (-> (site, token)), state (persisted dict), save (fn), opts."""
    ha, site_cfg, st, save, opts = ctx["ha"], ctx["site_cfg"], ctx["state"], ctx["save"], ctx["opts"]
    counters = {"printed": 0, "err": None}
    last = {"v": None, "t": 0}

    def report(s, **attrs):
        a = {"friendly_name": "Receipt printer", "icon": "mdi:printer-pos", "printer_ip": st.get("receipt_ip"),
             "model": st.get("receipt_model"), "printed_since_start": counters["printed"], "last_error": counters["err"], **attrs}
        if (s, a) == last["v"] and time.time() - last["t"] < 300:
            return
        try:
            ha("POST", "/states/sensor.receipt_printer", {"state": s, "attributes": a})
            last.update(v=(s, a), t=time.time())
        except Exception as e:
            print("receipt: report failed", e)

    def site_req(path, body=None, timeout=20):
        site, token = site_cfg()
        req = urllib.request.Request(site + path, method="POST" if body is not None else "GET",
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "User-Agent": "hark-gateway/receipt"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, (json.loads(r.read() or b"null") if r.status == 200 else None)

    last_scan, backoff = 0, 5
    print("receipt: starting")
    while True:
        try:
            site, token = site_cfg()
            if not token:
                report("waiting for setup", hint="Waiting for Hark to pair with the app"); time.sleep(15); continue
            ip = opts.get("printer_ip") or st.get("receipt_ip")
            if not ip:
                if time.time() - last_scan < SCAN_EVERY:
                    report("printer not found", hint="Plug the receipt printer into the network and turn it on")
                    time.sleep(CHECK_EVERY); continue
                report("searching for printer"); last_scan = time.time()
                ip, name = discover()
                if ip:
                    st.update(receipt_ip=ip, receipt_model=name); save(); print("receipt: found printer", ip, name)
                else:
                    print("receipt: no receipt printer on the network yet; next search in 10 min")
                    continue
            s = status(ip)
            if s == "not_receipt":
                print("receipt:", ip, "is a page printer, not a receipt printer; forgetting it")
                st.pop("receipt_ip", None); save()
                report("printer not found", hint="The address set is a page printer, not a receipt printer")
                time.sleep(SCAN_EVERY); continue
            if s == "unreachable":
                report("offline")
                if not opts.get("printer_ip") and time.time() - last_scan > SCAN_EVERY:
                    st.pop("receipt_ip", None); save()   # may have moved: search again
                time.sleep(CHECK_EVERY); continue
            if s != "ready":
                report(s); time.sleep(CHECK_EVERY); continue
            if not st.get("receipt_hello"):
                try:
                    send(ip, receipt({"title": "Hello", "number": 0, "when": time.strftime("%b %d, %-I:%M %p"),
                                      "body": "Hark HA Gateway is connected to this receipt printer."}))
                    st["receipt_hello"] = True; save()
                except Exception as e:
                    print("receipt: hello print failed", e)
            if not caps.receipts_allowed(opts):   # daily paper guard: receipts wait on the server until tomorrow
                report("daily limit reached"); time.sleep(600); continue
            report("ready")
            # one short request (no long-poll); only made while the printer is ready, so jobs are never taken early
            code, j = site_req("/bridge/next", timeout=20)
            backoff = 5
            if code == 200 and j:
                ok = True
                try:
                    caps.add(receipts=1)
                    send(ip, receipt(j)); counters["printed"] += 1; counters["err"] = None
                except Exception as e:
                    ok = False; counters["err"] = f"print: {e}"; print("receipt: print failed", e)
                site_req("/bridge/ack", {"id": j["id"], "ok": ok})
                continue   # more may be waiting: check again right away
            time.sleep(POLL_EVERY)
        except urllib.error.HTTPError as e:
            counters["err"] = f"site HTTP {e.code}"; print("receipt: poll failed", e)
            report("site error"); time.sleep(backoff); backoff = min(backoff * 2, 120)
        except Exception as e:
            counters["err"] = f"{e}"[:200]; print("receipt: error", e)
            time.sleep(backoff); backoff = min(backoff * 2, 120)

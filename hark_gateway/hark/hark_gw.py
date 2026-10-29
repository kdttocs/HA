#!/usr/bin/env python3
"""Hark-side client for the Hark Home Assistant Gateway app. Python 3.9+ standard library only.

Any Hark (or other assistant) can run this to set up and use the gateway. Instructions: HARK.md next to this file.
It needs two files from the app folder: ed25519.py and pairing.py (found next to this file or one folder up).

  hark_gw.py keygen                      make the approval key once (prints only the PUBLIC key)
  hark_gw.py approval-pub                print the approval PUBLIC key (the user pastes it into the relay deploy)
  hark_gw.py claim RELAY_URL             claim a freshly deployed relay (gets its secrets once; prints none)
  hark_gw.py pair --code CODE            pair with the app through the relay (CODE: from the app's Log)
  hark_gw.py run TOOL '{"json":"args"}'  send a signed command. Read tools: waits for the result.
                                         Change tools: held, exit code 3; ask the user, then `approve ID`.
  hark_gw.py approve ID | deny ID        ONLY after the user said yes (or no) to that exact command
  hark_gw.py result ID | list | status
  hark_gw.py push-file PATH LOCAL        stage a file for configuration.yaml or packages/<name>.yaml, held for approval
  hark_gw.py push-dashboard URL_PATH LOCAL.json   stage a dashboard (JSON), held for approval
  hark_gw.py print FILE.pdf [--copies N] [--sides two-sided-long-edge] [--color monochrome]
  hark_gw.py export-secrets              print every secret as JSON, ONLY to store it in your secure vault
  hark_gw.py import-secrets < file.json  restore them (for example from your vault onto a new machine)
Optional speed-up for homes whose Home Assistant you can reach with a token:
  hark_gw.py ha HA_URL --token-stdin     remember the Home Assistant address (+ long-lived token from stdin)
  hark_gw.py pair [--slug SLUG | --fingerprint FP]   pair through Home Assistant instead of --code
  hark_gw.py provision                   send missing settings to an app paired the old way (Home Assistant only)

State lives in --home DIR (default: env HARK_GW_HOME, else ~/.hark-gateway), files 0600. Environment variables
override the files: HARK_GW_APPROVAL_SEED, HARK_GW_GATEWAY_SECRET, HARK_GW_DOC_TOKEN, HARK_GW_SITE,
HARK_GW_HA_URL, HARK_GW_HA_TOKEN, HARK_GW_SLUG.
Prints one JSON object. Exit codes: 0 ok, 1 error/refused, 2 timed out, 3 waiting for the user's approval.
"""
import base64, hashlib, hmac, json, os, re, secrets, sys, time, urllib.error, urllib.parse, urllib.request, zlib

HERE = os.path.dirname(os.path.abspath(__file__))
for _d in (HERE, os.path.dirname(HERE)):
    if os.path.exists(os.path.join(_d, "ed25519.py")) and _d not in sys.path:
        sys.path.insert(0, _d)
try:
    import ed25519, pairing  # noqa: E402  (from the app folder: the exact code the app verifies with)
except ImportError:
    sys.exit(json.dumps({"error": "put ed25519.py and pairing.py (from the app folder) next to this file"}))

VERSION = "2.0.5"
REPO_URL = "https://github.com/kdttocs/HA"     # the app's store slug is derived from the repository address
APP_SLUG = "hark_gateway"
EVENT, RESULT_PREFIX = "hark_gateway_command", "sensor.hark_gateway_result_"
FINAL = ("done", "error", "rejected", "denied", "expired", "lost")
UA = f"hark-gw-client/{VERSION}"
CHANGE_TOOLS = {"wol", "ssh", "ha_service", "ha_file_write", "lovelace_save"}   # must match the app's tools.tier_of()
HOME = os.environ.get("HARK_GW_HOME") or os.path.expanduser("~/.hark-gateway")


def out(obj, code=0):
    print(json.dumps(obj, indent=1))
    return code


# ---------------- private state ----------------
def _p(*parts):
    return os.path.join(HOME, *parts)


def _load(path, default=None):
    try:
        return json.load(open(path))
    except Exception:
        return {} if default is None else default


def _save(path, data):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def cfg():
    c = _load(_p("config.json"))
    for k, env in (("site", "HARK_GW_SITE"), ("ha_url", "HARK_GW_HA_URL"), ("slug", "HARK_GW_SLUG")):
        if os.environ.get(env):
            c[k] = os.environ[env]
    return c


def host_of(url):
    return urllib.parse.urlsplit(url).netloc.lower()


def relay_file(url):
    return _p("relays", re.sub(r"[^a-z0-9.-]", "_", host_of(url)) + ".json")


def site():
    s = cfg().get("site")
    if not s:
        raise SystemExit(json.dumps({"error": "no relay yet: run `claim RELAY_URL` first"}))
    return s


def relay_secrets():
    r = _load(relay_file(site())) if cfg().get("site") else {}
    sec = os.environ.get("HARK_GW_GATEWAY_SECRET") or r.get("GATEWAY_SECRET")
    if not sec:
        raise SystemExit(json.dumps({"error": "no gateway secret for this relay: run `claim RELAY_URL` (or import-secrets)"}))
    return sec, os.environ.get("HARK_GW_DOC_TOKEN") or r.get("DOC_TOKEN")


def approval_key(create=False):
    """(seed bytes, public hex). The seed is never printed except by export-secrets."""
    env = os.environ.get("HARK_GW_APPROVAL_SEED")
    if env:
        seed = bytes.fromhex(env.strip())
        return seed, ed25519.public_key(seed).hex()
    d = _load(_p("approval_ed25519.json"))
    if not d.get("seed"):
        if not create:
            raise SystemExit(json.dumps({"error": "no approval key: run `keygen` first"}))
        seed = secrets.token_bytes(32)
        d = {"seed": seed.hex(), "public": ed25519.public_key(seed).hex(), "created_at": int(time.time())}
        _save(_p("approval_ed25519.json"), d)
    return bytes.fromhex(d["seed"]), d["public"]


def ha_token():
    return os.environ.get("HARK_GW_HA_TOKEN") or (open(_p("ha_token")).read().strip() if os.path.exists(_p("ha_token")) else "")


def ha_on():
    return bool(cfg().get("ha_url") and ha_token())


# ---------------- signing (same messages as the app and the relay) ----------------
def mac(msg):
    return hmac.new(relay_secrets()[0].encode(), msg.encode(), hashlib.sha256).hexdigest()


def tier_of(tool, args):
    if tool in CHANGE_TOOLS:
        return "change"
    m = str((args or {}).get("method") or "GET").upper()
    if (tool == "http" and m not in ("GET", "HEAD")) or (tool in ("firewall", "opnsense") and m != "GET"):
        return "change"
    return "read"


def make_cmd(tool, args):
    a = json.dumps(args, separators=(",", ":"), sort_keys=True)
    c = {"id": "c" + secrets.token_hex(6), "ts": int(time.time()), "nonce": secrets.token_urlsafe(16), "tool": tool, "args": a}
    c["sig"] = mac("\n".join([c["id"], str(c["ts"]), c["nonce"], tool, a]))
    return c


def make_approval(kind, c):
    a = {"id": c["id"], "ts": int(time.time()), "nonce": secrets.token_urlsafe(16)}
    a["sig"] = mac("\n".join([kind, c["id"], str(a["ts"]), a["nonce"], c["sig"]]))
    body = hashlib.sha256((c["tool"] + "\n" + c["args"]).encode()).hexdigest()
    msg = "\n".join(["hark-gw-approve-v2", kind, c["id"], str(a["ts"]), a["nonce"], c["sig"], body])
    a["esig"] = ed25519.sign(approval_key()[0], msg.encode()).hex()
    return a


# ---------------- HTTP ----------------
def _http(req, timeout):
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, (json.loads(raw) if raw else None)
            except ValueError:
                return r.status, {"text": raw.decode(errors="replace")[:300]}
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"error": raw.decode(errors="replace")[:300]}
    except Exception as e:
        return 0, {"error": f"unreachable: {e}"}


def relay(method, path, body=None, query="", timeout=40, raw=None, headers=None):
    """Signed call to /gw/* on the relay."""
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(16)
    h = {"Content-Type": "application/json", "User-Agent": UA,
         "X-GW-Auth": f"{ts}.{nonce}." + mac("\n".join(["req", method, path, ts, nonce, hashlib.sha256(data).hexdigest()]))}
    h.update(headers or {})
    return _http(urllib.request.Request(site() + path + query, data=data if method == "POST" else None, method=method, headers=h), timeout)


def ha(method, path, body=None, timeout=20, text=False):
    h = {"Content-Type": "application/json", "User-Agent": UA, "Authorization": "Bearer " + ha_token()}
    req = urllib.request.Request(cfg()["ha_url"].rstrip("/") + path, method=method, headers=h,
                                 data=json.dumps(body).encode() if body is not None else None)
    if text:
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode(errors="replace")
        except Exception:
            return 0, None
    return _http(req, timeout)


# ---------------- pending change commands (no secrets inside) ----------------
def pending():
    return _load(_p("pending.json"))


def save_pending(d):
    _save(_p("pending.json"), dict(list(d.items())[-100:]))


def cmd_for(cid):
    c = pending().get(cid)
    if c:
        return c
    code, r = relay("GET", f"/gw/result/{cid}")
    if code == 200 and r and all(r.get(k) is not None for k in ("ts", "nonce", "sig", "tool")):
        a = r["args"] if isinstance(r["args"], str) else json.dumps(r["args"], separators=(",", ":"), sort_keys=True)
        return {"id": cid, "ts": r["ts"], "nonce": r["nonce"], "tool": r["tool"], "sig": r["sig"], "args": a}
    raise SystemExit(json.dumps({"error": f"no record of command {cid}; send it again with run"}))


# ---------------- delivery ----------------
def wait_relay(cid, timeout):
    end = time.time() + timeout
    while time.time() < end:
        code, r = relay("GET", f"/gw/result/{cid}", query="?wait=20", timeout=40)
        if code == 200 and r and r.get("status") in FINAL:
            return {"id": cid, "tool": r.get("tool"), "status": r["status"], "ok": r.get("ok"), "via": "relay", "result": r.get("result")}
        if code not in (200, 404, 0):
            return {"id": cid, "status": "error", "http": code, "error": r}
        if code in (404, 0):
            time.sleep(2)
    return None


def open_ha_result(cid, st):
    a = st.get("attributes") or {}
    res = a.get("result")
    if a.get("sealed"):
        try:
            res = json.loads(pairing.unbox(relay_secrets()[0], "result|" + str(cid), a["sealed"]))
        except Exception as e:
            res = {"error": f"could not open sealed result: {e}"}
    o = {"id": cid, "tool": a.get("tool"), "status": st.get("state"), "ok": a.get("ok"), "via": "ha", "result": res}
    if a.get("truncated"):
        r = wait_relay(cid, 20)
        if r:
            o["result"], o["truncated_in_ha"] = r.get("result"), True
    ha("DELETE", f"/states/{RESULT_PREFIX}{cid.lower()}")
    return o


def deliver(env, timeout, relay_send, via=None, no_wait=False):
    """via 'relay' (default without Home Assistant) or 'ha'. relay_send() puts it on the relay (cmd or approval)."""
    cid = env["id"]
    via = via or ("ha" if ha_on() else "relay")
    note = None
    if via == "ha":
        code, r = ha("POST", f"/events/{EVENT}", env)
        if code == 200:
            end = time.time() + timeout
            acked = False
            while time.time() < end:
                c2, st = ha("GET", f"/states/{RESULT_PREFIX}{cid.lower()}", timeout=15)
                if c2 == 200 and isinstance(st, dict):
                    acked = True
                    if st.get("state") in FINAL:
                        return open_ha_result(cid, st)
                if no_wait and acked:
                    return {"id": cid, "status": "sent", "via": "ha"}
                if not acked and time.time() > end - timeout + 8:
                    break       # the app did not acknowledge within 8 s: use the relay
                time.sleep(0.5)
            if acked:
                return {"id": cid, "status": "timeout", "via": "ha"}
            note = "app did not acknowledge through Home Assistant within 8 s; sent through the relay"
        else:
            note = f"Home Assistant event failed (HTTP {code}); sent through the relay"
    code, r = relay_send()
    if code not in (200, 409):
        return {"id": cid, "status": "error", "http": code, "error": r, "note": note}
    if no_wait:
        return {"id": cid, "status": "queued", "via": "relay", "note": note}
    res = wait_relay(cid, timeout) or {"id": cid, "status": "timeout", "hint": "the app may be offline; check `status`"}
    if note:
        res["note"] = note
    return res


def code_of(res):
    if res.get("status") == "timeout":
        return 2
    return 0 if res.get("ok") or res.get("status") in ("sent", "queued") else 1


def hold(c, args, extra=None):
    p = pending(); p[c["id"]] = c; save_pending(p)
    code, _ = relay("POST", "/gw/cmd", c)
    o = {"id": c["id"], "status": "pending_approval", "tier": "change", "tool": c["tool"], "args": args,
         "recorded_on_relay": code == 200,
         "next": f"Describe this exact change to the user. Only after a clear yes: approve {c['id']} (a no: deny {c['id']})"}
    o.update(extra or {})
    return out(o, 3)


# ---------------- commands ----------------
def cmd_claim(url, timeout=30):
    url = url.strip().rstrip("/")
    h = host_of(url).split(":")[0]
    if not re.match(r"^https?://[A-Za-z0-9.-]+(:[0-9]+)?$", url) or (url.startswith("http://") and h not in ("127.0.0.1", "localhost")):
        return out({"ok": False, "error": "give the relay address Cloudflare showed after the deploy, starting with https://"}, 1)
    c = _load(_p("config.json")); c["site"] = url; _save(_p("config.json"), c)
    if _load(relay_file(url)).get("GATEWAY_SECRET"):
        code, _ = relay("GET", "/gw/status")
        return out({"ok": code == 200, "claimed": True, "already_saved": True, "site": url}, 0 if code == 200 else 1)
    seed, _ = approval_key()
    b = {"host": host_of(url), "ts": int(time.time()), "nonce": secrets.token_urlsafe(16)}
    b["sig"] = ed25519.sign(seed, "\n".join(["hark-relay-claim-v1", b["host"], str(b["ts"]), b["nonce"]]).encode()).hex()
    code, r = _http(urllib.request.Request(url + "/setup/claim", data=json.dumps(b).encode(), method="POST",
                                           headers={"Content-Type": "application/json", "User-Agent": UA}), timeout)
    if code != 200 or not (r or {}).get("gateway_secret") or not (r or {}).get("doc_token"):
        hint = {409: "this relay was already claimed, or its secrets were set by hand (DEPLOY.md, 'If something goes wrong')",
                503: "the relay has no GW_APPROVAL_PUB yet: the user adds the approval public key in Cloudflare",
                401: "refused: is GW_APPROVAL_PUB on the relay the key from `approval-pub`?"}.get(code)
        return out({"ok": False, "http": code, "error": (r or {}).get("error"), "hint": hint}, 1)
    _save(relay_file(url), {"site": url, "GATEWAY_SECRET": r["gateway_secret"], "DOC_TOKEN": r["doc_token"], "claimed_at": int(time.time())})
    code, _ = relay("GET", "/gw/status")      # first signed request: the relay now refuses every further claim
    return out({"ok": code == 200, "claimed": True, "confirmed": code == 200, "site": url,
                "next": "store the secrets in your vault (export-secrets), then have the user install the app, put this "
                        "relay address in its 'Relay address' option, start it and read you the pairing code"}, 0 if code == 200 else 1)


def pair_payload(doc_printer_ip=None):
    _, pub = approval_key()
    p = {"v": 2, "secret": relay_secrets()[0], "site": site(), "approval_pub": pub}
    if doc_printer_ip:
        p["doc_printer_ip"] = doc_printer_ip
    return p


def cmd_pair_relay(code_in, timeout, doc_printer_ip=None):
    want = re.sub(r"[^0-9a-f]", "", code_in.lower())
    if len(want) < 12:
        return out({"paired": False, "error": "the pairing code has 12 characters, like 3f9a-41c2-77de (app's Log tab)"}, 1)
    end = time.time() + timeout
    match = None
    while not match:
        code, r = relay("GET", "/gw/pairing")
        if code == 404:
            return out({"paired": False, "error": "this relay can't pair (older template): update the relay (DEPLOY.md)"}, 1)
        reqs = (r or {}).get("requests") or [] if code == 200 else []
        hits = [q for q in reqs if pairing.fingerprint(q.get("app_public", "")).startswith(want)]
        if len(hits) == 1:
            match = hits[0]; break
        if time.time() > end:
            return out({"paired": False, "status": "timeout", "hint": "no pairing request with that code on the relay. Is the "
                        "app started with the relay address set? The window lasts 30 minutes after it starts."}, 2)
        time.sleep(4)
    sealed = pairing.seal(match["app_public"], json.dumps(pair_payload(doc_printer_ip), separators=(",", ":")))
    t0 = int(time.time())
    code, r = relay("POST", "/gw/pairing/answer", {"id": match["id"], "answer": sealed})
    if code != 200:
        return out({"paired": False, "http": code, "error": r}, 1)
    end2 = time.time() + 180
    while time.time() < end2:              # the app checks the secret with the relay right after unpacking it
        time.sleep(3)
        c, st = relay("GET", "/gw/status")
        ago = (st or {}).get("app_hello_sec_ago") if c == 200 else None
        if ago is not None and ago <= time.time() - t0 + 2:
            return out({"paired": True, "via": "relay", "answer_key": pairing.fingerprint(sealed["hark_public"]),
                        "app_version": (st or {}).get("app_version"),
                        "next": "the app's Log should say 'pairing: done through relay; answered by key " +
                                pairing.fingerprint(sealed["hark_public"]) + "'"})
    return out({"paired": False, "status": "answer left on the relay, but the app has not checked in for 3 minutes",
                "hint": "ask the user to look at the app's Log tab"}, 2)


def default_slug():
    return hashlib.sha1(REPO_URL.lower().encode()).hexdigest()[:8] + "_" + APP_SLUG


def cmd_pair_ha(timeout, slug=None, fp_given=None, doc_printer_ip=None):
    end = time.time() + timeout
    while True:
        code, req = ha("GET", "/states/sensor.hark_gateway_pairing_request")
        if code == 200 and (req.get("attributes") or {}).get("app_public"):
            break
        if time.time() > end:
            return out({"paired": False, "status": "timeout", "hint": "no pairing request in Home Assistant (app started? a "
                        "paired app pairs again only with reset_pairing on + restart)"}, 2)
        time.sleep(5)
    app_pub = req["attributes"]["app_public"]
    fp = pairing.fingerprint(app_pub)
    if fp_given:
        if not fp.startswith(re.sub(r"[^0-9a-f]", "", fp_given.lower())[:20]) or len(re.sub(r"[^0-9a-f]", "", fp_given.lower())) < 12:
            return out({"paired": False, "error": "the request in Home Assistant does NOT match the code from the app's Log: refused"}, 1)
    else:
        _, log = ha("GET", f"/hassio/addons/{slug or cfg().get('slug') or default_slug()}/logs", text=True)
        seen = re.findall(r"request fingerprint ([0-9a-f]{20})", log or "")
        if not seen:
            return out({"paired": False, "error": "could not read the app's log (needs an admin token); ask the user for the "
                        "pairing code in the app's Log and pass --fingerprint CODE, or use --slug"}, 1)
        if seen[-1] != fp:
            return out({"paired": False, "error": "pairing request does NOT match the app's own log: possible tampering; refused"}, 1)
    sealed = pairing.seal(app_pub, json.dumps(pair_payload(doc_printer_ip), separators=(",", ":")))
    code, r = ha("POST", "/states/sensor.hark_gateway_pairing", {"state": "answer", "attributes": dict(
        sealed, friendly_name="Hark Gateway pairing answer", icon="mdi:link-variant")})
    if code not in (200, 201):
        return out({"paired": False, "http": code, "error": r}, 1)
    end2 = time.time() + 120
    while time.time() < end2:
        time.sleep(3)
        c1, _ = ha("GET", "/states/sensor.hark_gateway_pairing_request")
        c2, _ = ha("GET", "/states/sensor.hark_gateway_pairing")
        if c1 == 404 and c2 == 404:
            time.sleep(2)
            _, h = ha("GET", "/states/sensor.hark_gateway")
            return out({"paired": True, "via": "ha", "app_state": (h or {}).get("state"),
                        "provisioned": ((h or {}).get("attributes") or {}).get("provisioned")})
    return out({"paired": False, "status": "answer written but the app has not picked it up in 2 min"}, 2)


def stage_and_hold(raw, tool, args, timeout):
    sha = hashlib.sha256(raw).hexdigest()
    z = base64.b64encode(zlib.compress(raw, 9)).decode()
    parts = [z[i:i + 12000] for i in range(0, len(z), 12000)] or [""]
    if len(parts) > 64:
        return out({"error": "content too large to stage (64 parts of 12 KB compressed)"}, 1)
    name = "s" + secrets.token_hex(4)
    for i, pz in enumerate(parts, 1):
        c = make_cmd("stage", {"name": name, "part": i, "parts": len(parts), "z": pz})
        res = deliver(c, timeout, lambda c=c: relay("POST", "/gw/cmd", c))
        if not res.get("ok"):
            return out({"error": "staging failed", "part": i, "result": res}, 1)
    a = dict(args, stage=name, sha256=sha)
    return hold(make_cmd(tool, a), a, {"bytes": len(raw), "note": "staged parts expire in 1 hour"})


def flag(argv, name, default=None):
    return argv[argv.index(name) + 1] if name in argv and argv.index(name) + 1 < len(argv) else default


def main(argv):
    global HOME
    if "--home" in argv:
        HOME = os.path.abspath(flag(argv, "--home")); i = argv.index("--home"); argv = argv[:i] + argv[i + 2:]
    if len(argv) < 2 or argv[1] in ("-h", "--help", "help"):
        print(__doc__); return 1
    cmd = argv[1]
    timeout = float(flag(argv, "--timeout", 90))
    via = flag(argv, "--via")
    if cmd == "keygen":
        existed = bool(_load(_p("approval_ed25519.json")).get("seed")) or bool(os.environ.get("HARK_GW_APPROVAL_SEED"))
        _, pub = approval_key(create=True)
        return out({"approval_public_key": pub, "created": not existed,
                    "next": "store it in your vault (export-secrets); give the user the PUBLIC key for the relay deploy"})
    if cmd == "approval-pub":
        return out({"approval_public_key": approval_key()[1]})
    if cmd == "claim" and len(argv) > 2:
        return cmd_claim(argv[2])
    if cmd == "ha" and len(argv) > 2:
        c = _load(_p("config.json")); c["ha_url"] = argv[2].rstrip("/") + ("" if argv[2].rstrip("/").endswith("/api") else "/api")
        _save(_p("config.json"), c)
        if "--token-stdin" in argv:
            tok = sys.stdin.read().strip()
            os.makedirs(HOME, mode=0o700, exist_ok=True)
            fd = os.open(_p("ha_token"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(tok)
        code, _ = ha("GET", "/") if ha_token() else (0, None)
        return out({"ha_url": c["ha_url"], "token_saved": bool(ha_token()), "reachable": code == 200}, 0 if code == 200 else 1)
    if cmd == "pair":
        t = float(flag(argv, "--timeout", 900))
        if flag(argv, "--code"):
            return cmd_pair_relay(flag(argv, "--code"), t, flag(argv, "--doc-printer-ip"))
        if ha_on():
            return cmd_pair_ha(t, flag(argv, "--slug"), flag(argv, "--fingerprint"), flag(argv, "--doc-printer-ip"))
        return out({"paired": False, "error": "ask the user for the pairing code shown in the app's Log tab, then: pair --code CODE"}, 1)
    if cmd == "provision":
        if not ha_on():
            return out({"error": "provision works only through Home Assistant (configure `ha` first)"}, 1)
        a = {"site": site(), "approval_pub": approval_key()[1]}
        if flag(argv, "--doc-printer-ip"):
            a["doc_printer_ip"] = flag(argv, "--doc-printer-ip")
        c = make_cmd("provision", a)
        res = deliver(c, timeout, lambda: (0, {"error": "provision only works through Home Assistant"}), via="ha")
        return out(res, code_of(res))
    if cmd == "run" and len(argv) > 2:
        tool = argv[2]
        args = json.loads(argv[3]) if len(argv) > 3 and not argv[3].startswith("--") else {}
        if not isinstance(args, dict):
            return out({"error": "args must be a JSON object"}, 1)
        c = make_cmd(tool, args)
        if tier_of(tool, args) == "change":
            return hold(c, args)
        res = deliver(c, timeout, lambda: relay("POST", "/gw/cmd", c), via, "--no-wait" in argv)
        return out(res, code_of(res))
    if cmd in ("approve", "deny") and len(argv) > 2:
        cid = argv[2]
        c = cmd_for(cid)
        a = make_approval(cmd, c)
        if cmd == "deny":
            code, r = relay("POST", "/gw/deny", a)
            p = pending(); p.pop(cid, None); save_pending(p)
            return out({"http": code, **(r or {})}, 0 if code in (200, 404) else 1)

        def send():
            code, r = relay("POST", "/gw/approve", a)
            if code == 404:                    # the relay never got the command record: record it, then approve
                relay("POST", "/gw/cmd", c)
                code, r = relay("POST", "/gw/approve", a)
            return code, r
        res = deliver(dict(c, approval=a), timeout, send, via)
        if res.get("via") == "ha":
            relay("POST", "/gw/approve", a, query="?via=ha")     # the record only
        p = pending(); p.pop(cid, None); save_pending(p)
        return out(res, code_of(res))
    if cmd == "result" and len(argv) > 2:
        cid = argv[2]
        if ha_on():
            c2, st = ha("GET", f"/states/{RESULT_PREFIX}{cid.lower()}")
            if c2 == 200 and isinstance(st, dict) and st.get("state") in FINAL:
                return out(open_ha_result(cid, st))
        code, r = relay("GET", f"/gw/result/{cid}")
        return out(r if code == 200 else {"id": cid, "http": code, "error": r}, 0 if code == 200 else 1)
    if cmd == "list":
        code, r = relay("GET", "/gw/list")
        return out(r, 0 if code == 200 else 1)
    if cmd == "status":
        code, r = relay("GET", "/gw/status")
        o = {"relay": r if code == 200 else {"http": code, "error": r}, "site": cfg().get("site"),
             "home_assistant": "configured" if ha_on() else "not used", "pending_local": list(pending())}
        if ha_on():
            hc, h = ha("GET", "/states/sensor.hark_gateway")
            o["ha_sensor"] = {"state": h.get("state"), **{k: v for k, v in (h.get("attributes") or {}).items()
                                                          if k not in ("ssh_public_key", "friendly_name", "icon")}} if hc == 200 else {"http": hc}
        return out(o, 0 if code == 200 else 1)
    if cmd == "push-file" and len(argv) > 3:
        return stage_and_hold(open(argv[3], "rb").read(), "ha_file_write", {"path": argv[2]}, timeout)
    if cmd == "push-dashboard" and len(argv) > 3:
        raw = json.dumps(json.load(open(argv[3])), ensure_ascii=False, separators=(",", ":")).encode()
        return stage_and_hold(raw, "lovelace_save", {"url_path": argv[2]}, timeout)
    if cmd == "print" and len(argv) > 2:
        data = open(argv[2], "rb").read()
        if not data.startswith(b"%PDF-"):
            return out({"error": "only PDF files can be printed"}, 1)
        _, doc = relay_secrets()
        q = {"name": os.path.basename(argv[2])[:120], "copies": flag(argv, "--copies", "1")}
        for k in ("sides", "color"):
            if flag(argv, "--" + k):
                q[k] = flag(argv, "--" + k)
        code, r = _http(urllib.request.Request(site() + "/docs/upload?" + urllib.parse.urlencode(q), data=data, method="POST",
                                               headers={"Authorization": "Bearer " + doc, "Content-Type": "application/pdf",
                                                        "User-Agent": UA}), 120)
        return out({"http": code, **(r or {}), "check": "status of the job: GET /docs/status/<id> with the DOC_TOKEN"}, 0 if code == 200 else 1)
    if cmd == "export-secrets":
        seed, pub = approval_key()
        s = {"warning": "SECRET: store only in a secure vault, never in chat or logs", "approval_seed": seed.hex(),
             "approval_public": pub}
        if cfg().get("site"):
            g, d = relay_secrets()
            s.update(site=site(), gateway_secret=g, doc_token=d)
        print(json.dumps(s)); return 0
    if cmd == "import-secrets":
        s = json.load(sys.stdin)
        seed = bytes.fromhex(s["approval_seed"])
        _save(_p("approval_ed25519.json"), {"seed": seed.hex(), "public": ed25519.public_key(seed).hex()})
        if s.get("site"):
            c = _load(_p("config.json")); c["site"] = s["site"]; _save(_p("config.json"), c)
            _save(relay_file(s["site"]), {"site": s["site"], "GATEWAY_SECRET": s["gateway_secret"], "DOC_TOKEN": s.get("doc_token")})
        return out({"imported": True, "approval_public_key": ed25519.public_key(seed).hex(), "site": s.get("site")})
    print(__doc__); return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))

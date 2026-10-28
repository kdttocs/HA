#!/usr/bin/env python3
"""Hark HA Gateway: printing (receipt + full page) and Hark's signed network-tool commands.

Hark PUSHES commands through Home Assistant: it fires the event `hark_gateway_command` with Home Assistant's REST API;
this app hears it at once over HA's internal WebSocket, checks it, runs it, and writes the (encrypted) result back to
Home Assistant (sensor.hark_gateway_result_<id> + event `hark_gateway_result`) where Hark reads it. The app also
checks Hark's server briefly once a minute as a safety net. Outbound only, no port forwarding. Stdlib only.

Security model (1.2.0):
- Every command is signed (HMAC-SHA256) with the gateway secret; unsigned, stale (>120 s) or replayed ones are refused.
- Change commands also need an approval signed with a SEPARATE Ed25519 key that only Hark holds. The app keeps just
  the public half, so even someone who steals the app's data (for example from a backup) can't approve changes.
- Pairing hands over the secret, Hark's server address and the approval public key through Home Assistant, sealed to
  a one-time key. Pairing closes after it succeeds; re-pairing needs the `reset_pairing` option and a restart.
- Kill switch fails closed: if the helper is off, missing or unreadable, network tools are refused.
"""
import hashlib, hmac, json, os, queue, re, secrets, threading, time, urllib.error, urllib.parse, urllib.request

os.umask(0o077)   # everything this app writes in /data is private to it

import haapi, tools, receipt, docs, pairing, ed25519, caps  # noqa: E402

VERSION = "1.3.0"
OPTS = {}
try:
    OPTS = json.load(open(os.environ.get("OPTIONS_FILE", "/data/options.json")))
except Exception as e:
    print("no options file", e)
DATA_DIR = os.environ.get("DATA_DIR", "/data")
STATE_FILE = os.environ.get("CACHE_FILE", os.path.join(DATA_DIR, "state.json"))
NONCE_FILE = os.path.join(DATA_DIR, "nonces.json")
SECRET_FILE = os.path.join(DATA_DIR, "gateway_secret")       # written by pairing; never printed
SITE_FILE = os.path.join(DATA_DIR, "site")                   # Hark's server address, from pairing
APPROVAL_FILE = os.path.join(DATA_DIR, "approval_key.pub")   # Ed25519 PUBLIC key that approvals must verify against
PAIRED_FILE = os.path.join(DATA_DIR, "paired.json")          # pairing marker (closes the pairing window)
CMD_EVENT, RESULT_EVENT = "hark_gateway_command", "hark_gateway_result"
RESULT_PREFIX = "sensor.hark_gateway_result_"
RESULT_KEEP = 900             # seconds a per-command result sensor stays in HA before the app removes it
RESULT_MAX_ATTR = 7000        # bytes of result JSON sealed into the HA sensor (stays under HA's 16 KB attribute limit)
FALLBACK_EVERY = int(os.environ.get("GW_FALLBACK_EVERY", "60"))
MAX_AGE = 120                 # seconds a command (or an approval) stays valid
CHANGE_MAX_AGE = 86400        # a change command may wait up to a day for the owner's approval
PAIR_WINDOW = int(os.environ.get("GW_PAIR_WINDOW", "1800"))   # pairing request stays open 30 min after start
MAX_EVENT_BYTES = 24000       # a command event bigger than this is ignored
MAX_QUEUE = 16                # commands waiting to run; more are dropped
ACCEPT_PER_MIN = 120          # signed commands accepted per minute (flood guard)
NONCE_CAP = 50000
ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,40}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{12,64}$")
TOOL_RE = re.compile(r"^[a-z_]{2,30}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def _read(path):
    try:
        return open(path).read().strip()
    except Exception:
        return ""


def write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass


def valid_site(u):
    try:
        p = urllib.parse.urlsplit(str(u).strip())
    except Exception:
        return None
    https_only = p.scheme != "https" and not (os.environ.get("GW_TEST_ALLOW_HTTP_SITE") == "1" and p.hostname == "127.0.0.1")
    if https_only or not p.hostname or p.username or p.password or p.query or p.fragment:
        return None
    return f"{p.scheme}://{p.hostname}" + (f":{p.port}" if p.port else "") + p.path.rstrip("/")


SITE = valid_site(OPTS.get("site") or "") or valid_site(_read(SITE_FILE))
SITE_SOURCE = "app option" if valid_site(OPTS.get("site") or "") else ("paired" if SITE else None)
SECRET = (OPTS.get("gateway_secret") or "").strip()
SECRET_SOURCE = "app option" if SECRET else None
if not SECRET:
    SECRET = _read(SECRET_FILE)
    SECRET_SOURCE = "paired" if SECRET else None
APPROVAL_PUB = _read(APPROVAL_FILE).lower()
if APPROVAL_PUB and not HEX64.match(APPROVAL_PUB):
    print("WARNING: stored approval key is malformed; change commands stay off until Hark pairs again")
    APPROVAL_PUB = ""

TOOL_OPTION = {  # tool -> option that switches it on/off
    "ping_sweep": "tool_discovery", "mdns": "tool_discovery", "ssdp": "tool_discovery",
    "port_scan": "tool_port_scan", "http": "tool_http", "probe": "tool_probe", "latency": "tool_probe",
    "dns": "tool_dns", "snmp": "tool_snmp", "speedtest": "tool_speedtest", "ha_states": "tool_ha_states",
    "firewall": "tool_opnsense", "opnsense": "tool_opnsense", "wol": "tool_wol", "ssh": "tool_ssh",
    "ha_service": "tool_ha_service",
    "stage": "tool_ha_config", "ha_file_read": "tool_ha_config", "lovelace_get": "tool_ha_config",
    "ha_check_config": "tool_ha_config", "ha_file_write": "tool_ha_config", "lovelace_save": "tool_ha_config",
}
ALWAYS_ON = {"status", "audit", "ssh_pubkey", "print_doc", "provision"}   # answered even with the kill switch off

state = {}
try:
    state = json.load(open(STATE_FILE))
except Exception:
    pass
_save_lock = threading.Lock()


def save():
    with _save_lock:
        try:
            write_private(STATE_FILE, json.dumps(state))
        except Exception as e:
            print("state save failed", e)


def provisioned():
    return {"secret": bool(SECRET), "site": bool(SITE), "approval_key": bool(APPROVAL_PUB)}


# ---------------- signing (must match the Worker and Hark's helper) ----------------
def mac(msg, secret=None):
    return hmac.new((secret if secret is not None else SECRET).encode(), msg.encode(), hashlib.sha256).hexdigest()


def gw_req(method, path, body=None, timeout=20, query="", site=None, secret=None):
    site = site or SITE
    if not site:
        raise RuntimeError("no Hark server address yet (waiting for pairing)")
    data = json.dumps(body).encode() if body is not None else b""
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(16)
    sig = mac("\n".join(["req", method, path, ts, nonce, hashlib.sha256(data).hexdigest()]), secret)
    req = urllib.request.Request(site + path + query, method=method, data=data if method == "POST" else None,
                                 headers={"X-GW-Auth": f"{ts}.{nonce}.{sig}", "Content-Type": "application/json",
                                          "User-Agent": f"hark-gateway/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else None)


# ---------------- print token: from Hark's server using the gateway secret, else the option ----------------
def hello():
    if not SECRET or not SITE:
        return
    try:
        code, j = gw_req("GET", "/gw/hello", query="?v=" + VERSION)
        if j and j.get("bridge_token") and state.get("print_token") != j["bridge_token"]:
            state["print_token"] = j["bridge_token"]; save()
        if j and abs(int(j.get("server_time", time.time())) - time.time()) > 30:
            print(f"WARNING: this machine's clock is {int(time.time() - j['server_time'])} s off; "
                  "commands older than 120 s are refused, so fix the clock (NTP)")
        print("hello ok: print token", "received" if state.get("print_token") else "missing")
    except urllib.error.HTTPError as e:
        print("hello failed: HTTP", e.code, "(401 means the gateway secret does not match Hark's server)")
    except Exception as e:
        print("hello failed:", e)


_hello_at = [0]


def site_cfg():
    """(site, print token) for the printing loops; token None until the app is paired and has an address."""
    if not SITE:
        return None, None
    token = OPTS.get("print_token") or state.get("print_token")
    if not token and SECRET and time.time() - _hello_at[0] > 60:
        _hello_at[0] = time.time(); hello()
        token = state.get("print_token")
    return SITE, token


# ---------------- command verification ----------------
_nonce_lock = threading.Lock()


def load_nonces():
    try:
        d = json.load(open(NONCE_FILE))
    except Exception:
        d = {}
    t = time.time()
    return {k: v for k, v in d.items() if isinstance(v, (int, float)) and t - v < 2 * CHANGE_MAX_AGE}


NONCES = load_nonces()


def remember(nonce):
    with _nonce_lock:
        t = time.time()
        NONCES[nonce] = t
        if len(NONCES) > NONCE_CAP or len(NONCES) % 200 == 0:
            for k in [k for k, v in NONCES.items() if t - v > 2 * CHANGE_MAX_AGE]:
                NONCES.pop(k, None)
            while len(NONCES) > NONCE_CAP:      # oldest first; anything this old is far past every freshness window
                NONCES.pop(min(NONCES, key=NONCES.get))
        try:
            write_private(NONCE_FILE, json.dumps(NONCES))
        except Exception as e:
            print("nonce save failed", e)


def well_formed(c):
    """Strict field checks, so no field can smuggle a newline into the signed message."""
    if not isinstance(c, dict):
        return "not an object"
    for k in ("id", "ts", "nonce", "tool", "args", "sig"):
        if k not in c:
            return f"missing {k}"
    if not isinstance(c["id"], str) or not ID_RE.match(c["id"]):
        return "bad id"
    if isinstance(c["ts"], bool) or not (isinstance(c["ts"], int) or (isinstance(c["ts"], str) and c["ts"].isdigit() and len(c["ts"]) <= 12)):
        return "bad ts"
    if not isinstance(c["nonce"], str) or not NONCE_RE.match(c["nonce"]):
        return "bad nonce"
    if not isinstance(c["tool"], str) or not TOOL_RE.match(c["tool"]):
        return "bad tool"
    if not isinstance(c["args"], str) or len(c["args"]) > 16000:
        return "bad args"
    if not isinstance(c["sig"], str) or not HEX64.match(c["sig"]):
        return "bad sig"
    return ""


def cmd_msg(c):
    return "\n".join([c["id"], str(c["ts"]), c["nonce"], c["tool"], c["args"]])


def sig_ok(c, secret=None):
    return not well_formed(c) and hmac.compare_digest(mac(cmd_msg(c), secret), c["sig"])


def approval_msg(kind, a, c):
    """What Hark's approval key signs: bound to this exact command (its signature AND a hash of tool + args)."""
    body = hashlib.sha256((c["tool"] + "\n" + c["args"]).encode()).hexdigest()
    return "\n".join(["hark-gw-approve-v2", kind, str(a.get("id")), str(a.get("ts")), str(a.get("nonce")), c["sig"], body])


def verify(c):
    """Returns (ok, reason, tier, args, signed). signed=True once the HMAC signature checked out."""
    bad = well_formed(c)
    if bad:
        return False, bad, None, None, False
    if not hmac.compare_digest(mac(cmd_msg(c)), c["sig"]):
        return False, "bad signature", None, None, False
    if c["nonce"] in NONCES:
        return False, "nonce already used (replay)", None, None, True
    try:
        args = json.loads(c["args"])
    except Exception:
        return False, "args are not JSON", None, None, True
    if not isinstance(args, dict):
        return False, "args must be a JSON object", None, None, True
    tier = tools.tier_of(c["tool"], args)   # decided here, never trusted from the server
    age = time.time() - int(c["ts"])
    if tier == "read":
        if abs(age) > MAX_AGE:
            return False, f"command is {int(age)} s old (limit {MAX_AGE} s)", tier, args, True
        return True, "", tier, args, True
    a = c.get("approval")
    if not isinstance(a, dict) or not a:
        return False, "change command without the owner's approval", tier, args, True
    if not APPROVAL_PUB:
        return False, "change commands are off until Hark finishes pairing (no approval key yet)", tier, args, True
    if age > CHANGE_MAX_AGE or age < -MAX_AGE:
        return False, "change command too old (over a day)", tier, args, True
    if str(a.get("id")) != c["id"]:
        return False, "approval is for a different command", tier, args, True
    if not isinstance(a.get("nonce"), str) or not NONCE_RE.match(a["nonce"]):
        return False, "bad approval nonce", tier, args, True
    try:
        ats = int(a.get("ts"))
        esig = bytes.fromhex(str(a.get("esig") or ""))
    except (TypeError, ValueError):
        return False, "bad approval", tier, args, True
    if not ed25519.verify(bytes.fromhex(APPROVAL_PUB), approval_msg("approve", a, c).encode(), esig):
        return False, "bad approval signature (must be signed with the owner's approval key)", tier, args, True
    if a["nonce"] in NONCES:
        return False, "approval already used (replay)", tier, args, True
    if abs(time.time() - ats) > MAX_AGE:
        return False, f"approval is older than {MAX_AGE} s; ask Hark to send the command again", tier, args, True
    return True, "", tier, args, True


def target_of(tool, args):
    if args.get("url"):
        return tools.scrub_url(args["url"])
    for k in ("host", "mac", "entity_id", "path", "url_path", "network", "name", "match"):
        if args.get(k):
            return str(args[k])[:120]
    if tool == "ha_service":
        return f"{args.get('domain')}.{args.get('service')}"
    return ""


def summary(res):
    if not isinstance(res, dict):
        return str(res)[:150]
    for k in ("found", "open", "status", "exit_code", "mbps", "avg_ms", "count", "answers", "changed", "written", "saved", "complete", "sha256"):
        if k in res:
            v = res[k]
            if isinstance(v, list):
                v = len(v)
            return f"{k}={v}"
    return "ok"


# ---------------- provisioning: fill in missing settings from a signed command (Home Assistant path only) ----------------
def provision(args, via):
    """Fills ONLY missing settings: Hark's server address, the approval public key, a printer address hint.
    Accepted only through Home Assistant (never from the server queue). Existing values are never replaced here;
    replacing the approval key needs a full re-pair (reset_pairing)."""
    global SITE, SITE_SOURCE, APPROVAL_PUB
    if via != "ha":
        raise tools.ToolError("provision is only accepted through Home Assistant")
    tools.rate_check("provision")
    changed, kept = [], []
    site = valid_site(args.get("site") or "")
    if args.get("site") and not site:
        raise tools.ToolError("site must be an https address")
    if site and not SITE:
        write_private(SITE_FILE, site); SITE, SITE_SOURCE = site, "paired"; changed.append("site")
    elif site and site != SITE:
        kept.append("site")
    ap = str(args.get("approval_pub") or "").lower()
    if ap and not HEX64.match(ap):
        raise tools.ToolError("approval_pub must be 64 hex characters")
    if ap and not APPROVAL_PUB:
        write_private(APPROVAL_FILE, ap); APPROVAL_PUB = ap; changed.append("approval_key")
    elif ap and ap != APPROVAL_PUB:
        kept.append("approval_key (already set; re-pair to replace it)")
    hint = args.get("doc_printer_ip")
    if hint:
        if not tools.ip_allowed(hint, payload=True):
            raise tools.ToolError("doc_printer_ip must be a device on your network")
        if docs.save_hint(str(hint), only_if_missing=True):
            changed.append("doc_printer_ip")
    if "site" in changed:
        _hello_at[0] = 0
        threading.Thread(target=hello, daemon=True).start()
    return {"changed": changed, "kept_existing": kept, "provisioned": provisioned()}


# ---------------- running one command ----------------
_verify_lock = threading.Lock()


def handle(c, ctx, via="ha"):
    with _verify_lock:   # check + remember the nonce atomically, so a duplicate delivery can never run twice
        ok, why, tier, args, signed = verify(c)
        if signed:                      # only signed commands may burn a nonce (no unsigned way to block Hark)
            remember(c["nonce"])
        if ok and isinstance(c.get("approval"), dict):
            remember(c["approval"]["nonce"])
    tool = str(c.get("tool"))[:30]
    args = args or {}
    if ok and tool not in ALWAYS_ON and not ctx["kill"].enabled(force=True):
        ok, why = False, f"kill switch is {ctx['kill'].state}"
    if not ok:
        haapi.audit(tool, target_of(tool, args), "refused: " + why, ok=False, cmd_id=c.get("id") if signed else None, tier=tier)
        return {"id": c.get("id"), "ok": False, "status": "rejected", "result": {"error": why}}
    t0 = time.time()
    try:
        res = provision(args, via) if tool == "provision" else tools.run(tool, args, ctx)
        haapi.audit(tool, target_of(tool, args), summary(res), ok=True, cmd_id=c["id"], tier=tier)
        return {"id": c["id"], "ok": True, "result": {"data": res, "seconds": round(time.time() - t0, 2)}}
    except tools.ToolError as e:
        haapi.audit(tool, target_of(tool, args), "refused: " + str(e), ok=False, cmd_id=c["id"], tier=tier)
        return {"id": c["id"], "ok": False, "status": "rejected", "result": {"error": str(e)}}
    except Exception as e:
        haapi.audit(tool, target_of(tool, args), "error: " + type(e).__name__, ok=False, cmd_id=c["id"], tier=tier)
        return {"id": c["id"], "ok": False, "result": {"error": f"{type(e).__name__}: {e}"[:500]}}


# ---------------- status sensor ----------------
_last_status = {"v": None, "t": 0}
PAIRING = {"open": False}


def publish_status(ctx, poll_ok=None):
    if poll_ok is not None:
        ctx["poll_ok"] = poll_ok
    on = ctx["kill"].enabled()
    ev = ctx.get("events")
    prov = provisioned()
    if not SECRET:
        st = "waiting for pairing" if PAIRING["open"] else "not paired (restart the app to pair)"
    elif not all(prov.values()):
        st = "needs setup from Hark"
    else:
        st = "on" if on else "off"
    a = {"friendly_name": "Hark Gateway", "icon": "mdi:shield-lock" if on else "mdi:shield-off",
         "version": VERSION, "kill_switch": ctx["kill"].state, "kill_switch_entity": haapi.KILL_ENTITY,
         "listening_for_hark": bool(ev and ev.connected), "command_event": CMD_EVENT,
         "worker_reachable": ctx.get("poll_ok"), "secret_source": SECRET_SOURCE, "site_source": SITE_SOURCE,
         "provisioned": prov, "needs_provision": not all(prov.values()), "pairing_open": PAIRING["open"],
         "tools_enabled": sorted(ctx["enabled_tools"]),
         "ssh_public_key": tools.ssh_pubkey(create=False) or "", "firewall_configured": bool(
             OPTS.get("opnsense_key") and OPTS.get("opnsense_secret"))}
    if (st, a) == _last_status["v"] and time.time() - _last_status["t"] < 600:
        return
    try:
        haapi.ha("POST", "/states/sensor.hark_gateway", {"state": st, "attributes": a})
        _last_status.update(v=(st, a), t=time.time())
    except Exception as e:
        print("status sensor failed", e)


# ---------------- results: sealed into Home Assistant (Hark reads them by REST), copy to Hark's server ----------------
_results = {}                 # entity_id -> time written (for clean-up)
_results_lock = threading.Lock()


def result_entity(cid):
    suffix = re.sub(r"[^a-z0-9_]", "_", str(cid).lower())[:40].strip("_") or "unknown"
    return RESULT_PREFIX + suffix


def shrink(result, limit=RESULT_MAX_ATTR):
    """Returns (result_for_ha, truncated). Big results are cut in Home Assistant; the full result still goes to
    Hark's server, where Hark fetches it."""
    raw = json.dumps(result, default=str)
    if len(raw) <= limit:
        return result, False
    return {"preview": raw[:limit - 400], "note": f"result was {len(raw)} bytes; full copy is on Hark's server"}, True


def seal_result(cid, res):
    """Results in Home Assistant are encrypted with a key derived from the gateway secret: other HA users, the
    recorder (history database) and backups only see ciphertext."""
    return pairing.box(SECRET, "result|" + str(cid), json.dumps(res, default=str))


def publish_result(out, cmd, via, status=None):
    cid = out.get("id") or cmd.get("id")
    st = status or out.get("status") or ("done" if out.get("ok") else "error")
    res, truncated = shrink(out.get("result"))
    ent = result_entity(cid)
    if via == "ha":
        try:
            attrs = {"friendly_name": f"Hark Gateway result {cid}", "icon": "mdi:console", "id": cid,
                     "tool": cmd.get("tool"), "ok": out.get("ok"), "status": st, "truncated": truncated,
                     "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S%z") if st != "running" else None}
            if st != "running":
                attrs["sealed"] = seal_result(cid, res)
            haapi.ha("POST", "/states/" + ent, {"state": st, "attributes": attrs})
            with _results_lock:
                _results[ent] = time.time()
        except Exception as e:
            print("result sensor failed", e)
        if st != "running":
            try:
                haapi.ha("POST", "/events/" + RESULT_EVENT, {"id": cid, "ok": out.get("ok"), "status": st,
                                                            "entity_id": ent, "truncated": truncated})
            except Exception as e:
                print("result event failed", e)
    if st == "running" or not SITE:
        return
    body = dict(out, via=via, cmd={k: cmd.get(k) for k in ("id", "ts", "nonce", "tool", "args", "sig")})

    def post():
        for attempt in range(3):
            try:
                gw_req("POST", "/gw/result", body, timeout=30); return
            except Exception as e:
                print("result copy to Hark's server failed", e); time.sleep(3 * (attempt + 1))
    if via == "worker":
        post()
    else:
        threading.Thread(target=post, daemon=True).start()


def cleanup_results():
    """Removes per-command result sensors after 15 minutes (Hark normally deletes them itself once read)."""
    try:  # leftovers from before a restart
        for st in haapi.ha("GET", "/states", timeout=20) or []:
            eid = st.get("entity_id", "")
            if eid.startswith(RESULT_PREFIX):
                with _results_lock:
                    _results.setdefault(eid, time.time() - RESULT_KEEP + 60)
    except Exception as e:
        print("result clean-up scan failed", e)
    while True:
        cutoff = time.time() - RESULT_KEEP
        with _results_lock:
            old = [e for e, t in _results.items() if t < cutoff]
        for e in old:
            try:
                haapi.ha("DELETE", "/states/" + e)
            except urllib.error.HTTPError as err:
                if err.code != 404:
                    print("result clean-up failed", e, err); continue
            except Exception as err:
                print("result clean-up failed", e, err); continue
            with _results_lock:
                _results.pop(e, None)
        time.sleep(60)


# ---------------- command intake: Home Assistant events (instant), bounded ----------------
_cmd_queue = queue.Queue(maxsize=MAX_QUEUE)
_intake = {"accepted": [], "dropped": 0, "last_log": 0}
_intake_lock = threading.Lock()


def _note_drop(why):
    with _intake_lock:
        _intake["dropped"] += 1
        if time.time() - _intake["last_log"] > 60:   # never let a flood fill the log
            print(f"ha events: ignored {_intake['dropped']} command event(s) in the last minute (latest: {why})")
            _intake["dropped"], _intake["last_log"] = 0, time.time()


def admit(data):
    """Cheap checks run on the WebSocket thread before anything is queued. Returns '' to accept, else the reason."""
    if not SECRET:
        return "not paired"
    try:
        size = len(json.dumps(data))
    except Exception:
        return "unreadable"
    if size > MAX_EVENT_BYTES:
        return f"too large ({size} bytes)"
    if not sig_ok(data):
        return "unsigned or badly signed"
    if data["nonce"] in NONCES:
        return "duplicate"
    t = time.time()
    with _intake_lock:
        _intake["accepted"] = [x for x in _intake["accepted"] if t - x < 60]
        if len(_intake["accepted"]) >= ACCEPT_PER_MIN:
            return "rate limit"
        _intake["accepted"].append(t)
    return ""


def on_ha_event(etype, data, ev, ctx):
    if etype != CMD_EVENT or not isinstance(data, dict):
        return
    why = admit(data)
    if why:
        _note_drop(why); return
    try:
        _cmd_queue.put_nowait(data)
        print("command (via HA)", data["id"], data["tool"])
    except queue.Full:
        _note_drop("queue full")


def cmd_worker(ctx):
    while True:
        data = _cmd_queue.get()
        try:
            publish_result({"id": data["id"], "ok": None}, data, "ha", status="running")   # "got it" for Hark
            publish_result(handle(data, ctx, via="ha"), data, "ha")
        except Exception as e:
            print("command worker error", type(e).__name__, e)


# ---------------- safety net: short checks of the server command queue ----------------
def fallback_loop(ctx):
    backoff = FALLBACK_EVERY
    while True:
        publish_status(ctx)
        if not SECRET or not SITE:
            time.sleep(15); continue
        try:
            q = "?" + urllib.parse.urlencode({"v": VERSION, "enabled": int(ctx["kill"].enabled()),
                                              "ha": int(bool(ctx["events"].connected))})
            for _ in range(10):  # drain whatever is waiting, then sleep
                code, j = gw_req("GET", "/gw/next", timeout=30, query=q)
                if not (code == 200 and j and isinstance(j.get("cmd"), dict)):
                    break
                c = j["cmd"]
                print("command (via server)", str(c.get("id"))[:40], str(c.get("tool"))[:30])
                publish_result(handle(c, ctx, via="worker"), c, "worker")
            backoff = FALLBACK_EVERY
            if not ctx.get("poll_ok"):
                publish_status(ctx, poll_ok=True)
        except urllib.error.HTTPError as e:
            print("server check: HTTP", e.code, "(401 = gateway secret does not match)" if e.code == 401 else "")
            publish_status(ctx, poll_ok=False); backoff = min(backoff * 2, 600)
        except Exception as e:
            print("server check error:", e)
            publish_status(ctx, poll_ok=False); backoff = min(backoff * 2, 600)
        time.sleep(backoff)


# ---------------- pairing: get secret + server address + approval key from Hark through Home Assistant ----------------
PAIR_REQUEST, PAIR_ANSWER = "sensor.hark_gateway_pairing_request", "sensor.hark_gateway_pairing"


def check_secret(candidate, site):
    """True = Hark's server accepts it, False = it rejects it, None = server unknown/unreachable (can't tell)."""
    if not site:
        return None
    try:
        code, _ = gw_req("GET", "/gw/hello", query="?v=" + VERSION + "&pairing=1", site=site, secret=candidate)
        return code == 200
    except urllib.error.HTTPError as e:
        return False if e.code == 401 else None
    except Exception:
        return None


def parse_pairing(text):
    """Pairing payload: v2 JSON {"v":2,"secret","site","approval_pub","doc_printer_ip"} or a bare secret (v1)."""
    text = text.strip()
    if text.startswith("{"):
        p = json.loads(text)
        if not isinstance(p, dict):
            raise ValueError("pairing payload is not an object")
    else:
        p = {"secret": text}
    sec = str(p.get("secret") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{32,128}", sec):
        raise ValueError("pairing answer is not a gateway secret")
    site = valid_site(p.get("site") or "") if p.get("site") else None
    if p.get("site") and not site:
        raise ValueError("pairing answer has a bad server address")
    ap = str(p.get("approval_pub") or "").lower()
    if ap and not HEX64.match(ap):
        raise ValueError("pairing answer has a bad approval key")
    return {"secret": sec, "site": site, "approval_pub": ap, "doc_printer_ip": p.get("doc_printer_ip")}


def pairing_marker():
    try:
        return json.load(open(PAIRED_FILE))
    except Exception:
        return {}


def should_pair():
    """True when the pairing window may open: never paired, or the owner asked for a reset (reset_pairing on,
    not yet used since it was switched on)."""
    global SECRET, SECRET_SOURCE, APPROVAL_PUB
    m = pairing_marker()
    if OPTS.get("reset_pairing"):
        if m.get("reset_consumed"):
            print("reset_pairing is still on but was already used; switch it off (re-pairing happens once per switch-on)")
        else:
            print("reset_pairing: forgetting the old pairing and opening a new pairing window")
            for f in (SECRET_FILE, APPROVAL_FILE, SITE_FILE):
                try:
                    os.remove(f)
                except FileNotFoundError:
                    pass
            if SECRET_SOURCE == "paired":
                SECRET, SECRET_SOURCE = "", None
            APPROVAL_PUB = ""
            return True, True
    elif m.get("reset_consumed"):
        m["reset_consumed"] = False
        write_private(PAIRED_FILE, json.dumps(m))
    return (not SECRET), False


def pair(ctx, is_reset=False):
    """Opens the pairing window (30 min). Publishes only a one-time public key; prints its fingerprint in this app's
    own log so Hark can tell a genuine request from one swapped in by someone else with Home Assistant access.
    Returns True when paired."""
    global SECRET, SECRET_SOURCE, SITE, SITE_SOURCE, APPROVAL_PUB
    priv, pub = pairing.keypair()
    pub_hex = format(pub, "x")
    fp = pairing.fingerprint(pub_hex)
    print(f"pairing: window open for {PAIR_WINDOW // 60} min; request fingerprint {fp} (Hark checks this)")
    PAIRING["open"] = True
    opened, published = time.time(), 0
    try:
        while time.time() - opened < PAIR_WINDOW:
            if time.time() - published > 600:   # (re)publish; HA forgets states on restart
                try:
                    haapi.ha("POST", "/states/" + PAIR_REQUEST, {"state": "waiting", "attributes": {
                        "friendly_name": "Hark Gateway pairing request", "icon": "mdi:link-variant",
                        "app_public": pub_hex, "fingerprint": fp, "version": VERSION,
                        "note": "Public key only. Hark answers in sensor.hark_gateway_pairing; nothing to do here."}})
                    published = time.time()
                    print(f"pairing: request fingerprint {fp}")
                except Exception as e:
                    print("pairing: could not publish request", e)
            publish_status(ctx)
            try:
                ans = haapi.ha("GET", "/states/" + PAIR_ANSWER, timeout=10)
            except urllib.error.HTTPError:
                ans = None
            except Exception as e:
                print("pairing: HA read failed", e); ans = None
            if ans and isinstance(ans.get("attributes"), dict) and ans["attributes"].get("ciphertext"):
                try:
                    p = parse_pairing(pairing.open_sealed(priv, pub, ans["attributes"]))
                    site = valid_site(OPTS.get("site") or "") or p["site"] or SITE
                    ok = check_secret(p["secret"], site)
                    if ok is False:
                        raise ValueError("Hark's server rejected the paired secret")
                    write_private(SECRET_FILE, p["secret"])
                    SECRET, SECRET_SOURCE = p["secret"], "paired"
                    if p["site"]:
                        write_private(SITE_FILE, p["site"])
                        if SITE_SOURCE != "app option":
                            SITE, SITE_SOURCE = p["site"], "paired"
                    if p["approval_pub"]:
                        write_private(APPROVAL_FILE, p["approval_pub"]); APPROVAL_PUB = p["approval_pub"]
                    if p.get("doc_printer_ip") and tools.ip_allowed(p["doc_printer_ip"], payload=True):
                        docs.save_hint(str(p["doc_printer_ip"]), only_if_missing=True)
                    write_private(PAIRED_FILE, json.dumps({"at": int(time.time()), "version": VERSION,
                                                           "reset_consumed": bool(is_reset)}))
                    print("pairing: done (", "checked with Hark's server" if ok else "server not reachable to double-check yet",
                          "; approval key", "received" if APPROVAL_PUB else "MISSING", "). Pairing is now closed.")
                    for e in (PAIR_ANSWER, PAIR_REQUEST):
                        try:
                            haapi.ha("DELETE", "/states/" + e)
                        except Exception:
                            pass
                    try:
                        haapi.ha("POST", "/events/hark_gateway_paired", {"version": VERSION})
                    except Exception:
                        pass
                    return True
                except Exception as e:
                    print("pairing: answer not usable:", e)
                    try:
                        haapi.ha("DELETE", "/states/" + PAIR_ANSWER)
                    except Exception:
                        pass
            time.sleep(5)
        print("pairing: window closed without an answer; restart the app to open it again")
        for e in (PAIR_REQUEST, PAIR_ANSWER):
            try:
                haapi.ha("DELETE", "/states/" + e)
            except Exception:
                pass
        return False
    finally:
        PAIRING["open"] = False
        publish_status(ctx)


def main():
    print(f"Hark HA Gateway {VERSION} starting; server address {'set (' + SITE_SOURCE + ')' if SITE else 'not set yet'}")
    enabled_tools = set(ALWAYS_ON) | {t for t, opt in TOOL_OPTION.items() if OPTS.get(opt, True)}
    if not (OPTS.get("opnsense_key") and OPTS.get("opnsense_secret")):
        enabled_tools -= {"firewall", "opnsense"}
    kill = haapi.KillSwitch(OPTS)
    docs_wake = threading.Event()

    def wake_docs(a):
        docs_wake.set()
        return {"woke": True, "job": str(a.get("job") or "")[:20]}
    ctx = {"opts": OPTS, "state": state, "save": save, "kill": kill, "enabled_tools": enabled_tools,
           "version": VERSION, "ha": haapi.ha, "site_cfg": site_cfg, "wake_docs": wake_docs, "provisioned": provisioned}
    events = haapi.EventStream([CMD_EVENT], lambda et, d, ev: on_ha_event(et, d, ev, ctx),
                               on_state=lambda up, why: publish_status(ctx))
    ctx["events"] = events
    hello()
    # printing first: it is the critical path and must not wait on anything else
    threading.Thread(target=receipt.run, args=(ctx,), daemon=True, name="receipt").start()
    threading.Thread(target=docs.run, args=(haapi.ha, site_cfg, receipt.local_nets, None, OPTS),
                     kwargs={"wake": docs_wake}, daemon=True, name="docs").start()
    try:
        kill.ensure_helper()
    except Exception as e:
        print("kill switch setup failed", e)
    try:
        tools.ssh_pubkey()
    except Exception as e:
        print("ssh key generation failed", e)
    do_pair, is_reset = should_pair()
    if do_pair:
        if pair(ctx, is_reset):
            hello()
            docs_wake.set()
    else:
        print("gateway secret from", SECRET_SOURCE or "nowhere (not paired; set reset_pairing to pair again)")
    if SECRET and not all(provisioned().values()):
        print("needs setup from Hark:", ", ".join(k for k, v in provisioned().items() if not v),
              "missing (Hark sends it through Home Assistant; change commands stay off until then)")
    for _ in range(4):
        threading.Thread(target=cmd_worker, args=(ctx,), daemon=True, name="cmd").start()
    threading.Thread(target=events.run_forever, daemon=True, name="ha-events").start()
    threading.Thread(target=cleanup_results, daemon=True, name="cleanup").start()

    def rehello():
        while True:
            time.sleep(3600)
            hello()
    threading.Thread(target=rehello, daemon=True).start()
    fallback_loop(ctx)


if __name__ == "__main__":
    main()

"""Home Assistant access for the Hark Home Assistant Gateway: REST via the Supervisor proxy, a tiny WebSocket client
(creates the kill-switch helper, and keeps a live subscription to Hark's command events), the kill switch itself,
and the audit trail. Stdlib only."""
import base64, json, os, socket, struct, threading, time, urllib.request, urllib.error

AUDIT_FILE = os.environ.get("AUDIT_FILE", "/data/audit.jsonl")
AUDIT_MAX_LINES = 2000
KILL_ENTITY = "input_boolean.hark_gateway_enabled"


def _sup_token():
    t = os.environ.get("SUPERVISOR_TOKEN") or os.environ.get("HASSIO_TOKEN")
    for p in ("/run/s6/container_environment/SUPERVISOR_TOKEN", "/var/run/s6/container_environment/SUPERVISOR_TOKEN",
              "/run/s6/container_environment/HASSIO_TOKEN"):
        if not t:
            try:
                t = open(p).read().strip()
            except Exception:
                pass
    if not t:
        print("WARNING: no Supervisor token found; Home Assistant API calls will fail")
    return t or ""


SUP = _sup_token()
HA_BASE = os.environ.get("HA_API_BASE", "http://supervisor/core/api")   # overridable for local tests only


def ha(method, path, body=None, timeout=10):
    req = urllib.request.Request(HA_BASE + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {SUP}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        try:
            return json.loads(raw or b"null")
        except ValueError:
            return raw.decode(errors="replace")


# ---------------- minimal WebSocket client (text frames; answers pings) ----------------
SUP_HOST = os.environ.get("SUPERVISOR_HOST", "supervisor")      # overridable for local tests only
SUP_PORT = int(os.environ.get("SUPERVISOR_PORT", "80"))
WS_MAX_FRAME = 4 * 1024 * 1024   # Home Assistant event messages are small; refuse anything absurd instead of buffering it


def _ws_frame(s, op, data=b"", lock=None):
    hdr = bytearray([0x80 | op])
    n = len(data)
    if n < 126:
        hdr.append(0x80 | n)
    elif n < 65536:
        hdr.append(0x80 | 126); hdr += struct.pack(">H", n)
    else:
        hdr.append(0x80 | 127); hdr += struct.pack(">Q", n)
    mask = os.urandom(4)
    hdr += mask
    frame = bytes(hdr) + bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    if lock:
        with lock:
            s.sendall(frame)
    else:
        s.sendall(frame)


def _ws_send(s, text, lock=None):
    _ws_frame(s, 0x1, text.encode(), lock)


def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise ConnectionError("websocket closed")
        buf += c
    return buf


def _ws_recv(s, lock=None):
    """Returns the next JSON text message. Answers server pings (Home Assistant pings every ~55 s and drops
    clients that don't answer). Raises socket.timeout if nothing arrives within the socket timeout."""
    msg = b""
    while True:
        b1, b2 = _recv_exact(s, 2)
        n = b2 & 0x7F
        if n == 126:
            n = struct.unpack(">H", _recv_exact(s, 2))[0]
        elif n == 127:
            n = struct.unpack(">Q", _recv_exact(s, 8))[0]
        mask = _recv_exact(s, 4) if b2 & 0x80 else None
        if n > WS_MAX_FRAME or len(msg) + n > WS_MAX_FRAME:
            raise ConnectionError(f"websocket message too large ({n} bytes)")
        data = _recv_exact(s, n)
        if mask:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        op = b1 & 0x0F
        if op == 0x8:
            raise ConnectionError("websocket closed by server")
        if op == 0x9:  # ping -> pong with the same payload
            _ws_frame(s, 0xA, data, lock)
            continue
        if op == 0xA:  # pong
            continue
        msg += data
        if b1 & 0x80:
            return json.loads(msg.decode())


def ws_connect(timeout=15):
    """Opens and authenticates a Home Assistant WebSocket through the Supervisor. Returns the socket."""
    s = socket.create_connection((SUP_HOST, SUP_PORT), timeout=timeout)
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        s.sendall((f"GET /core/websocket HTTP/1.1\r\nHost: {SUP_HOST}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            c = s.recv(1)
            if not c:
                raise ConnectionError("no websocket handshake")
            head += c
        if b" 101 " not in head.split(b"\r\n")[0]:
            raise ConnectionError("websocket upgrade refused: " + head.split(b"\r\n")[0].decode(errors="replace"))
        first = _ws_recv(s)
        if first.get("type") == "auth_required":
            _ws_send(s, json.dumps({"type": "auth", "access_token": SUP}))
            ok = _ws_recv(s)
            if ok.get("type") != "auth_ok":
                raise PermissionError("websocket auth failed: " + json.dumps(ok)[:200])
        return s
    except Exception:
        s.close()
        raise


def ws_commands(cmds, timeout=15):
    """Runs Home Assistant WebSocket commands (list of dicts without 'id') and returns their result messages."""
    s = ws_connect(timeout)
    try:
        out = []
        for i, c in enumerate(cmds, start=1):
            _ws_send(s, json.dumps({"id": i, **c}))
            while True:
                m = _ws_recv(s)
                if m.get("id") == i and m.get("type") == "result":
                    out.append(m); break
        return out
    finally:
        try:
            s.close()
        except Exception:
            pass


class EventStream:
    """Keeps a WebSocket open to Home Assistant, subscribed to one or more event types, and calls
    on_event(event_type, data, event) for each one. Reconnects with backoff (2 s doubling to 60 s) if the
    connection drops. Sends its own keep-alive ping every 30 s and reconnects if HA goes quiet for 90 s."""

    def __init__(self, event_types, on_event, on_state=None):
        self.event_types = list(event_types)
        self.on_event = on_event
        self.on_state = on_state or (lambda connected, why: None)
        self.connected = False
        self.connected_since = None
        self.last_event_at = None
        self.reconnects = 0
        self.last_error = None

    def run_forever(self):
        backoff = 2
        while True:
            try:
                self._session()
                backoff = 2
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"[:200]
            if self.connected:
                self.connected = False
                self.on_state(False, self.last_error)
            self.reconnects += 1
            print(f"ha events: disconnected ({self.last_error}); reconnecting in {backoff} s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)

    def _session(self):
        s = ws_connect()
        lock = threading.Lock()
        try:
            ids = {}
            for i, et in enumerate(self.event_types, start=1):
                _ws_send(s, json.dumps({"id": i, "type": "subscribe_events", "event_type": et}), lock)
                ids[i] = et
            pending = set(ids)
            s.settimeout(30)
            last_rx, ping_id, next_id = time.time(), None, len(ids) + 1
            while True:
                try:
                    m = _ws_recv(s, lock)
                except socket.timeout:
                    if time.time() - last_rx > 90:
                        raise ConnectionError("no answer from Home Assistant for 90 s")
                    ping_id = next_id; next_id += 1
                    _ws_send(s, json.dumps({"id": ping_id, "type": "ping"}), lock)
                    continue
                last_rx = time.time()
                t = m.get("type")
                if t == "result" and m.get("id") in pending:
                    if not m.get("success"):
                        raise PermissionError(f"subscribe to {ids[m['id']]} refused: {json.dumps(m.get('error'))[:200]}")
                    pending.discard(m["id"])
                    if not pending:
                        self.connected, self.connected_since, self.last_error = True, time.time(), None
                        print("ha events: subscribed to", ", ".join(self.event_types))
                        self.on_state(True, None)
                elif t == "event":
                    ev = m.get("event") or {}
                    self.last_event_at = time.time()
                    try:
                        self.on_event(ev.get("event_type"), ev.get("data") or {}, ev)
                    except Exception as e:
                        print("ha events: handler error", e)
        finally:
            try:
                s.close()
            except Exception:
                pass


# ---------------- kill switch ----------------
class KillSwitch:
    """The switch is the Home Assistant helper input_boolean.hark_gateway_enabled (created by the app on first run).
    ON = Hark may run network tools. OFF = every network command is refused (status reads and printing still work).
    Fail-closed (1.2.0): if the helper is missing, unavailable, or can't be read, network commands are refused too.
    The app option `enabled: false` is a second, harder off switch."""

    def __init__(self, opts):
        self.opts = opts
        self.state = "unknown"
        self.checked = 0
        self.created_tried = False

    def ensure_helper(self):
        if self.created_tried:
            return
        self.created_tried = True
        try:
            ha("GET", "/states/" + KILL_ENTITY)
            return
        except Exception:
            pass
        try:
            res = ws_commands([{"type": "input_boolean/create", "name": "Hark Gateway enabled", "icon": "mdi:shield-lock"}])
            if res and res[0].get("success"):
                ha("POST", "/services/input_boolean/turn_on", {"entity_id": KILL_ENTITY})
                print("created kill switch helper", KILL_ENTITY, "(turned on)")
            else:
                print("could not create kill switch helper:", json.dumps(res)[:300])
        except Exception as e:
            print("could not create kill switch helper:", e)

    def enabled(self, force=False):
        if not self.opts.get("enabled", True):
            self.state = "off (app option)"
            return False
        if force or time.time() - self.checked > 2:
            self.checked = time.time()
            try:
                st = (ha("GET", "/states/" + KILL_ENTITY, timeout=5) or {}).get("state")
                self.state = "on" if st == "on" else ("off" if st == "off" else f"off (helper is {st or 'empty'})")
            except urllib.error.HTTPError as e:
                self.state = "off (helper missing)" if e.code == 404 else f"off (helper unreadable: HTTP {e.code})"
            except Exception:
                self.state = "off (helper unreadable)"
        return self.state == "on"


# ---------------- audit trail ----------------
_audit_lock = threading.Lock()


def audit(tool, target, result, ok=True, cmd_id=None, tier=None, detail=None):
    rec = {"time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "id": cmd_id, "tool": tool, "tier": tier,
           "target": str(target or "")[:200], "result": str(result)[:300], "ok": bool(ok)}
    if detail:
        rec["detail"] = str(detail)[:500]
    with _audit_lock:
        try:
            lines = []
            if os.path.exists(AUDIT_FILE):
                with open(AUDIT_FILE) as f:
                    lines = f.readlines()
            lines.append(json.dumps(rec) + "\n")
            with open(AUDIT_FILE, "w") as f:
                f.writelines(lines[-AUDIT_MAX_LINES:])
        except Exception as e:
            print("audit file write failed", e)
    try:
        ha("POST", "/states/sensor.hark_gateway_last_action", {
            "state": f"{tool}: {rec['result']}"[:250],
            "attributes": {"friendly_name": "Hark Gateway last action", "icon": "mdi:router-network",
                           "tool": tool, "tier": tier, "target": rec["target"], "result": rec["result"],
                           "ok": rec["ok"], "command_id": cmd_id, "time": rec["time"]}})
    except Exception as e:
        print("audit sensor failed", e)
    try:
        ha("POST", "/services/logbook/log", {"name": "Hark Gateway",
                                             "message": f"{'ran' if ok else 'refused/failed'} {tool} on {rec['target'] or '-'}: {rec['result'][:150]}",
                                             "entity_id": "sensor.hark_gateway_last_action", "domain": "hark_gateway"})
    except Exception as e:
        print("logbook failed", e)
    print("AUDIT", json.dumps(rec))
    return rec


def read_audit(n=50):
    try:
        with open(AUDIT_FILE) as f:
            return [json.loads(x) for x in f.readlines()[-int(n):]]
    except Exception:
        return []

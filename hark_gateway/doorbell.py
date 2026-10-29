"""Doorbell (2.0.4): a WebSocket the app keeps open to your relay, so commands and documents queued there reach the
app within about a second, without Hark needing access to Home Assistant. Stdlib only.

- Outbound only: the app connects out to your relay (wss://<relay>/gw/ws), like every other request it makes.
- The connection is opened with the same signed X-GW-Auth header as every /gw request.
- It carries only "wake" notices ({"wake": "gw"} or {"wake": "docs"}), never commands, results or secrets. On a wake
  the app fetches the work over the normal signed /gw/next (or /docs/next) and checks it exactly as before.
- Keep-alive: the app sends "ping" every 30 s; the relay answers "pong" without waking up (Cloudflare hibernation),
  so an idle doorbell costs almost nothing on the free plan.
- A relay without the doorbell (older template) answers 404/426: the app then just keeps its once-a-minute check and
  tries the doorbell again every 10 minutes.
"""
import base64, hashlib, json, os, socket, ssl, struct, time, urllib.parse

PING_EVERY = 30          # seconds between keep-alive pings
DEAD_AFTER = 75          # seconds without any frame from the relay = connection is dead, reconnect
OLD_RELAY_RETRY = 600    # relay has no doorbell: try again this often


class NoDoorbell(Exception):
    """The relay answered, but has no doorbell (older relay template)."""


def _frame(op, data=b""):
    hdr = bytearray([0x80 | op])
    n = len(data)
    if n < 126:
        hdr.append(0x80 | n)
    elif n < 65536:
        hdr.append(0x80 | 126); hdr += struct.pack(">H", n)
    else:
        hdr.append(0x80 | 127); hdr += struct.pack(">Q", n)
    mask = os.urandom(4)
    return bytes(hdr) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data))


def _exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise ConnectionError("doorbell closed")
        buf += c
    return buf


def read_frame(s, max_len=65536):
    """Returns (opcode, payload bytes). Raises socket.timeout when nothing arrives within the socket timeout."""
    b1, b2 = _exact(s, 2)
    n = b2 & 0x7F
    if n == 126:
        n = struct.unpack(">H", _exact(s, 2))[0]
    elif n == 127:
        n = struct.unpack(">Q", _exact(s, 8))[0]
    if n > max_len:
        raise ConnectionError("doorbell frame too large")
    mask = _exact(s, 4) if b2 & 0x80 else None
    data = _exact(s, n)
    if mask:
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return b1 & 0x0F, data


def connect(site, auth_header, user_agent="hark-gateway", timeout=15):
    """Opens wss://<site>/gw/ws (ws:// only for a local test relay). auth_header(path) returns the X-GW-Auth value."""
    u = urllib.parse.urlsplit(site)
    port = u.port or (443 if u.scheme == "https" else 80)
    path = (u.path.rstrip("/") or "") + "/gw/ws"
    raw = socket.create_connection((u.hostname, port), timeout=timeout)
    s = ssl.create_default_context().wrap_socket(raw, server_hostname=u.hostname) if u.scheme == "https" else raw
    try:
        key = base64.b64encode(os.urandom(16)).decode()
        host = u.hostname + (f":{u.port}" if u.port else "")
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                   f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: {user_agent}\r\n"
                   f"X-GW-Auth: {auth_header(path)}\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            c = s.recv(1)
            if not c:
                raise ConnectionError("doorbell: relay closed during handshake")
            head += c
            if len(head) > 16384:
                raise ConnectionError("doorbell: handshake too long")
        status = head.split(b"\r\n", 1)[0].decode(errors="replace")
        code = int(status.split()[1]) if len(status.split()) > 1 and status.split()[1].isdigit() else 0
        if code in (404, 426):
            raise NoDoorbell(status)
        if code != 101:
            raise ConnectionError(f"doorbell: relay answered {status[:80]}")
        want = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        if want.encode() not in head:
            raise ConnectionError("doorbell: bad handshake answer")
        return s
    except Exception:
        s.close()
        raise


def listen(s, on_wake, stop=lambda: False):
    """Reads until the connection ends. on_wake(channel) for each wake notice. Returns normally on close."""
    s.settimeout(PING_EVERY)
    last_rx = time.time()
    while not stop():
        try:
            op, data = read_frame(s)
        except socket.timeout:
            if time.time() - last_rx > DEAD_AFTER:
                raise ConnectionError("doorbell: no answer from the relay")
            s.sendall(_frame(0x1, b"ping"))
            continue
        last_rx = time.time()
        if op == 0x8:
            return
        if op == 0x9:
            s.sendall(_frame(0xA, data)); continue
        if op != 0x1 or data == b"pong":
            continue
        try:
            msg = json.loads(data.decode())
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("wake") in ("gw", "docs"):
            on_wake(msg["wake"])

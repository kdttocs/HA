"""On-demand receipt printing for Hark's print_receipt tool: a network ESC/POS receipt printer on raw TCP 9100.
Stdlib only. Since 2.0.0 nothing here polls a queue; receipts print only when Hark asks.
Rule (1.2.1): never send bytes to a page printer's port 9100; any host that answers on IPP (631) is skipped."""
import ipaddress, re, socket, subprocess, textwrap, threading, time

COLS = 42
PORT = 9100


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


def find(hint=None):
    """On-demand lookup (since 2.0.0 the gateway no longer watches any public receipt queue). Tries the given or
    remembered address first, then searches the network. A host that speaks IPP (a page printer) is never sent
    ESC/POS bytes. Returns (ip, model) or (None, None)."""
    if hint:
        s = status(hint)
        if s in ("ready", "no_paper", "cover_open"):
            if s != "ready":
                raise RuntimeError(f"receipt printer at {hint} is not ready ({s.replace('_', ' ')})")
            return hint, query_id(hint)
    ip, name = discover()
    if ip and status(ip) != "ready":
        raise RuntimeError(f"receipt printer at {ip} is not ready ({status(ip).replace('_', ' ')})")
    return ip, name

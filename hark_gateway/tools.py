"""The network tools the Hark HA Gateway can run. Stdlib only.

Two tiers:
  read   - look only (discovery, scans, probes, GETs, DNS, SNMP read, speed, HA states, status) - runs on its own.
  change - anything that changes something (WoL, HTTP write, SSH, HA service call, firewall API POST) - the app
           refuses it unless an approval signed with the owner's separate approval key came with it.

Target rules (1.2.0): a tool only talks to addresses on the home network (RFC 1918 private ranges, CGNAT
100.64.0.0/10 and IPv6 unique-local fc00::/7). Never: loopback, 0.0.0.0, link-local / cloud metadata (169.254.x),
Home Assistant's internal Supervisor/Docker networks, or Home Assistant's own internal names. Tools that send data
(http, probe, snmp, ssh) also may not target this machine's own addresses. A name is resolved once, EVERY address it
resolves to must pass, and the connection goes to that checked address (no second lookup, so DNS rebinding can't
swap it). HTTP redirects are never followed. DNS and the speed test reach the internet only at fixed endpoints.
"""
import base64, hashlib, http.client, ipaddress, json, os, re, select, shutil, socket, ssl, struct, subprocess, threading, time
import urllib.parse

import haapi

DATA_DIR = os.environ.get("DATA_DIR", "/data")
SSH_KEY = os.path.join(DATA_DIR, "ssh", "id_ed25519")

ALLOWED_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]
BLOCKED_NETS = [ipaddress.ip_network(n) for n in (
    "172.30.32.0/23", "172.30.33.0/24",      # Home Assistant Supervisor / app (add-on) networks
    "172.17.0.0/16",                         # Docker's default bridge
    "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::/128", "::1/128", "fe80::/10", "ff00::/8")]
BLOCKED_NAMES = {"localhost", "supervisor", "hassio", "homeassistant", "home-assistant", "core", "observer", "dns",
                 "audio", "cli", "multicast", "host.docker.internal", "ip6-localhost", "ip6-loopback"}
BLOCKED_SUFFIXES = (".localhost", ".hassio", ".local.hass.io", ".hass.io", ".internal")
PUBLIC_DNS = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112"}
SPEEDTEST_URL = "https://speed.cloudflare.com/__down?bytes={n}"
HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9-]{1,63})*\.?$")

CHANGE_TOOLS = {"wol", "ssh", "ha_service", "ha_file_write", "lovelace_save"}
ALL_TOOLS = ["ping_sweep", "port_scan", "mdns", "ssdp", "http", "probe", "dns", "snmp", "latency", "speedtest",
             "ha_states", "status", "audit", "ssh_pubkey", "firewall", "wol", "ssh", "ha_service",
             "stage", "ha_file_read", "lovelace_get", "ha_check_config", "ha_file_write", "lovelace_save"]
# tool -> list of (max runs, per seconds) windows; every window must have room
LIMITS = {"ping_sweep": [(2, 60), (20, 3600)], "port_scan": [(3, 60), (30, 3600)], "mdns": [(4, 60)], "ssdp": [(4, 60)],
          "http": [(30, 60), (600, 3600)], "probe": [(30, 60), (600, 3600)], "dns": [(30, 60)], "snmp": [(20, 60), (400, 3600)],
          "latency": [(10, 60)], "speedtest": [(2, 600), (6, 86400)], "ha_states": [(20, 60)], "status": [(60, 60)],
          "audit": [(20, 60)], "ssh_pubkey": [(10, 60)], "firewall": [(20, 60)], "opnsense": [(20, 60)], "wol": [(10, 60)], "ssh": [(10, 60)],
          "ha_service": [(20, 60)], "print_doc": [(30, 60)],
          "stage": [(64, 60)], "ha_file_read": [(20, 60)], "lovelace_get": [(10, 60)], "ha_check_config": [(4, 60)],
          "ha_file_write": [(10, 60)], "lovelace_save": [(5, 60)]}
TOP_PORTS = [21, 22, 23, 25, 53, 67, 68, 69, 80, 81, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445,
             465, 500, 515, 548, 554, 587, 631, 636, 873, 902, 993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 1900,
             2049, 2082, 2083, 2086, 2181, 2375, 2376, 3000, 3128, 3260, 3306, 3389, 3478, 3689, 4443, 4500, 5000,
             5001, 5060, 5061, 5222, 5353, 5432, 5555, 5601, 5672, 5900, 5984, 6379, 6667, 7000, 7070, 8000, 8006,
             8008, 8009, 8080, 8081, 8086, 8096, 8123, 8181, 8200, 8443, 8554, 8883, 9000, 9090, 9091, 9100, 9200,
             9300, 9443, 10000, 11434, 27017, 32400, 51820]

# Home Assistant service calls: never allowed, even with approval (Supervisor control can restore backups, install
# apps, stop this app's own safety checks).
HA_DENY_DOMAINS = {"hassio"}
# Allowed only when the approved command also carries "dangerous_ok": true (Hark must name the risk when asking).
HA_DANGEROUS_DOMAINS = {"homeassistant", "shell_command", "python_script", "pyscript", "command_line", "recorder",
                        "backup", "system_log", "logger", "lock", "alarm_control_panel", "notify", "persistent_notification",
                        "rest_command", "script", "automation", "input_boolean", "update", "zha", "zwave_js", "mqtt"}
SENSITIVE_KEY = re.compile(r"(token|secret|passw|pwd|api[_-]?key|apikey|auth|bearer|cookie|session|credential|private|"
                           r"signature|^sig$|^code$|pin$|otp|^key$|_key$|latitude|longitude|gps)", re.I)
TOKENISH = re.compile(r"^(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*|[A-Fa-f0-9]{40,}|[A-Za-z0-9+/_-]{48,}={0,2})$")
URL_TOKEN = re.compile(r"([?&](?:token|access_token|auth|key|sig|signature|code)=)[^&\s\"']+", re.I)


class ToolError(Exception):
    pass


# ---------------- redaction (results leave this app: HA states, logbook, Hark's server) ----------------
def redact(obj, depth=0):
    """Copy of obj with secrets blanked: values under sensitive-looking keys, token-looking strings, and tokens in URLs."""
    if depth > 12:
        return "[deep]"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and SENSITIVE_KEY.search(k) and v not in (None, "", [], {}) and not isinstance(v, bool):
                out[k] = "[redacted]"
            else:
                out[k] = redact(v, depth + 1)
        return out
    if isinstance(obj, list):
        return [redact(v, depth + 1) for v in obj]
    if isinstance(obj, str):
        if TOKENISH.match(obj.strip()):
            return "[redacted]"
        return URL_TOKEN.sub(r"\1[redacted]", obj)
    return obj


def scrub_url(url):
    """For audit lines: drop user:password@ and the query string."""
    try:
        u = urllib.parse.urlsplit(str(url))
        host = u.hostname or ""
        if u.port:
            host += f":{u.port}"
        return urllib.parse.urlunsplit((u.scheme, host, u.path, "", "")) + ("?…" if u.query else "")
    except Exception:
        return "?"


# ---------------- target guards ----------------
def _norm_ip(ip):
    ip = ipaddress.ip_address(ip)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.version == 6 and ip.sixtofour:
        ip = ip.sixtofour
    return ip


_own = {"t": 0, "ips": set()}


def own_ips():
    """This machine's own addresses (the app shares the Home Assistant host's network)."""
    if time.time() - _own["t"] < 300:
        return _own["ips"]
    ips = set()
    try:
        out = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, timeout=5).stdout
        for m in re.finditer(r"inet6? ([0-9a-fA-F:.]+)/\d+", out):
            try:
                ips.add(str(_norm_ip(m.group(1))))
            except ValueError:
                pass
    except Exception:
        pass
    _own.update(t=time.time(), ips=ips)
    return ips


def ip_allowed(ip, payload=False):
    """True when ip is on the home network and not a forbidden internal address."""
    try:
        ip = _norm_ip(ip)
    except ValueError:
        return False
    if any(ip in n for n in BLOCKED_NETS if n.version == ip.version):
        return False
    if not any(ip in n for n in ALLOWED_NETS if n.version == ip.version):
        return False
    if payload and str(ip) in own_ips():
        return False
    return True


def is_local(host):
    """Kept for callers that only need a yes/no on an IP literal."""
    return ip_allowed(host)


def name_blocked(host):
    h = host.lower().rstrip(".")
    return h in BLOCKED_NAMES or h.endswith(BLOCKED_SUFFIXES) or h.startswith("addon_") or h.startswith("local-")


def check_target(host, payload=False):
    """Host must be a home-network IP, or a name whose EVERY address is one. Returns the checked IP (connect to
    that, never to the name again). payload=True also forbids this machine's own addresses."""
    host = str(host or "").strip().strip("[]")
    if not host:
        raise ToolError("no target given")
    try:
        ip = _norm_ip(host)
        literal = True
    except ValueError:
        literal = False
    if literal:
        if not ip_allowed(ip, payload):
            raise ToolError(f"{host} is not an allowed address; this gateway only touches devices on your own network")
        return str(ip)
    if not HOST_RE.match(host) or name_blocked(host):
        raise ToolError(f"{host} is not an allowed target")
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except Exception as e:
        raise ToolError(f"cannot resolve {host}: {e}")
    ips = sorted({str(_norm_ip(i[4][0])) for i in infos})
    bad = [i for i in ips if not ip_allowed(i, payload)]
    if not ips or bad:
        raise ToolError(f"{host} resolves to {', '.join(bad or ips) or 'nothing'}, which is not allowed")
    v4 = [i for i in ips if ":" not in i]
    return (v4 or ips)[0]


resolve_local = check_target   # old name


def local_nets():
    import receipt
    return receipt.local_nets()


def default_gateway():
    """IPv4 default gateway of this machine (usually the router), from the kernel routing table."""
    try:
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if len(f) > 3 and f[1] == "00000000" and int(f[3], 16) & 2:
                gw = socket.inet_ntoa(struct.pack("<L", int(f[2], 16)))
                if ip_allowed(gw):
                    return gw
    except Exception:
        pass
    return None


def default_net():
    nets = local_nets()
    for n in nets:
        if n.prefixlen >= 24:
            return n
    if nets:
        return nets[0]
    raise ToolError("could not work out your home network; give a network like 10.0.0.0/24")


_rate = {}
_rate_lock = threading.Lock()


def rate_check(tool):
    windows = LIMITS.get(tool, [(30, 60)])
    t = time.time()
    longest = max(per for _, per in windows)
    with _rate_lock:
        hits = [x for x in _rate.get(tool, []) if t - x < longest]
        for n, per in windows:
            recent = [x for x in hits if t - x < per]
            if len(recent) >= n:
                raise ToolError(f"rate limit: {tool} is capped at {n} per {per}s; try again in {int(per - (t - recent[0])) + 1}s")
        hits.append(t); _rate[tool] = hits


def parallel(fn, items, workers=48):
    out, lock, it = [], threading.Lock(), iter(list(items))
    def worker():
        while True:
            with lock:
                try:
                    x = next(it)
                except StopIteration:
                    return
            try:
                r = fn(x)
            except Exception:
                r = None
            if r is not None:
                with lock:
                    out.append(r)
    ths = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in ths: t.start()
    for t in ths: t.join()
    return out


def _num(v, default, lo, hi, cast=float):
    try:
        x = cast(v) if v not in (None, "") else default
    except (TypeError, ValueError):
        raise ToolError(f"bad number: {v!r}")
    return max(lo, min(hi, x))


# ---------------- read tools ----------------
def t_ping_sweep(a):
    try:
        net = ipaddress.ip_network(str(a.get("network") or default_net()), strict=False)
    except ValueError:
        raise ToolError("network must look like 10.0.0.0/24")
    if net.version != 4 or net.num_addresses > 1024 or not ip_allowed(net.network_address) or not ip_allowed(net.broadcast_address):
        raise ToolError("network must be an allowed private IPv4 range of /22 or smaller")
    have_ping = shutil.which("ping")
    def probe(ip):
        ip = str(ip)
        if have_ping and subprocess.run(["ping", "-c", "1", "-W", "1", "--", ip], capture_output=True).returncode == 0:
            return {"ip": ip, "via": "icmp"}
        for port in (80, 443, 22, 9100, 631, 8123, 53, 445):   # some hosts ignore ping
            try:
                with socket.create_connection((ip, port), timeout=0.5):
                    return {"ip": ip, "via": f"tcp/{port}"}
            except Exception:
                continue
        return None
    hosts = parallel(probe, [h for h in net.hosts() if ip_allowed(h)])
    arp = arp_table()
    for h in hosts:
        if h["ip"] in arp:
            h["mac"] = arp[h["ip"]]
        try:
            h["name"] = socket.gethostbyaddr(h["ip"])[0]
        except Exception:
            pass
    hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    return {"network": str(net), "found": len(hosts), "hosts": hosts}


def arp_table():
    out = {}
    try:
        for line in open("/proc/net/arp").read().splitlines()[1:]:
            f = line.split()
            if len(f) >= 4 and f[3] != "00:00:00:00:00:00":
                out[f[0]] = f[3]
    except Exception:
        pass
    return out


def _ports(spec):
    if spec in (None, "", []):
        return list(TOP_PORTS)
    got = []
    try:
        if isinstance(spec, str):
            for part in spec.split(","):
                part = part.strip()
                if "-" in part:
                    lo, hi = (int(x) for x in part.split("-", 1))
                    if hi - lo > 2000:
                        raise ToolError("port range too wide (max 200 ports per scan)")
                    got += list(range(lo, hi + 1))
                elif part:
                    got.append(int(part))
        elif isinstance(spec, list):
            got = [int(p) for p in spec[:400]]
        else:
            raise ToolError("ports must be a list or text like 22,80,8000-8100")
    except ValueError:
        raise ToolError("ports must be numbers")
    return [p for p in dict.fromkeys(got) if 1 <= p <= 65535][:200]


def t_port_scan(a):
    ip = check_target(a.get("host"))
    ports = _ports(a.get("ports"))
    timeout = _num(a.get("timeout"), 0.8, 0.2, 3)
    def probe(p):
        try:
            with socket.create_connection((ip, p), timeout=timeout) as s:
                banner = ""
                try:
                    s.settimeout(0.4)
                    banner = s.recv(80).decode(errors="replace").strip()
                except Exception:
                    pass
                return {"port": p, "banner": banner[:80]} if banner else {"port": p}
        except Exception:
            return None
        finally:
            time.sleep(0.01)          # politeness: never hammer a host
    open_ports = sorted(parallel(probe, ports, workers=24), key=lambda x: x["port"])
    return {"host": ip, "scanned": len(ports), "open": open_ports}


def _mcast_query(dest, port, payload, seconds, parse):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(0.5)
    try:
        s.sendto(payload, (dest, port))
        found, end = {}, time.time() + seconds
        while time.time() < end:
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                continue
            except Exception:
                break
            r = parse(data, addr)
            if r:
                found.setdefault(addr[0], r)
        return list(found.values())
    finally:
        s.close()


def _dns_name(buf, off, depth=0):
    parts = []
    while off < len(buf) and depth < 10:
        n = buf[off]
        if n == 0:
            off += 1; break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", buf[off:off + 2])[0] & 0x3FFF
            sub, _ = _dns_name(buf, ptr, depth + 1)
            parts.append(sub); off += 2; break
        parts.append(buf[off + 1:off + 1 + n].decode(errors="replace")); off += 1 + n
    return ".".join(p for p in parts if p), off


def t_mdns(a):
    service = str(a.get("service") or "_services._dns-sd._udp.local")
    q = bytearray(struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0))
    for lbl in service.split("."):
        if lbl:
            q += bytes([len(lbl)]) + lbl.encode()
    q += b"\x00" + struct.pack(">HH", 12, 1)   # PTR, IN
    def parse(data, addr):
        try:
            qd, an = struct.unpack(">HH", data[4:8])
            off = 12
            for _ in range(qd):
                _, off = _dns_name(data, off); off += 4
            names = []
            for _ in range(an + 4):
                if off >= len(data):
                    break
                _, off = _dns_name(data, off)
                if off + 10 > len(data):
                    break
                typ, _cls, _ttl, dl = struct.unpack(">HHIH", data[off:off + 10]); off += 10
                if typ == 12:
                    nm, _ = _dns_name(data, off); names.append(nm)
                off += dl
            return {"ip": addr[0], "names": sorted(set(n for n in names if n))[:12]} if names else {"ip": addr[0]}
        except Exception:
            return {"ip": addr[0]}
    res = _mcast_query("224.0.0.251", 5353, bytes(q), min(float(a.get("seconds") or 4), 10), parse)
    return {"service": service, "found": len(res), "responders": res}


def t_ssdp(a):
    st = str(a.get("search") or "ssdp:all")
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           f"ST: {st}\r\n\r\n").encode()
    def parse(data, addr):
        h = {}
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            if ":" in line:
                k, v = line.split(":", 1); h[k.strip().upper()] = v.strip()
        return {"ip": addr[0], "server": h.get("SERVER", ""), "st": h.get("ST", ""), "location": h.get("LOCATION", "")}
    res = _mcast_query("239.255.255.250", 1900, msg, min(float(a.get("seconds") or 4), 10), parse)
    return {"found": len(res), "devices": res}


class _PinnedHTTP(http.client.HTTPConnection):
    """HTTP connection to an already-checked IP, sending the original name in the Host header."""
    def __init__(self, host, ip, port, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, ip, port, timeout, context):
        super().__init__(host, port, timeout=timeout, context=context)
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        sni = None
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            sni = self.host
        self.sock = self._context.wrap_socket(sock, server_hostname=sni)


HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,60}$")
SENSITIVE_RESPONSE_HEADER = re.compile(r"^(set-cookie2?|cookie|authorization|proxy-authorization|www-authenticate|"
                                       r"proxy-authenticate|authentication-info|x-(auth|api|csrf|xsrf|access|session|amz-security)[\w-]*|"
                                       r"x-[\w-]*(token|secret|key|session)[\w-]*)$", re.I)


def clean_headers(items):
    """Response headers without session cookies, auth challenges and token-carrying headers."""
    out = {}
    for k, v in list(items)[:40]:
        if SENSITIVE_RESPONSE_HEADER.match(str(k)):
            continue
        out[k] = redact(str(v))[:400]
        if len(out) >= 25:
            break
    return out
FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection", "upgrade", "proxy-authorization"}


def _http(a, method, payload=True):
    url = str(a.get("url") or "")
    u = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
    if u.scheme not in ("http", "https"):
        raise ToolError("url must be http or https")
    if not u.hostname:
        raise ToolError("url has no host")
    if u.username or u.password:
        raise ToolError("put credentials in username/password, not in the url")
    ip = check_target(u.hostname, payload=payload)
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise ToolError("bad port in url")
    data = a.get("body")
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
    elif isinstance(data, str):
        data = data.encode()
    elif data is not None:
        raise ToolError("body must be text or JSON")
    if data and len(data) > 64000:
        raise ToolError("body too large (64 KB max)")
    headers = {"User-Agent": "hark-gateway/1.2", "Accept": "*/*"}
    for k, v in (a.get("headers") or {}).items():
        k, v = str(k), str(v)
        if not HEADER_NAME.match(k) or k.lower() in FORBIDDEN_HEADERS or "\r" in v or "\n" in v:
            raise ToolError(f"header {k[:40]!r} is not allowed")
        headers[k] = v[:400]
    if data and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"
    if a.get("username"):
        headers["Authorization"] = "Basic " + base64.b64encode(f"{a['username']}:{a.get('password', '')}".encode()).decode()
    timeout = _num(a.get("timeout"), 15, 1, 30)
    max_bytes = int(_num(a.get("max_bytes"), 60000, 1, 200000))
    if u.scheme == "https":
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE  # home gear = self-signed
        conn = _PinnedHTTPS(u.hostname, ip, port, timeout, ctx)
    else:
        conn = _PinnedHTTP(u.hostname, ip, port, timeout)
    path = (u.path or "/") + ("?" + u.query if u.query else "")
    t0 = time.time()
    try:
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        body = r.read(max_bytes)
        hdrs = clean_headers(r.getheaders())
        out = {"url": scrub_url(u.geturl()), "ip": ip, "method": method, "status": r.status,
               "ms": int((time.time() - t0) * 1000), "headers": hdrs, "body": body.decode(errors="replace")}
        if 300 <= r.status < 400 and r.getheader("Location"):
            out["redirect_not_followed"] = r.getheader("Location")[:300]
        return out
    except (OSError, http.client.HTTPException) as e:
        raise ToolError(f"{method} {scrub_url(u.geturl())} failed: {e}")
    finally:
        conn.close()


def t_http(a):
    method = str(a.get("method") or "GET").upper()
    if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
        raise ToolError("unsupported HTTP method")
    return _http(a, method)


PRINTER_RAW_PORTS = {9100, 9101, 9102, 9103, 515}  # raw/LPD printing: any bytes become printed pages


def t_probe(a):
    payload = str(a.get("payload") or "")[:2000]
    ip = check_target(a.get("host"), payload=bool(payload) or str(a.get("proto") or "tcp").lower() == "udp")
    port = int(_num(a.get("port"), 0, 0, 65535, int))
    if not port:
        raise ToolError("port required (1-65535)")
    proto = str(a.get("proto") or "tcp").lower()
    if proto not in ("tcp", "udp"):
        raise ToolError("proto must be tcp or udp")
    if payload and port in PRINTER_RAW_PORTS:
        raise ToolError(f"refused: port {port} is a raw printer port; anything sent there prints. Use print_doc instead")
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    t0 = time.time()
    if proto == "tcp":
        try:
            with socket.create_connection((ip, port), timeout=_num(a.get("timeout"), 5, 0.5, 15)) as s:
                ms = int((time.time() - t0) * 1000)
                if payload:
                    s.sendall(payload.encode())
                s.settimeout(2)
                try:
                    data = s.recv(2000)
                except Exception:
                    data = b""
                return {"host": ip, "port": port, "proto": "tcp", "open": True, "ms": ms,
                        "response": data.decode(errors="replace")[:1000]}
        except Exception as e:
            return {"host": ip, "port": port, "proto": "tcp", "open": False, "error": str(e)}
    s = socket.socket(fam, socket.SOCK_DGRAM); s.settimeout(_num(a.get("timeout"), 3, 0.5, 10))
    try:
        s.sendto(payload.encode() or b"\x00", (ip, port))
        data, _ = s.recvfrom(2000)
        return {"host": ip, "port": port, "proto": "udp", "answered": True, "ms": int((time.time() - t0) * 1000),
                "response": data.decode(errors="replace")[:1000]}
    except socket.timeout:
        return {"host": ip, "port": port, "proto": "udp", "answered": False, "note": "no answer (normal for many UDP services)"}
    finally:
        s.close()


def dns_server(server):
    """The resolver the dns tool may ask: a device on your network (not this machine), or a well-known public resolver."""
    if not server:
        return default_gateway() or "1.1.1.1"
    server = str(server).strip()
    if server in PUBLIC_DNS:
        return server
    try:
        ip = str(_norm_ip(server))
    except ValueError:
        raise ToolError("server must be an IP address")
    if not ip_allowed(ip, payload=True):
        raise ToolError(f"server must be a device on your network or one of {', '.join(sorted(PUBLIC_DNS))}")
    return ip


def t_dns(a):
    name = str(a.get("name") or "").strip()
    if not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})(?:\.[A-Za-z0-9_-]{1,63})*\.?", name):
        raise ToolError("name must be a host name")
    rtype = str(a.get("type") or "A").upper()
    types = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28, "SRV": 33}
    if rtype not in types:
        raise ToolError("type must be one of " + ", ".join(types))
    server = dns_server(a.get("server"))
    q = bytearray(struct.pack(">HHHHHH", int.from_bytes(os.urandom(2), "big"), 0x0100, 1, 0, 0, 0))
    for lbl in name.strip(".").split("."):
        q += bytes([len(lbl)]) + lbl.encode()
    q += b"\x00" + struct.pack(">HH", types[rtype], 1)
    s = socket.socket(socket.AF_INET6 if ":" in server else socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
    t0 = time.time()
    try:
        s.sendto(bytes(q), (server, 53))
        data, _ = s.recvfrom(4096)
    except Exception as e:
        raise ToolError(f"no answer from {server}: {e}")
    finally:
        s.close()
    try:
        qd, an = struct.unpack(">HH", data[4:8])
        off = 12
        for _ in range(qd):
            _, off = _dns_name(data, off); off += 4
        answers = []
        for _ in range(min(an, 50)):
            nm, off = _dns_name(data, off)
            typ, _c, ttl, dl = struct.unpack(">HHIH", data[off:off + 10]); off += 10
            raw = data[off:off + dl]; off += dl
            if typ == 1 and dl == 4:
                val = ".".join(str(b) for b in raw)
            elif typ == 28 and dl == 16:
                val = ":".join(f"{raw[i]:02x}{raw[i+1]:02x}" for i in range(0, 16, 2))
            elif typ in (2, 5, 12):
                val, _ = _dns_name(data, off - dl)
            elif typ == 16:
                val = raw[1:].decode(errors="replace")
            elif typ == 15:
                val, _ = _dns_name(data, off - dl + 2)
            else:
                val = raw.hex()
            answers.append({"name": nm, "type": {v: k for k, v in types.items()}.get(typ, typ), "ttl": ttl, "value": val})
    except (struct.error, IndexError):
        raise ToolError(f"unreadable answer from {server}")
    return {"name": name, "type": rtype, "server": server, "ms": int((time.time() - t0) * 1000),
            "rcode": data[3] & 0x0F, "answers": answers}


# ---- SNMP v2c (minimal BER) ----
def _ber_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _tlv(tag, body):
    return bytes([tag]) + _ber_len(len(body)) + body


def _int(n):
    b = n.to_bytes(max((n.bit_length() + 8) // 8, 1), "big", signed=True) if n else b"\x00"
    return _tlv(0x02, b)


def _oid(oid):
    p = [int(x) for x in str(oid).strip(". ").split(".")]
    body = bytes([p[0] * 40 + p[1]])
    for v in p[2:]:
        chunk = bytearray([v & 0x7F]); v >>= 7
        while v:
            chunk.insert(0, (v & 0x7F) | 0x80); v >>= 7
        body += bytes(chunk)
    return _tlv(0x06, body)


def _parse(buf, i=0):
    tag = buf[i]; i += 1
    n = buf[i]; i += 1
    if n & 0x80:
        k = n & 0x7F; n = int.from_bytes(buf[i:i + k], "big"); i += k
    return tag, buf[i:i + n], i + n


def _dec_oid(b):
    out = [str(b[0] // 40), str(b[0] % 40)]
    v = 0
    for x in b[1:]:
        v = (v << 7) | (x & 0x7F)
        if not x & 0x80:
            out.append(str(v)); v = 0
    return ".".join(out)


def _dec_val(tag, b):
    if tag == 0x02 or tag in (0x41, 0x42, 0x43, 0x46):
        return int.from_bytes(b, "big")
    if tag == 0x04:
        try:
            s = b.decode()
            return s if s.isprintable() else b.hex()
        except Exception:
            return b.hex()
    if tag == 0x06:
        return _dec_oid(b)
    if tag == 0x05:
        return None
    if tag == 0x40 and len(b) == 4:
        return ".".join(str(x) for x in b)
    if tag in (0x80, 0x81, 0x82):
        return "(no such object)"
    return b.hex()


def _snmp_pdu(community, pdu_tag, oid, reqid):
    varbind = _tlv(0x30, _oid(oid) + _tlv(0x05, b""))
    pdu = _tlv(pdu_tag, _int(reqid) + _int(0) + _int(0) + _tlv(0x30, varbind))
    return _tlv(0x30, _int(1) + _tlv(0x04, community.encode()) + pdu)


def _snmp_once(ip, community, oid, pdu_tag, timeout, port=161):
    reqid = int(time.time() * 1000) % 2147483647
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        s.sendto(_snmp_pdu(community, pdu_tag, oid, reqid), (ip, port))
        data, _ = s.recvfrom(8000)
    except socket.timeout:
        raise ToolError(f"no SNMP answer from {ip} (SNMP off, or wrong community string)")
    finally:
        s.close()
    _, msg, _ = _parse(data)
    _, _, i = _parse(msg)                 # version
    _, _, i = _parse(msg, i)              # community
    _, pdu, _ = _parse(msg, i)
    _, _, j = _parse(pdu)                 # request id
    _, errb, j = _parse(pdu, j)           # error status
    err = int.from_bytes(errb, "big") if errb else 0
    _, _, j = _parse(pdu, j)              # error index
    _, vbl, _ = _parse(pdu, j)
    _, vb, _ = _parse(vbl)
    _, oidb, k = _parse(vb)
    tag, valb, _ = _parse(vb, k)
    return err, _dec_oid(oidb), _dec_val(tag, valb)


def t_snmp(a):
    ip = check_target(a.get("host"), payload=True)
    community = str(a.get("community") or "public")[:40]
    oid = str(a.get("oid") or "1.3.6.1.2.1.1").strip()
    if not re.fullmatch(r"\.?[0-9]+(\.[0-9]+){1,60}", oid):
        raise ToolError("oid must look like 1.3.6.1.2.1.1")
    timeout = _num(a.get("timeout"), 4, 0.5, 10)
    op = str(a.get("op") or "get").lower()
    if op not in ("get", "walk"):
        raise ToolError("op must be get or walk")
    if op == "get":
        err, roid, val = _snmp_once(ip, community, oid, 0xA0, timeout)
        if err:
            raise ToolError(f"SNMP error {err} (often: no such OID, or wrong community string)")
        return {"host": ip, "op": "get", "results": [{"oid": roid, "value": val}]}
    out, cur, root = [], oid, oid.strip(".")
    for _ in range(int(_num(a.get("max"), 40, 1, 100, int))):
        err, roid, val = _snmp_once(ip, community, cur, 0xA1, timeout)
        if err or not roid.startswith(root) or roid == cur:
            break
        out.append({"oid": roid, "value": val}); cur = roid
    return {"host": ip, "op": "walk", "results": out, "count": len(out)}


def t_latency(a):
    host = a.get("host") or default_gateway()
    if not host:
        raise ToolError("host required")
    ip = check_target(host)
    count = int(_num(a.get("count"), 5, 1, 20, int))
    port = a.get("port")
    out = []
    if port:
        port = int(_num(port, 0, 1, 65535, int))
        for _ in range(count):
            t0 = time.time()
            try:
                with socket.create_connection((ip, port), timeout=3):
                    out.append(round((time.time() - t0) * 1000, 1))
            except Exception:
                out.append(None)
            time.sleep(0.15)
        mode = f"tcp/{port}"
    else:
        r = subprocess.run(["ping", "-c", str(count), "-W", "2", "--", ip], capture_output=True, text=True, timeout=60)
        out = [float(x) for x in re.findall(r"time=([\d.]+) ms", r.stdout)]
        mode = "icmp"
    got = [x for x in out if x is not None]
    return {"host": ip, "mode": mode, "samples": out, "loss_pct": round(100 * (count - len(got)) / count, 1),
            "min_ms": min(got) if got else None, "avg_ms": round(sum(got) / len(got), 1) if got else None,
            "max_ms": max(got) if got else None}


def t_speedtest(a):
    """Rough download speed over the internet, always from the same fixed public test endpoint (no other URLs)."""
    mb = _num(a.get("max_mb"), 25, 1, 100)
    url = SPEEDTEST_URL.format(n=int(mb * 1000000))
    t0, got = time.time(), 0
    conn = http.client.HTTPSConnection(urllib.parse.urlsplit(url).hostname, 443, timeout=60,
                                       context=ssl.create_default_context())
    try:
        conn.request("GET", url.split("cloudflare.com", 1)[1], headers={"User-Agent": "hark-gateway/1.2"})
        r = conn.getresponse()
        if r.status != 200:
            raise ToolError(f"speed test server answered HTTP {r.status}")
        while got < mb * 1000000 and time.time() - t0 < 30:
            chunk = r.read(262144)
            if not chunk:
                break
            got += len(chunk)
    finally:
        conn.close()
    secs = max(time.time() - t0, 0.001)
    return {"server": "speed.cloudflare.com", "downloaded_mb": round(got / 1e6, 2), "seconds": round(secs, 2),
            "mbps": round(got * 8 / secs / 1e6, 1)}


ENTITY_RE = re.compile(r"^[a-z0-9_]{1,64}\.[a-z0-9_]{1,128}$")
PRIVATE_ENTITIES = ("sensor.hark_gateway_pairing", "sensor.hark_gateway_result_")


def t_ha_states(a):
    ent = a.get("entity_id")
    if ent:
        ent = str(ent).strip()
        if not ENTITY_RE.match(ent):
            raise ToolError("entity_id must look like light.living_room")
        if ent.startswith(PRIVATE_ENTITIES):
            raise ToolError("that entity belongs to the gateway itself")
        return redact(haapi.ha("GET", "/states/" + ent))
    pat = str(a.get("match") or "").lower()[:80]
    data = haapi.ha("GET", "/states", timeout=30)
    rows = [{"entity_id": s["entity_id"], "state": redact(s.get("state")),
             "name": s.get("attributes", {}).get("friendly_name")} for s in data
            if not s["entity_id"].startswith(PRIVATE_ENTITIES)
            and (not pat or pat in s["entity_id"].lower() or pat in str(s.get("attributes", {}).get("friendly_name", "")).lower())]
    return {"count": len(rows), "states": rows[:int(_num(a.get("limit"), 200, 1, 1000, int))]}


def t_audit(a):
    return {"entries": haapi.read_audit(int(_num(a.get("limit"), 25, 1, 200, int)))}


# ---- firewall / router REST API (OPNsense-style: key + secret as HTTP Basic, JSON at https://<host>/api/<path>) ----
def firewall_host(opts):
    """The one host the firewall tool may talk to: the opnsense_host option, else this network's default gateway."""
    return str(opts.get("opnsense_host") or "").strip() or default_gateway()


def firewall_call(opts, a, method):
    key, sec = opts.get("opnsense_key"), opts.get("opnsense_secret")
    host = firewall_host(opts)
    if not key or not sec:
        raise ToolError("the firewall tool is off: set opnsense_key and opnsense_secret in the app options")
    if not host:
        raise ToolError("no firewall address: set opnsense_host (the default gateway could not be found)")
    ip = check_target(host, payload=True)           # only ever the one configured (or default-gateway) host
    path = str(a.get("path") or "").strip().lstrip("/")
    if path.startswith("api/"):
        path = path[4:]
    if not re.fullmatch(r"[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-.]+){1,10}", path) or ".." in path:
        raise ToolError("path must look like core/firmware/status")
    hostpart = f"[{ip}]" if ":" in ip else ip
    return _http({"url": f"https://{hostpart}/api/{path}", "username": key, "password": sec, "body": a.get("body"),
                  "timeout": a.get("timeout") or 20, "headers": {"Accept": "application/json"}}, method)


def t_firewall(a, opts):
    method = str(a.get("method") or "GET").upper()
    if method not in ("GET", "POST"):
        raise ToolError("the firewall API takes GET (read) or POST (change)")
    r = firewall_call(opts, a, method)
    try:
        r["json"] = redact(json.loads(r.pop("body")))
    except Exception:
        pass
    return r


# ---------------- change tools ----------------
def t_wol(a):
    mac = re.sub(r"[^0-9a-fA-F]", "", str(a.get("mac") or ""))
    if len(mac) != 12:
        raise ToolError("mac must be 12 hex digits, e.g. a4:bb:6d:11:22:33")
    pkt = b"\xff" * 6 + bytes.fromhex(mac) * 16
    bcast = str(a.get("broadcast") or "255.255.255.255")
    allowed = {"255.255.255.255"} | {str(n.broadcast_address) for n in local_nets()}
    if bcast not in allowed:
        raise ToolError("broadcast must be 255.255.255.255 or your network's broadcast address")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        for port in (9, 7):
            s.sendto(pkt, (bcast, port))
    finally:
        s.close()
    return {"mac": ":".join(mac[i:i + 2] for i in range(0, 12, 2)), "sent_to": bcast, "ports": [9, 7]}


def ssh_pubkey(create=True):
    d = os.path.dirname(SSH_KEY)
    os.makedirs(d, mode=0o700, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except Exception:
        pass
    if not os.path.exists(SSH_KEY + ".pub"):
        if not create:
            return None
        if not shutil.which("ssh-keygen"):
            return None
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "hark-ha-gateway", "-f", SSH_KEY],
                       check=True, capture_output=True, timeout=30)
    try:
        os.chmod(SSH_KEY, 0o600)
    except Exception:
        pass
    return open(SSH_KEY + ".pub").read().strip()


def t_ssh_pubkey(a):
    key = ssh_pubkey()
    if not key:
        raise ToolError("no ssh key: openssh-client is missing from the app image")
    return {"public_key": key,
            "how_to_install": "Add this one line to ~/.ssh/authorized_keys on the machine you want Hark to reach."}


def ssh_args(host, user, port, cmd):
    kh = os.path.join(os.path.dirname(SSH_KEY), "known_hosts")
    return ["ssh", "-F", "/dev/null", "-i", SSH_KEY, "-p", str(port), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=accept-new", "-o", "UserKnownHostsFile=" + kh, "-o", "ConnectTimeout=10",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "PermitLocalCommand=no",
            "-o", "UpdateHostKeys=no", "-l", user, "--", host, cmd]


def t_ssh(a):
    if not shutil.which("ssh"):
        raise ToolError("ssh is missing from the app image")
    host = check_target(a.get("host"), payload=True)
    user = str(a.get("user") or "root")
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user):
        raise ToolError("bad username")
    cmd = str(a.get("command") or "").strip()
    if not cmd or len(cmd) > 4000 or "\x00" in cmd:
        raise ToolError("command required (4000 characters max)")
    port = int(_num(a.get("port"), 22, 1, 65535, int))
    ssh_pubkey()
    r = subprocess.run(ssh_args(host, user, port, cmd), capture_output=True, text=True,
                       timeout=int(_num(a.get("timeout"), 60, 5, 120, int)))
    return {"host": host, "user": user, "command": cmd[:300], "exit_code": r.returncode,
            "host_key_note": "first connection to a machine remembers its key; a changed key is refused",
            "stdout": r.stdout[-8000:], "stderr": r.stderr[-4000:]}


def ha_service_check(domain, service, data, a):
    """Raises ToolError for Home Assistant calls the gateway must never make, or may make only when the approved
    command explicitly says dangerous_ok."""
    if domain in HA_DENY_DOMAINS:
        raise ToolError(f"{domain}.* calls are never allowed through the gateway")
    blob = json.dumps(data, sort_keys=True).lower() + " " + json.dumps(a.get("entity_id") or "").lower()
    if haapi.KILL_ENTITY in blob or "hark_gateway" in blob:
        raise ToolError("the gateway may not change its own kill switch or entities")
    if domain in HA_DANGEROUS_DOMAINS and a.get("dangerous_ok") is not True:
        raise ToolError(f"{domain}.{service} is on the dangerous list; it needs \"dangerous_ok\": true in the approved command")


def t_ha_service(a):
    domain = str(a.get("domain") or "").strip()
    service = str(a.get("service") or "").strip()
    if not re.fullmatch(r"[a-z0-9_]{2,40}", domain) or not re.fullmatch(r"[a-z0-9_]{2,40}", service):
        raise ToolError("domain and service required, e.g. light / turn_on")
    data = a.get("data") or {}
    if not isinstance(data, dict):
        raise ToolError("data must be an object")
    if a.get("entity_id"):
        data = {**data, "entity_id": a["entity_id"]}
    ha_service_check(domain, service, data, a)
    out = haapi.ha("POST", f"/services/{domain}/{service}", data, timeout=30)
    return {"service": f"{domain}.{service}", "data": redact(data), "result": redact(out)}


def _doc_printer(a):
    """What the document printer takes. {"printer_formats": true} asks the printer again over IPP right now."""
    import docs
    d = {k: docs.STATE.get(k) for k in ("ip", "path", "model", "formats", "send_as", "last_method", "printed", "err")}
    d["today"] = docs.counts_today()
    if (a or {}).get("printer_formats"):
        ip = (a or {}).get("host") or d["ip"]
        if not ip:
            d["live"] = {"error": "no document printer found yet"}
            return d
        ip = check_target(ip, payload=True)
        try:
            p, at = docs.printer_info(ip)
            d["live"] = {"ip": ip, "path": p, "model": ((at or {}).get("printer-make-and-model") or [None])[0],
                         "document-format-supported": (at or {}).get("document-format-supported", []),
                         "document-format-default": (at or {}).get("document-format-default", []),
                         "send_as": docs.send_format((at or {}).get("document-format-supported", [])) or "raw 9100 (PJL PDF)"}
        except Exception as e:
            d["live"] = {"ip": ip, "error": f"{type(e).__name__}: {e}"}
    return d


def t_status(a, ctx):
    st = ctx["state"]
    ev = ctx.get("events")
    o = ctx["opts"]
    return {"version": ctx["version"], "enabled": ctx["kill"].enabled(force=True), "kill_switch": ctx["kill"].state,
            "listening_for_hark": bool(ev and ev.connected), "ha_reconnects": ev.reconnects if ev else None,
            "kill_switch_entity": haapi.KILL_ENTITY, "tools_enabled": sorted(ctx["enabled_tools"]),
            "networks": [str(n) for n in local_nets()],
            "provisioned": ctx.get("provisioned", lambda: {})(),
            "receipt_printer": {"ip": st.get("receipt_ip"), "model": st.get("receipt_model")},
            "doc_printer": _doc_printer(a),
            "firewall_configured": bool(o.get("opnsense_key") and o.get("opnsense_secret")),
            "ssh_key": bool(shutil.which("ssh-keygen")), "time": time.strftime("%Y-%m-%dT%H:%M:%S%z")}


def _cfg(fn, a):
    """Home Assistant configuration tools (hacfg.py); their refusals become ToolError like every other tool."""
    import hacfg
    try:
        return getattr(hacfg, fn)(a)
    except hacfg.CfgError as e:
        raise ToolError(str(e))


DISPATCH = {
    "ping_sweep": lambda a, c: t_ping_sweep(a), "port_scan": lambda a, c: t_port_scan(a),
    "mdns": lambda a, c: t_mdns(a), "ssdp": lambda a, c: t_ssdp(a), "http": lambda a, c: t_http(a),
    "probe": lambda a, c: t_probe(a), "dns": lambda a, c: t_dns(a), "snmp": lambda a, c: t_snmp(a),
    "latency": lambda a, c: t_latency(a), "speedtest": lambda a, c: t_speedtest(a),
    "ha_states": lambda a, c: t_ha_states(a), "audit": lambda a, c: t_audit(a),
    "ssh_pubkey": lambda a, c: t_ssh_pubkey(a), "firewall": lambda a, c: t_firewall(a, c["opts"]),
    "opnsense": lambda a, c: t_firewall(a, c["opts"]),   # older name of the same tool
    "wol": lambda a, c: t_wol(a), "ssh": lambda a, c: t_ssh(a), "ha_service": lambda a, c: t_ha_service(a),
    "status": lambda a, c: t_status(a, c),
    "stage": lambda a, c: _cfg("t_stage", a), "ha_file_read": lambda a, c: _cfg("t_file_read", a),
    "lovelace_get": lambda a, c: _cfg("t_lovelace_get", a), "ha_check_config": lambda a, c: _cfg("t_check_config", a),
    "ha_file_write": lambda a, c: _cfg("t_file_write", a), "lovelace_save": lambda a, c: _cfg("t_lovelace_save", a),
    "print_doc": lambda a, c: c["wake_docs"](a),   # Hark's nudge: check the document queue now (job stays on the Worker)
}


def tier_of(tool, args):
    if tool in CHANGE_TOOLS:
        return "change"
    m = str((args or {}).get("method") or "GET").upper()
    if tool == "http" and m not in ("GET", "HEAD"):
        return "change"
    if tool in ("firewall", "opnsense") and m != "GET":
        return "change"
    return "read"


def run(tool, args, ctx):
    """Runs one tool. Raises ToolError for anything refused. ctx carries opts, state, kill switch, enabled tools."""
    if tool not in DISPATCH:
        raise ToolError(f"unknown tool {tool}")
    if tool not in ctx["enabled_tools"]:
        raise ToolError(f"the {tool} tool is switched off in the app options")
    if not isinstance(args, dict):
        raise ToolError("args must be a JSON object")
    rate_check(tool)
    return DISPATCH[tool](args, ctx)

"""A short, polite look at a device the first time it shows up, so the alert can say what it probably is (2.0.5).

Stdlib only. Read-only. Bounded: every check has its own short timeout and the whole look ends after DEADLINE_S
seconds (about 6) even if something is slow. It only talks to the new device itself:

  - Maker: the first half of the hardware (MAC) address, looked up OFFLINE in oui.txt.gz (the public IEEE list,
    bundled with the app; refresh with oui_refresh.py). A maker name your router already gives (e.g. OPNsense Kea
    "mac_info") wins. Contract makers (Foxconn and friends) and chip makers (Espressif, Intel...) get a plain hint.
  - Private address: the "locally administered" bit means a phone/laptop is hiding its real address.
  - Names: the DHCP name from your router, reverse DNS (your router's DNS), the device's own mDNS name (one unicast
    question to its port 5353), its Windows/NetBIOS name (one "node status" question to UDP 137) and its UPnP name
    (one unicast SSDP search to UDP 1900, then one HTTP GET of the description file it points to, on that same
    device only, no redirects, 64 KB max).
  - Services: a TCP connect (no data sent) to a small list of common ports, and the mDNS service types it announces
    (AirPlay, Chromecast, printer, HomeKit...). Raw printer ports (9100-9103, 515) are never touched.
Nothing here logs in, sends a password, or changes anything.
"""
import gzip, html, http.client, ipaddress, os, random, re, shutil, socket, struct, subprocess, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
OUI_FILE = os.environ.get("OUI_FILE", os.path.join(HERE, "oui.txt.gz"))
DEADLINE_S = 6.0
PRINTER_RAW_PORTS = {9100, 9101, 9102, 9103, 515}
MDNS_PORT, NETBIOS_PORT, SSDP_PORT = 5353, 137, 1900   # fixed by the protocols (overridable only in tests)
# TCP connect only. Chosen because each one says something about what a device is.
PORTS = {22: "remote login (SSH)", 23: "old remote login (Telnet)", 53: "DNS", 80: "a web page", 139: "Windows file sharing",
         443: "a secure web page", 445: "Windows file sharing", 548: "Mac file sharing", 554: "a video stream (RTSP)",
         631: "printing (IPP)", 1883: "smart-home messages (MQTT)", 3389: "Windows remote desktop", 5000: "a web app or NAS",
         6053: "ESPHome", 6668: "Tuya smart-home control", 7000: "AirPlay", 8008: "Chromecast", 8009: "Chromecast",
         8080: "a web page", 8123: "Home Assistant", 8443: "a secure web page", 32400: "Plex media server",
         49152: "UPnP", 62078: "Apple iPhone/iPad sync"}
assert not PRINTER_RAW_PORTS & set(PORTS)

_oui, _oui_lock = None, threading.Lock()


# ---------------- maker ----------------
def oui_table():
    global _oui
    with _oui_lock:
        if _oui is None:
            t = {}
            try:
                with gzip.open(OUI_FILE, "rt", encoding="utf-8") as f:
                    for line in f:
                        k, _, v = line.rstrip("\n").partition("\t")
                        if len(k) == 6 and v:
                            t[k] = v
            except Exception as e:
                print("investigate: maker table unavailable", e)
            _oui = t
        return _oui


def is_private_mac(mac):
    """Locally administered bit set: a randomized ('private') address that hides the real maker."""
    try:
        return bool(int(str(mac).split(":")[0], 16) & 0x02)
    except Exception:
        return False


# (pattern on the maker name, short name, plain hint, guess, confidence 1 low .. 3 high)
MAKERS = [
    (r"cloud network technology|hon hai|foxconn|fih \(", "Foxconn",
     "a contract maker that builds laptops, game consoles, smart speakers and TVs for many brands",
     "a laptop, game console, smart TV or smart speaker", 1),
    (r"espressif", "Espressif", "maker of the ESP Wi-Fi chip inside many smart-home gadgets",
     "a smart-home gadget (plug, bulb, sensor or similar) built on an ESP chip", 2),
    (r"^apple", "Apple", "iPhone, iPad, Mac, Apple TV, HomePod, Apple Watch", "an Apple device", 2),
    (r"amazon technologies|^amazon", "Amazon", "Echo, Fire TV, Kindle, Ring, Blink",
     "an Amazon device (Echo, Fire TV, Kindle or similar)", 2),
    (r"^google|nest labs", "Google", "Pixel phones, Nest speakers and thermostats, Chromecast",
     "a Google or Nest device, or a Pixel phone", 2),
    (r"samsung", "Samsung", "phones, tablets, TVs and appliances", "a Samsung phone, tablet, TV or appliance", 1),
    (r"^roku", "Roku", "streaming players and Roku TVs", "a Roku streaming player or Roku TV", 3),
    (r"^sonos", "Sonos", "speakers", "a Sonos speaker", 3),
    (r"^ring llc|^ring ", "Ring", "doorbells and cameras", "a Ring doorbell or camera", 3),
    (r"wyze", "Wyze", "cameras and smart-home gadgets", "a Wyze camera or smart-home gadget", 3),
    (r"nintendo", "Nintendo", "game consoles", "a Nintendo game console", 3),
    (r"sony interactive", "Sony", "PlayStation", "a PlayStation", 3),
    (r"^sony", "Sony", "TVs, PlayStation, phones, cameras", "a Sony TV, PlayStation or phone", 1),
    (r"^microsoft", "Microsoft", "Xbox, Surface", "an Xbox or a Surface computer", 2),
    (r"raspberry pi", "Raspberry Pi", "small hobby computers", "a Raspberry Pi mini-computer", 3),
    (r"^intel", "Intel", "Wi-Fi chips inside many laptops and PCs", "a laptop or desktop computer", 2),
    (r"realtek|lite-?on|azurewave|murata|universal global scientific|chongqing fugui|qualcomm|mediatek|broadcom|"
     r"rivet networks|hui zhou gaoshengda|ampak|silicon labs|texas instruments|marvell",
     None, "a maker of network chips used in many laptops, TVs and gadgets", "a laptop, TV or other gadget", 1),
    (r"wistron|quanta|compal|pegatron|inventec|arcadyan|askey|sercomm|gemtek|liteon", None,
     "a contract maker that builds computers and network gear for other brands", "a laptop or a piece of network equipment", 1),
    (r"tuya|ai-thinker|beken|shenzhen bilian|hangzhou hikvision|ogemray|shelly|allterco", None,
     "a maker of smart-home parts", "a smart-home gadget (plug, bulb, camera or sensor)", 2),
    (r"canon|xerox|lexmark|kyocera|ricoh|konica|sharp corp", None, "printers and scanners", "a printer", 2),
    (r"hewlett|^hp inc", "HP", "printers and computers", "an HP printer or computer", 1),
    (r"signify|philips lighting", "Philips Hue", "smart lights", "a Philips Hue bridge or light", 3),
    (r"ecobee", "ecobee", "thermostats", "an ecobee thermostat or sensor", 3),
    (r"^lg electronics|lg innotek", "LG", "TVs, appliances, phones", "an LG TV or appliance", 1),
    (r"vizio|hisense|^tcl|funai|universal electronics", None, "TVs and remotes", "a smart TV", 2),
    (r"ubiquiti|netgear|d-link|arris|^eero|cisco|juniper|mikrotik|zyxel|ruckus|aruba|commscope|technicolor|sagemcom",
     None, "network equipment", "a router, Wi-Fi access point or network switch", 2),
    (r"asustek", "ASUS", "laptops, routers and PC parts", "an ASUS laptop, PC or router", 1),
    (r"synology|qnap|western digital", None, "network storage", "a network storage box (NAS)", 3),
    (r"^dell|lenovo|^acer|micro-star|gigabyte|elitegroup|framework", None, "computers", "a laptop or desktop computer", 2),
    (r"xiaomi|oneplus|motorola|huawei|guangdong oppo|vivo mobile|^zte|honor device|nothing technology", None,
     "phones and gadgets", "a phone or tablet", 2),
    (r"garmin|fitbit", None, "watches and fitness trackers", "a smartwatch or fitness tracker", 2),
    (r"^private$", None, "a maker who keeps its name private", None, 0),
    (r"icann, iana", None, "example and test addresses (not a real maker)", None, 0),
]


def maker_info(mac, router_vendor=None):
    """{name, source, short, hint, guess, conf} or {} when unknown."""
    name, source = None, None
    rv = str(router_vendor or "").strip()
    if rv and rv.lower() not in ("unknown", "none", "n/a", "-"):
        name, source = rv[:80], "router"
    elif not is_private_mac(mac):
        name = oui_table().get(re.sub(r"[^0-9a-f]", "", str(mac).lower())[:6].upper())
        source = "IEEE list" if name else None
    if not name:
        return {}
    out = {"name": name, "source": source}
    low = name.lower()
    for pat, short, hint, guess, conf in MAKERS:
        if re.search(pat, low):
            out.update(short=short, hint=hint, guess=guess, conf=conf)
            break
    return out


# ---------------- tiny DNS helpers (mDNS and NetBIOS) ----------------
def _qname(name):
    out = bytearray()
    for lbl in name.strip(".").split("."):
        b = lbl.encode()[:63]
        out += bytes([len(b)]) + b
    return bytes(out + b"\x00")


def _name_at(buf, off, depth=0):
    parts = []
    while off < len(buf) and depth < 12:
        n = buf[off]
        if n == 0:
            return ".".join(parts), off + 1
        if n & 0xC0 == 0xC0:
            if off + 2 > len(buf):
                break
            sub, _ = _name_at(buf, struct.unpack(">H", buf[off:off + 2])[0] & 0x3FFF, depth + 1)
            parts.append(sub)
            return ".".join(p for p in parts if p), off + 2
        parts.append(buf[off + 1:off + 1 + n].decode(errors="replace"))
        off += 1 + n
    return ".".join(parts), off


def parse_dns(data):
    """All answer/additional records: [(name, type, value)] with PTR/SRV target names, TXT as dict, A as text."""
    recs = []
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
        off = 12
        for _ in range(qd):
            _, off = _name_at(data, off)
            off += 4
        for _ in range(min(an + ns + ar, 60)):
            nm, off = _name_at(data, off)
            if off + 10 > len(data):
                break
            typ, _cls, _ttl, dl = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + dl]
            if typ == 12:
                val = _name_at(data, off)[0]
            elif typ == 33 and dl > 6:
                val = _name_at(data, off + 6)[0]
            elif typ == 16:
                val, i = {}, 0
                while i < len(rd):
                    s = rd[i + 1:i + 1 + rd[i]].decode(errors="replace")
                    i += 1 + rd[i]
                    k, _, v = s.partition("=")
                    if k:
                        val[k.lower()[:20]] = v[:80]
            elif typ == 1 and dl == 4:
                val = socket.inet_ntoa(rd)
            else:
                val = None
            recs.append((nm, typ, val))
            off += dl
    except Exception:
        pass
    return recs


def _udp_ask(ip, port, payload, wait, max_replies=3):
    """Send one datagram to the device, collect replies FROM THAT DEVICE ONLY for `wait` seconds."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    out = []
    try:
        s.settimeout(0.3)
        s.sendto(payload, (ip, port))
        end = time.time() + wait
        while time.time() < end and len(out) < max_replies:
            try:
                data, addr = s.recvfrom(9000)
            except socket.timeout:
                continue
            if addr[0] == ip:
                out.append(data)
    except OSError:
        pass
    finally:
        s.close()
    return out


def mdns_ask(ip, qname, qtype=12, wait=1.2):
    """One unicast mDNS question straight to the device (RFC 6762 'legacy unicast'). Returns parsed records."""
    q = struct.pack(">HHHHHH", random.randint(1, 65535), 0, 1, 0, 0, 0) + _qname(qname) + struct.pack(">HH", qtype, 1)
    recs = []
    for data in _udp_ask(ip, MDNS_PORT, q, wait, max_replies=2):
        recs += parse_dns(data)
    return recs


def netbios_name(ip, wait=1.0):
    """NetBIOS 'node status' (NBSTAT) question to UDP 137: Windows PCs and file servers answer with their name."""
    enc = b"".join(bytes([0x41 + (c >> 4), 0x41 + (c & 0xF)]) for c in b"*" + b"\x00" * 15)
    q = struct.pack(">HHHHHH", random.randint(1, 65535), 0, 1, 0, 0, 0) + b"\x20" + enc + b"\x00" + struct.pack(">HH", 0x21, 1)
    for data in _udp_ask(ip, NETBIOS_PORT, q, wait, max_replies=1):
        try:
            _, off = _name_at(data, 12)
            off += 10                                   # type, class, ttl, rdlength
            n = data[off]
            off += 1
            for i in range(n):
                e = data[off + 18 * i: off + 18 * i + 18]
                nm, suffix, flags = e[:15].decode(errors="replace").strip(), e[15], struct.unpack(">H", e[16:18])[0]
                if suffix == 0 and not flags & 0x8000 and nm and nm.isprintable():
                    return nm
        except Exception:
            continue
    return None


def ssdp_info(ip, wait=1.5, fetch=True):
    """Unicast SSDP search to the device; if it points at a description file ON ITSELF, read the names there."""
    msg = (f"M-SEARCH * HTTP/1.1\r\nHOST: {ip}:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n").encode()
    info = {}
    for data in _udp_ask(ip, SSDP_PORT, msg, wait, max_replies=4):
        for line in data.decode(errors="replace").split("\r\n")[1:]:
            k, _, v = line.partition(":")
            k = k.strip().upper()
            if k in ("LOCATION", "SERVER") and k.lower() not in info:
                info[k.lower()] = v.strip()[:200]
    loc = info.get("location")
    if fetch and loc:
        info.update(upnp_description(ip, loc))
    return info


def upnp_description(ip, url, timeout=2.0):
    m = re.match(r"^http://([0-9.]+)(?::(\d{1,5}))?(/[^\s]*)?$", url)
    if not m or m.group(1) != ip:
        return {}                                       # only the device itself, plain HTTP, no names to resolve
    port = int(m.group(2) or 80)
    if port in PRINTER_RAW_PORTS or not 1 <= port <= 65535:
        return {}
    conn = http.client.HTTPConnection(ip, port, timeout=timeout)
    try:
        conn.request("GET", m.group(3) or "/", headers={"User-Agent": "Hark-Gateway/2 (device check)", "Connection": "close"})
        r = conn.getresponse()
        if r.status != 200:
            return {}
        body = r.read(65536).decode(errors="replace")
    except Exception:
        return {}
    finally:
        conn.close()
    out = {}
    for tag in ("friendlyName", "manufacturer", "modelName", "modelDescription", "modelNumber"):
        mm = re.search(rf"<{tag}>\s*([^<]{{1,120}}?)\s*</{tag}>", body)
        if mm:
            out[tag] = clean(html.unescape(mm.group(1)), 60)
    return out


def reverse_dns(ip, wait=1.5):
    box = {}
    def look():
        try:
            box["n"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
    t = threading.Thread(target=look, daemon=True)
    t.start(); t.join(wait)
    n = box.get("n")
    if not n or n == ip or n.endswith(".arpa"):
        return None
    return n


def tcp_ports(ip, ports=None, timeout=0.6):
    """Connect-only check (no data sent). SSH says hello first, so its first line is kept (it names the OS)."""
    res, lock = {}, threading.Lock()
    def one(p):
        try:
            with socket.create_connection((ip, p), timeout=timeout) as s:
                banner = ""
                if p == 22:
                    try:
                        s.settimeout(0.5); banner = s.recv(80).decode(errors="replace").strip()
                    except Exception:
                        pass
                with lock:
                    res[p] = banner
        except Exception:
            pass
    ps = [p for p in (ports or PORTS) if p not in PRINTER_RAW_PORTS]
    ths = []
    for chunk in range(0, len(ps), 8):                       # at most 8 at a time: polite
        batch = [threading.Thread(target=one, args=(p,), daemon=True) for p in ps[chunk:chunk + 8]]
        for t in batch: t.start()
        for t in batch: t.join(timeout + 0.3)
        ths += batch
    return res, len(ps)


def clean(s, n=40):
    """Device-supplied text goes into a Markdown notification: keep it short and harmless."""
    s = re.sub(r"[\x00-\x1f\x7f`*_\[\]<>|\\#]", "", str(s or "")).strip()
    s = re.sub(r"https?://", "", s)
    return s[:n]


# ---------------- services -> plain words ----------------
SERVICES = {   # mDNS service type -> (plain words, guess, confidence)
    "_googlecast": ("Chromecast casting", "a Chromecast, Google TV or Google/Nest speaker", 3),
    "_airplay": ("AirPlay", "an Apple TV, AirPlay speaker or AirPlay TV", 2),
    "_raop": ("AirPlay audio", "an AirPlay speaker", 2),
    "_ipp": ("printing", "a printer", 3), "_ipps": ("printing", "a printer", 3), "_printer": ("printing", "a printer", 3),
    "_pdl-datastream": ("printing", "a printer", 3), "_uscan": ("scanning", "a printer/scanner", 3),
    "_hap": ("HomeKit", "a HomeKit smart-home device", 2),
    "_matter": ("Matter smart home", "a Matter smart-home device", 2), "_matterc": ("Matter smart home", "a Matter smart-home device", 2),
    "_spotify-connect": ("Spotify Connect", "a speaker, TV or streaming box", 2),
    "_sonos": ("Sonos", "a Sonos speaker", 3),
    "_amzn-wplay": ("Amazon casting", "a Fire TV or Echo device", 3), "_amzn-alexa": ("Alexa", "an Echo device", 3),
    "_esphomelib": ("ESPHome", "an ESPHome smart-home gadget", 3),
    "_home-assistant": ("Home Assistant", "a Home Assistant server", 3),
    "_hue": ("Philips Hue", "a Philips Hue bridge", 3),
    "_companion-link": ("Apple device link", "an iPhone, iPad, Mac or Apple TV", 2),
    "_smb": ("file sharing", "a computer or network storage", 1), "_afpovertcp": ("Mac file sharing", "a Mac or network storage", 2),
    "_ssh": ("remote login", "a computer or mini-computer", 1), "_sftp-ssh": ("remote login", "a computer or mini-computer", 1),
    "_rfb": ("screen sharing", "a computer", 2), "_device-info": ("Apple device info", None, 0),
    "_androidtvremote2": ("Android TV remote", "an Android/Google TV", 3), "_nvstream": ("game streaming", "a gaming PC or Shield", 2),
    "_plexmediasvr": ("Plex", "a Plex media server", 3), "_roku": ("Roku", "a Roku player", 3),
    "_meshcop": ("Thread", "a Thread border router (smart-home hub)", 2), "_mqtt": ("smart-home messages", "a smart-home hub", 1),
    "_workstation": ("computer", "a computer (Linux)", 1), "_http": ("a web page", None, 0),
}
APPLE_MODELS = [(r"^iphone", "an iPhone"), (r"^ipad", "an iPad"), (r"^macbook", "a MacBook"), (r"^(imac|macmini|macpro|mac\d)", "a Mac"),
                (r"^appletv", "an Apple TV"), (r"^audioaccessory", "a HomePod"), (r"^watch", "an Apple Watch")]
HOSTNAME_HINTS = [   # pattern on the device's own name -> guess, confidence
    (r"iphone", "an iPhone", 3), (r"ipad", "an iPad", 3), (r"macbook|mbp|mba\b", "a MacBook", 3), (r"imac|mac-?mini", "a Mac", 3),
    (r"apple-?tv", "an Apple TV", 3), (r"homepod", "a HomePod", 3), (r"watch", "a smartwatch", 2),
    (r"android|galaxy|pixel|oneplus|redmi|moto", "an Android phone or tablet", 3),
    (r"^desktop-|^laptop-|^win-|windows", "a Windows computer", 3), (r"chromebook|^chrome", "a Chromebook", 2),
    (r"xbox", "an Xbox", 3), (r"ps[345]|playstation", "a PlayStation", 3), (r"nintendo|switch", "a Nintendo Switch", 2),
    (r"roku", "a Roku player", 3), (r"echo|amazon|fire-?tv|kindle", "an Amazon device", 2), (r"chromecast|google-?home|nest", "a Google/Nest device", 3),
    (r"^esp|tasmota|shelly|wled|esphome|tuya|smartplug|plug", "a smart-home gadget", 3), (r"ring|doorbell|cam", "a camera or doorbell", 2),
    (r"printer|^brw|^hp[0-9a-f]{6}|^npi|canon", "a printer", 3), (r"raspberrypi|^pi\b|^rpi", "a Raspberry Pi", 3),
    (r"tv\b|bravia|vizio|lgwebos|tizen", "a smart TV", 2), (r"laptop|notebook|thinkpad|surface", "a laptop", 2),
    (r"desktop|-pc\b|^pc-", "a desktop computer", 2), (r"tesla|rivian", "a car", 2),
]
PORT_HINTS = [   # (ports all open) -> guess, confidence
    ({62078}, "an iPhone or iPad", 3), ({8008, 8009}, "a Chromecast or Google/Nest speaker", 3), ({8009}, "a Chromecast or Google/Nest speaker", 2),
    ({7000}, "an Apple TV, Mac or AirPlay speaker", 2), ({631}, "a printer", 2), ({3389}, "a Windows computer", 3),
    ({445, 139}, "a Windows computer or network storage", 2), ({548}, "a Mac or network storage", 2), ({554}, "a security camera or video recorder", 2),
    ({8123}, "a Home Assistant server", 3), ({32400}, "a Plex media server", 3), ({6053}, "an ESPHome smart-home gadget", 3),
    ({6668}, "a Tuya smart plug or bulb", 3), ({1883}, "a smart-home hub", 2), ({53}, "a router or network box", 2),
    ({5000}, "a network storage box or media device", 1), ({22}, "a computer or mini-computer", 1), ({80}, "a gadget with a web page", 1),
]
CONF_WORDS = {3: "fairly sure", 2: "medium confidence", 1: "low confidence"}


def best_guess(r):
    """Pick the strongest piece of evidence. Returns (guess, confidence 1..3) or (None, 0)."""
    cands = []                                   # (conf, order, guess)
    model = (r.get("upnp") or {}).get("modelName")
    fn = (r.get("upnp") or {}).get("friendlyName")
    if model or fn:
        man = (r.get("upnp") or {}).get("manufacturer")
        g = " ".join(x for x in (man if man and man.lower() not in str(model).lower() else None, model or fn) if x)
        cands.append((3, 0, f"{g} (it says so itself)"))
    for m, g in APPLE_MODELS:
        if re.search(m, str(r.get("apple_model") or "").lower()):
            cands.append((3, 1, g))
    for t in r.get("services") or []:
        s = SERVICES.get(t)
        if s and s[1]:
            cands.append((s[2], 2, s[1]))
    for n in (r.get("names") or {}).values():
        for pat, g, c in HOSTNAME_HINTS:
            if n and re.search(pat, n.lower()):
                cands.append((c, 3, g)); break
    op = set(r.get("open_ports") or [])
    for need, g, c in PORT_HINTS:
        if need <= op:
            cands.append((c, 4, g)); break
    mk = r.get("maker") or {}
    if mk.get("guess"):
        cands.append((mk.get("conf", 1), 5, mk["guess"]))
    if r.get("private_mac"):
        cands.append((2, 6, "a phone, tablet or laptop"))
    if not cands:
        return None, 0
    conf, _, g = sorted(cands, key=lambda c: (-c[0], c[1]))[0]
    agree = [c for c in cands if c[2] == g]
    if conf < 3 and len(agree) > 1:
        conf += 1
    return g, conf


def investigate(dev, check_target=None, deadline=DEADLINE_S, active=lambda: True, probes=True):
    """dev: {mac, ip, hostname, vendor}. Returns a result dict (never raises)."""
    t0 = time.time()
    mac, ip = dev.get("mac"), dev.get("ip")
    r = {"private_mac": is_private_mac(mac), "maker": maker_info(mac, dev.get("vendor")), "names": {},
         "services": [], "open_ports": [], "ports_checked": 0, "upnp": {}, "probed": False}
    if dev.get("hostname"):
        r["names"]["dhcp"] = clean(dev["hostname"])
    why_not = None
    if not probes:
        why_not = "closer look switched off (inventory_investigate)"
    elif not ip:
        why_not = "no network address known"
    elif not active():
        why_not = "Hark's network tools are switched off (kill switch)"
    elif check_target is None:
        why_not = "address safety check unavailable"        # fail closed: no check, no probes
    else:
        try:
            ipaddress.IPv4Address(ip)
            check_target(ip)
        except Exception:
            why_not = "address is outside your home network"
    if why_not:
        r["skipped"] = why_not
    else:
        r["probed"] = True
        box = {}
        def run(key, fn):
            try:
                box[key] = fn()
            except Exception as e:
                box[key + "_err"] = type(e).__name__
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        jobs = {"rdns": lambda: reverse_dns(ip), "mdns_name": lambda: mdns_ask(ip, rev),
                "mdns_svc": lambda: mdns_ask(ip, "_services._dns-sd._udp.local"), "netbios": lambda: netbios_name(ip),
                "ssdp": lambda: ssdp_info(ip), "ports": lambda: tcp_ports(ip)}
        ths = [threading.Thread(target=run, args=(k, f), daemon=True) for k, f in jobs.items()]
        for t in ths: t.start()
        for t in ths: t.join(max(0.05, deadline - (time.time() - t0)))
        if box.get("rdns"):
            r["names"]["reverse DNS"] = clean(box["rdns"])
        for nm, typ, val in box.get("mdns_name") or []:
            if typ == 12 and val:
                r["names"]["mDNS"] = clean(val[:-6] if val.endswith(".local") else val); break
        if box.get("netbios"):
            r["names"]["Windows"] = clean(box["netbios"])
        types = []
        for nm, typ, val in box.get("mdns_svc") or []:
            if typ == 12 and val:
                m = re.match(r"^(_[a-z0-9-]{1,30})\._(tcp|udp)", val.lower())
                if m and m.group(1) not in types:
                    types.append(m.group(1))
        r["services"] = types[:15]
        left = deadline - (time.time() - t0)
        interesting = [t for t in ("_googlecast", "_device-info", "_airplay", "_hap", "_ipp", "_spotify-connect") if t in types]
        if interesting and left > 1.0 and active():          # one more question for the friendly name / model
            recs = mdns_ask(ip, interesting[0] + "._tcp.local", wait=min(1.0, left - 0.2))
            fn_set = False
            for nm, typ, val in recs:
                if typ == 16 and isinstance(val, dict):
                    if val.get("fn"):                       # the name the owner gave it wins over the instance name
                        r["names"]["its own name"] = clean(val["fn"])
                        fn_set = True
                    if val.get("model") or val.get("md"):
                        r["apple_model" if val.get("model") else "model"] = clean(val.get("model") or val.get("md"))
                elif typ == 12 and val and not fn_set and "its own name" not in r["names"]:
                    inst = val.split("._")[0]
                    if inst and not re.fullmatch(r"[0-9a-f-]{20,}", inst.lower()):
                        r["names"]["its own name"] = clean(inst)
        if r.get("model"):
            r.setdefault("upnp", {}).setdefault("modelName", r["model"])
        up = box.get("ssdp") or {}
        r["upnp"].update({k: v for k, v in up.items() if k in ("friendlyName", "manufacturer", "modelName", "modelDescription")})
        if up.get("friendlyName"):
            r["names"]["UPnP"] = up["friendlyName"]
        ports, n = box.get("ports") or ({}, len(PORTS))
        r["open_ports"], r["ports_checked"] = sorted(ports), n
        ssh = ports.get(22) or ""
        if re.search(r"raspbian", ssh, re.I):
            r["names"].setdefault("SSH", "Raspberry Pi OS")
        r["timed_out"] = any(t.is_alive() for t in ths)
    r["guess"], r["confidence"] = best_guess(r)
    r["ms"] = int((time.time() - t0) * 1000)
    return r


# ---------------- presence (for the re-check) ----------------
def is_present(ip, mac, arp_fn, local_nets=()):
    """True = still here, False = gone, None = can't tell from here (different network segment and no answer)."""
    if not ip:
        return None
    answered = False
    if shutil.which("ping"):
        try:
            answered = subprocess.run(["ping", "-c", "1", "-W", "1", "--", ip], capture_output=True, timeout=3).returncode == 0
        except Exception:
            pass
    if not answered:
        for p in (62078, 80, 443):
            try:
                with socket.create_connection((ip, p), timeout=0.5):
                    answered = True
            except ConnectionRefusedError:
                answered = True                       # a 'no' still means someone is there
            except Exception:
                pass
            if answered:
                break
    try:
        seen = {k: str(v).lower() for k, v in (arp_fn() or {}).items()}
    except Exception:
        seen = {}
    if seen.get(ip) and seen.get(ip) != mac:
        return False                                  # someone else has that address now
    if answered or seen.get(ip) == mac:
        return True
    try:
        same_segment = any(ipaddress.ip_address(ip) in n for n in (local_nets() if callable(local_nets) else local_nets))
    except Exception:
        same_segment = False
    return False if same_segment else None

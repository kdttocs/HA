"""Weekly network check-up (2.0.0). Stdlib only. Read-only: it connects and looks, it never changes anything.

Once a week (checkup_day at checkup_time, local time), or when Hark asks with the `checkup` tool:
  1. Risky open ports on the devices in the inventory (Telnet, FTP, Windows file sharing, remote desktop, VNC,
     databases and Docker without passwords or encryption). Connect-only checks, a few at a time.
  2. Updates waiting: Home Assistant's own update entities (core, OS, apps, ESPHome, ...) and the router's firmware.
  3. Certificates about to expire on your devices' HTTPS pages (and any host:port in checkup_cert_hosts).
The report goes to sensor.hark_gateway_checkup (state "ok" or "N to look at"), a persistent notification, and the
event `hark_gateway_checkup`. The full report is kept in /data/checkup_last.json and returned by the `checkup` tool.
"""
import datetime, json, os, re, socket, ssl, tempfile, threading, time

DATA_DIR = os.environ.get("DATA_DIR", "/data")
FILE = os.path.join(DATA_DIR, "checkup_last.json")
RISKY = {21: "FTP (passwords travel unencrypted)", 23: "Telnet (unencrypted remote login)",
         445: "Windows file sharing (SMB)", 3389: "Remote Desktop", 5900: "VNC screen sharing",
         2375: "Docker control without encryption", 6379: "Redis database", 27017: "MongoDB database",
         9200: "Elasticsearch", 11211: "Memcached", 1883: "MQTT without encryption"}
TLS_PORTS = (443, 8443)
DAYS = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
MAX_HOSTS = 128
CERT_WARN_DAYS = 30


def _open(ip, port, timeout=0.6):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False


def cert_info(ip, port, server_name=None, timeout=4):
    """Expiry of the certificate a device presents (no verification: home gear is usually self-signed)."""
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=timeout) as s:
        with ctx.wrap_socket(s, server_hostname=server_name) as t:
            der = t.getpeercert(binary_form=True)
    pem = ssl.DER_cert_to_PEM_cert(der)
    fd, path = tempfile.mkstemp(suffix=".pem")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(pem)
        d = ssl._ssl._test_decode_cert(path)       # stdlib parser (no third-party packages in the app)
    finally:
        os.remove(path)
    exp = datetime.datetime.strptime(d["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    left = (exp - datetime.datetime.now(datetime.timezone.utc)).days
    subj = dict(x[0] for x in d.get("subject", ()) if x)
    iss = dict(x[0] for x in d.get("issuer", ()) if x)
    return {"expires": exp.strftime("%Y-%m-%d"), "days_left": left, "subject": subj.get("commonName"),
            "self_signed": d.get("subject") == d.get("issuer"), "issuer": iss.get("organizationName") or iss.get("commonName")}


class Checkup:
    def __init__(self, opts, ha, inventory, router_fn, check_target, parallel, now=time.time):
        self.opts, self.ha, self.inventory, self.router_fn = opts, ha, inventory, router_fn
        self.check_target, self.parallel, self.now = check_target, parallel, now
        self.lock = threading.Lock()

    def last(self):
        try:
            return json.load(open(FILE))
        except Exception:
            return None

    def _hosts(self):
        ips = []
        if self.inventory:
            week = self.now() - 7 * 86400
            for d in self.inventory.report(limit=2000)["devices"]:
                if d.get("ip") and d.get("last_seen", 0) > week:
                    ips.append((d["ip"], d.get("hostname")))
        out, seen = [], set()
        for ip, name in ips:
            try:
                ok = self.check_target(ip)
            except Exception:
                continue
            if ok not in seen:
                seen.add(ok); out.append((ok, name))
        return out[:MAX_HOSTS]

    def _cert_targets(self):
        out = []
        for item in str(self.opts.get("checkup_cert_hosts") or "").split(","):
            item = item.strip()
            if not item:
                continue
            m = re.fullmatch(r"([A-Za-z0-9.\-]{1,253})(?::(\d{1,5}))?", item)
            if not m:
                continue
            out.append((m.group(1), int(m.group(2) or 443)))
        return out[:20]

    def run(self, reason="weekly"):
        if not self.lock.acquire(blocking=False):
            return {"note": "a check-up is already running"}
        try:
            return self._run(reason)
        finally:
            self.lock.release()

    def _run(self, reason):
        t0 = self.now()
        hosts = self._hosts()
        names = dict(hosts)
        pairs = [(ip, p) for ip, _ in hosts for p in list(RISKY) + list(TLS_PORTS)]
        opened = self.parallel(lambda x: x if _open(*x) else None, pairs, workers=32)
        risky = sorted(({"ip": ip, "hostname": names.get(ip), "port": p, "what": RISKY[p]} for ip, p in opened if p in RISKY),
                       key=lambda r: (r["ip"], r["port"]))
        certs = []
        for ip, p in sorted(x for x in opened if x[1] in TLS_PORTS):
            try:
                certs.append(dict(host=ip, hostname=names.get(ip), port=p, **cert_info(ip, p)))
            except Exception as e:
                certs.append({"host": ip, "port": p, "error": str(e)[:100]})
        for host, p in self._cert_targets():
            try:
                infos = socket.getaddrinfo(host, p, proto=socket.IPPROTO_TCP)
                ip = infos[0][4][0]
                import tools
                nip = tools._norm_ip(ip)
                if tools.name_blocked(host) or any(nip in n for n in tools.BLOCKED_NETS if n.version == nip.version):
                    raise ValueError("internal address refused")
                ip = str(nip)
                certs.append(dict(host=host, port=p, **cert_info(ip, p, server_name=host)))
            except Exception as e:
                certs.append({"host": host, "port": p, "error": str(e)[:100]})
        cert_warn = [c for c in certs if c.get("days_left") is not None and c["days_left"] < CERT_WARN_DAYS]
        ha_updates = []
        try:
            for s in self.ha("GET", "/states", timeout=30) or []:
                if str(s.get("entity_id", "")).startswith("update.") and s.get("state") == "on":
                    a = s.get("attributes") or {}
                    ha_updates.append({"name": a.get("friendly_name") or s["entity_id"], "installed": a.get("installed_version"),
                                       "latest": a.get("latest_version")})
        except Exception as e:
            ha_updates = [{"error": f"could not read Home Assistant updates: {str(e)[:100]}"}]
        router_fw = None
        try:
            r = self.router_fn()
            if r is not None:
                router_fw = dict(router=r.kind, **r.firmware())
        except Exception as e:
            router_fw = {"error": str(e)[:150]}
        issues = len(risky) + len(cert_warn) + len([u for u in ha_updates if "error" not in u]) + \
            (1 if router_fw and router_fw.get("update_available") else 0)
        rep = {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t0)), "reason": reason,
               "seconds": round(self.now() - t0, 1), "devices_checked": len(hosts), "issues": issues,
               "risky_ports": risky, "certificates": certs, "certificates_expiring": cert_warn,
               "home_assistant_updates": ha_updates, "router_firmware": router_fw}
        try:
            fd = os.open(FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(rep, f)
        except Exception as e:
            print("checkup: save failed", e)
        self.publish(rep)
        return rep

    @staticmethod
    def markdown(rep):
        lines = [f"Checked {rep['devices_checked']} devices."]
        if rep["risky_ports"]:
            lines.append("\n**Open doors worth a look**")
            lines += [f"- {r['hostname'] or r['ip']} ({r['ip']}): port {r['port']}, {r['what']}" for r in rep["risky_ports"][:15]]
        if rep["certificates_expiring"]:
            lines.append("\n**Certificates expiring soon**")
            lines += [f"- {c.get('hostname') or c['host']}:{c['port']} expires {c['expires']} ({c['days_left']} days)"
                      for c in rep["certificates_expiring"][:10]]
        ups = [u for u in rep["home_assistant_updates"] if "error" not in u]
        if ups:
            lines.append("\n**Updates waiting in Home Assistant**")
            lines += [f"- {u['name']}: {u.get('installed')} → {u.get('latest')}" for u in ups[:15]]
        fw = rep.get("router_firmware") or {}
        if fw.get("update_available"):
            lines.append(f"\n**Router firmware update available** ({fw.get('router')}).")
        if rep["issues"] == 0:
            lines.append("\nNothing needs attention this week.")
        return "\n".join(lines)

    def publish(self, rep):
        st = "ok" if rep["issues"] == 0 else f"{rep['issues']} to look at"
        try:
            self.ha("POST", "/states/sensor.hark_gateway_checkup", {"state": st, "attributes": {
                "friendly_name": "Network check-up", "icon": "mdi:shield-check" if rep["issues"] == 0 else "mdi:shield-alert",
                "generated_at": rep["generated_at"], "devices_checked": rep["devices_checked"],
                "risky_ports": len(rep["risky_ports"]), "certificates_expiring": len(rep["certificates_expiring"]),
                "updates_waiting": len([u for u in rep["home_assistant_updates"] if "error" not in u]),
                "router_update": bool((rep.get("router_firmware") or {}).get("update_available"))}})
        except Exception as e:
            print("checkup: sensor failed", e)
        try:
            self.ha("POST", "/events/hark_gateway_checkup", {"issues": rep["issues"], "generated_at": rep["generated_at"]})
        except Exception as e:
            print("checkup: event failed", e)
        if self.opts.get("checkup_notify", True):
            try:
                self.ha("POST", "/services/persistent_notification/create",
                        {"title": "Weekly network check-up", "message": self.markdown(rep),
                         "notification_id": "hark_gateway_checkup"})
            except Exception as e:
                print("checkup: notification failed", e)

    def due(self, lt=None):
        lt = lt or time.localtime(self.now())
        day = str(self.opts.get("checkup_day") or "sun").lower()[:3]
        m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(self.opts.get("checkup_time") or "09:00").strip())
        hh, mm = (int(m.group(1)), int(m.group(2))) if m else (9, 0)
        if DAYS[lt.tm_wday] != (day if day in DAYS else "sun"):
            return False
        mins = lt.tm_hour * 60 + lt.tm_min - (hh * 60 + mm)
        last = self.last() or {}
        return 0 <= mins < 360 and not str(last.get("generated_at", "")).startswith(time.strftime("%Y-%m-%d", lt))

    def run_forever(self, active=lambda: True):
        time.sleep(120)
        while True:
            try:
                if self.opts.get("checkup_weekly", True) and self.due() and active():
                    self.run("weekly")
            except Exception as e:
                print("checkup: error", e)
            time.sleep(300)

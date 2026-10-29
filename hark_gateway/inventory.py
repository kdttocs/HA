"""Device inventory with new-device alerts (2.0.0; closer look, re-check and Known/Ignore in 2.0.5). Stdlib only.

Every few minutes (inventory_every_min) the app lists the devices on the home network:
  - from the router (DHCP leases + ARP/neighbour table) when a router is configured, and
  - from this machine's own ARP table (devices Home Assistant has talked to recently) always.
The first run only learns what is there (no alerts). After that, a device with a MAC address never seen before:
  - gets a short, polite closer look (investigate.py: maker, names, services; about 6 seconds at most, on a
    background thread so nothing else waits; skipped while the kill switch is off or inventory_investigate is off),
  - raises a Home Assistant persistent notification ("New device on your network") with a plain-language best guess,
  - fires the event `hark_gateway_new_device` (for your own automations),
  - is listed in sensor.hark_gateway_devices (state = devices known; attributes = counts + the latest new ones).
About 10 minutes later it is checked once more; if it has left, the notification is updated ("left after ...") and
`hark_gateway_device_left` fires.

Known / Ignore: fire the Home Assistant event `hark_gateway_device` with {"mac": ..., "action": "known" | "ignore" |
"new", "name": "optional"} (Hark can do this for you, and Developer tools > Events works too), or tap Known / Ignore
on your phone when inventory_phone_notify is on. That dismisses the alert, stops the re-check update, names the
device, and keeps it out of the "new" lists. A device marked before it ever shows up never alerts.
The list lives in the app's private /data/inventory.json (last 2,000 devices).
"""
import datetime, heapq, json, os, queue, re, threading, time

import investigate

DATA_DIR = os.environ.get("DATA_DIR", "/data")
FILE = os.path.join(DATA_DIR, "inventory.json")
MAX_DEVICES = 2000
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
NEW_EVENT = "hark_gateway_new_device"
LEFT_EVENT = "hark_gateway_device_left"
REVIEW_EVENT = "hark_gateway_device"
PHONE_ACTION_EVENT = "mobile_app_notification_action"
PHONE_ACTION_RE = re.compile(r"^HARKGW_DEV_(KNOWN|IGNORE)_([0-9a-f]{12})$")
SENSOR = "sensor.hark_gateway_devices"
RECHECK_S = 600
LOOKS_PER_HOUR = 20                       # closer looks; more new devices than that in an hour get a plain alert
ACTIONS = {"known", "ignore", "new"}
SOURCES = {"dhcp": "your router's address list (DHCP)", "arp": "your router's neighbour table",
           "neighbors": "your router's neighbour table", "this machine's ARP table": "Home Assistant's own neighbour table"}
NAME_SOURCES = [("its own name", "its own announcement"), ("UPnP", "its device description"), ("dhcp", "what it told your router"),
                ("mDNS", "its own announcement"), ("Windows", "its Windows network name"), ("reverse DNS", "your router's DNS"),
                ("SSH", "its remote-login greeting")]


def norm_mac(m):
    h = re.sub(r"[^0-9a-fA-F]", "", str(m or "")).lower()
    return ":".join(h[i:i + 2] for i in range(0, 12, 2)) if len(h) == 12 else None


is_private_mac = investigate.is_private_mac


def clean_name(s):
    return investigate.clean(s, 40)


LEGAL = re.compile(r"[\s,]+(pte\.?|ltd\.?|limited|inc\.?|co\.?|corp\.?|corporation|llc|gmbh|ag|s\.?a\.?|b\.?v\.?|"
                   r"oy|ab|plc|kk|company|incorporated|corporate)$", re.I)


def maker_display(name):
    """'Cloud Network Technology Singapore Pte. Ltd.' -> 'Cloud Network Technology Singapore'."""
    s = investigate.clean(name, 80)
    for _ in range(4):
        t = LEGAL.sub("", s).strip(" ,")
        if t == s or not t:
            break
        s = t
    return s[:50]


# ---------------- time on the user's clock ----------------
def zone(name):
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name) if name else None
    except Exception:
        return None


def clock(ts, tz=None):
    """'6:21 PM' in Home Assistant's time zone (falls back to the app's local time)."""
    dt = datetime.datetime.fromtimestamp(ts, tz) if tz else datetime.datetime.fromtimestamp(ts)
    return dt.strftime("%I:%M %p").lstrip("0")


def minutes(sec):
    m = max(1, int(round(sec / 60)))
    return f"{m} minute{'s' if m != 1 else ''}" if m < 90 else f"{round(m / 60, 1):g} hours"


# ---------------- the message ----------------
def best_name(names):
    for key, label in NAME_SOURCES:
        if (names or {}).get(key):
            return names[key], label
    return None, None


def render(n, r, status, tz=None, phone_buttons=False):
    """Plain-language Markdown for the persistent notification. n: the device; r: investigate() result;
    status: {first_seen, state: 'checking'|'online'|'left'|'unknown', checked_at, last_seen}."""
    names = r.get("names") or {}
    name, name_src = best_name(names)
    first = clock(status["first_seen"], tz)
    head = f"**{name}** joined your network at {first}." if name else f"An unnamed device joined your network at {first}."
    out = [head, ""]
    if r.get("guess"):
        out += [f"**Best guess:** {r['guess']} ({investigate.CONF_WORDS.get(r.get('confidence'), 'low confidence')})", ""]
    else:
        out += ["**Best guess:** not enough clues to say what it is", ""]
    mk = r.get("maker") or {}
    if mk.get("name"):
        short = f" ({mk['short']})" if mk.get("short") and mk["short"].lower() not in mk["name"].lower() else ""
        hint = f", {mk['hint']}" if mk.get("hint") else ""
        src = " (from your router)" if mk.get("source") == "router" else ""
        out.append(f"- **Made by:** {maker_display(mk['name'])}{short}{hint}{src}")
    elif r.get("private_mac"):
        out.append("- **Made by:** hidden. It uses a private Wi-Fi address, which phones, tablets and laptops use to hide "
                   "their maker")
    else:
        out.append("- **Made by:** not in the public maker list")
    if name:
        others = [f"{v} ({k if k not in dict(NAME_SOURCES) else dict(NAME_SOURCES)[k]})" for k, v in names.items()
                  if v and v != name][:2]
        out.append(f"- **Name:** {name} (from {name_src})" + (f"; also seen as {', '.join(others)}" if others else ""))
    else:
        out.append("- **Name:** none. It didn't give your router a name and doesn't announce one")
    mac_note = ("a private Wi-Fi address: it can change now and then, and it hides the maker" if r.get("private_mac")
                else "its real factory address, not a private one")
    out.append(f"- **Hardware address:** {n['mac']}, {mac_note}")
    if r.get("probed"):
        svc = []
        for t in r.get("services") or []:
            words = (investigate.SERVICES.get(t) or (t.lstrip("_"),))[0]
            if words not in svc:
                svc.append(words)
        ports = [f"{investigate.PORTS.get(p, 'port')} ({p})" for p in r.get("open_ports") or []]
        if svc or ports:
            bits = []
            if svc:
                bits.append("announces " + ", ".join(svc[:6]))
            if ports:
                bits.append("answers on " + ", ".join(ports[:6]))
            out.append(f"- **What it offers:** {'; '.join(bits)}")
        else:
            out.append(f"- **What it offers:** nothing. No answer on {r.get('ports_checked') or 'the'} common services and "
                       "it doesn't announce any. That's normal for phones, laptops and game consoles, and for sleeping devices")
    else:
        out.append(f"- **Closer look:** skipped ({r.get('skipped') or 'not available'})")
    src = n.get("source") or "network scan"
    out.append(f"- **Network address:** {n.get('ip') or 'unknown'}, seen in {SOURCES.get(src, clean_name(src))}")
    st = status.get("state")
    if st == "left":
        last = status.get("last_seen") or status["first_seen"]
        if last - status["first_seen"] >= 60:
            out.append(f"- **Status:** left after about {minutes(last - status['first_seen'])} "
                       f"(here {first} to {clock(last, tz)}; gone when I checked at {clock(status['checked_at'], tz)})")
        else:
            out.append(f"- **Status:** left. It was gone when I checked again at {clock(status['checked_at'], tz)} "
                       f"(here for less than {minutes(status['checked_at'] - status['first_seen'])})")
    elif st == "online":
        out.append(f"- **Status:** still online at {clock(status['checked_at'], tz)}")
    elif st == "unknown":
        out.append(f"- **Status:** online at {first}; I couldn't tell later whether it's still here")
    else:
        out.append(f"- **Status:** online at {first}. I'll check again in {minutes(RECHECK_S)}")
    out += ["", "**Is it yours?** Tell Hark (for example: \"the new device is the living room TV\")"
            + (", or tap **Known** or **Ignore** on your phone" if phone_buttons else "")
            + f". You can also mark it in Home Assistant: [Developer tools > Events](/developer-tools/event), event type "
            f"`{REVIEW_EVENT}`, event data `{{\"mac\": \"{n['mac']}\", \"action\": \"known\", \"name\": \"Living room TV\"}}` "
            "(or `\"action\": \"ignore\"`). Known and ignored devices don't alert again."]
    return "\n".join(out)


class Inventory:
    def __init__(self, opts, ha, router_fn, local_arp, notify=True, check_target=None, audit=None, local_nets=()):
        self.opts, self.ha, self.router_fn, self.local_arp, self.notify = opts, ha, router_fn, local_arp, notify
        self.check_target, self.audit_fn, self.local_nets = check_target, audit, local_nets
        self.background = False            # run_forever: closer looks happen on their own thread
        self.lock = threading.Lock()
        self.data = self._load()
        self.last_scan = None
        self.last_source = None
        self.last_error = None
        self.active = lambda: True
        self.q = queue.Queue(maxsize=50)
        self.rechecks = []                 # heap of (due, mac)
        self.alerts = {}                   # mac -> (device, look result, status) while a re-check is pending
        self.looks = []                    # times of recent closer looks (rate limit)
        self.worker = None
        self._tz, self._tz_at = None, 0
        svc = str(self.opts.get("phone_notify_service") or "").strip()
        svc = svc[7:] if svc.startswith("notify.") else svc
        self.phone = svc if (self.opts.get("inventory_phone_notify") and re.fullmatch(r"[a-z0-9_]{2,80}", svc)) else ""
        uid = str(self.opts.get("phone_approver_user_id") or "").strip().lower()
        self.phone_user = uid if re.fullmatch(r"[0-9a-f]{32}", uid) else ""

    def _load(self):
        try:
            d = json.load(open(FILE))
            if isinstance(d, dict) and isinstance(d.get("devices"), dict):
                return d
        except Exception:
            pass
        return {"baseline_done": False, "devices": {}}

    def _save(self):
        try:
            fd = os.open(FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.data, f)
        except Exception as e:
            print("inventory: save failed", e)

    def tz(self):
        """Home Assistant's time zone (asked once an hour), so alert times match the user's clock."""
        if time.time() - self._tz_at > 3600:
            self._tz_at = time.time()
            name = None
            try:
                cfg = self.ha("GET", "/config")
                name = cfg.get("time_zone") if isinstance(cfg, dict) else None
            except Exception:
                pass
            self._tz = zone(name or os.environ.get("TZ"))
        return self._tz

    def _audit(self, tool, target, result, ok=True):
        if self.audit_fn:
            try:
                self.audit_fn(tool, target, result, ok=ok, tier="read")
            except Exception as e:
                print("inventory: audit failed", e)

    def gather(self):
        """Returns ({mac: {ip, hostname, vendor, source}}, source label)."""
        seen, sources = {}, []
        r = None
        try:
            r = self.router_fn()
        except Exception as e:
            self.last_error = f"router: {str(e)[:150]}"
        if r is not None:
            for fn in ("leases", "arp"):
                try:
                    rows = getattr(r, fn)()
                    sources.append(f"{r.kind} {fn}")
                except Exception as e:
                    self.last_error = f"router {fn}: {str(e)[:150]}"
                    continue
                for x in rows:
                    mac = norm_mac(x.get("mac"))
                    if mac and mac != "00:00:00:00:00:00" and not mac.startswith("ff:ff"):
                        cur = seen.setdefault(mac, {})
                        for k in ("ip", "hostname", "vendor", "source"):
                            cur[k] = cur.get(k) or x.get(k)
        try:
            for ip, m in (self.local_arp() or {}).items():
                mac = norm_mac(m)
                if mac and mac != "00:00:00:00:00:00":
                    cur = seen.setdefault(mac, {})
                    if not cur.get("ip"):
                        cur["ip"] = ip
                    if not cur.get("source"):
                        cur["source"] = "this machine's ARP table"
            sources.append("local ARP")
        except Exception as e:
            self.last_error = f"local ARP: {e}"
        return seen, ", ".join(sources)

    def scan(self):
        """One pass. Returns the list of devices that are new since the baseline."""
        seen, src = self.gather()
        now = int(time.time())
        new = []
        with self.lock:
            devs = self.data["devices"]
            for mac, x in seen.items():
                d = devs.get(mac)
                if d is None:
                    d = devs[mac] = {"first_seen": now, "private_mac": is_private_mac(mac)}
                    if self.data.get("baseline_done"):
                        new.append(dict(mac=mac, **{k: x.get(k) for k in ("ip", "hostname", "vendor", "source")},
                                        private_mac=d["private_mac"], first_seen=now))
                        d["new"] = True
                d.setdefault("first_seen", now)
                d["last_seen"] = now
                for k in ("ip", "hostname", "vendor"):
                    if x.get(k):
                        d[k] = str(x[k])[:80]
            if len(devs) > MAX_DEVICES:
                for mac in sorted(devs, key=lambda m: devs[m].get("last_seen", 0))[:len(devs) - MAX_DEVICES]:
                    devs.pop(mac, None)
            first = not self.data.get("baseline_done")
            if seen:
                self.data["baseline_done"] = True
            self._save()
        self.last_scan, self.last_source = now, src
        if first and seen:
            print(f"inventory: learned {len(seen)} devices (first run; no alerts for these)")
        for n in new:
            self.submit(n)
        self.publish(len(seen))
        return new

    # ---- new device: closer look + alert, off the scan thread ----
    def submit(self, n):
        if not self.background:
            return self.handle_new(n)
        self._ensure_worker()
        try:
            self.q.put_nowait(n)
        except queue.Full:
            self.handle_new(n, probes=False, why="too many new devices at once")

    def _ensure_worker(self):
        if self.worker is None or not self.worker.is_alive():
            self.worker = threading.Thread(target=self._work, daemon=True, name="inventory-look")
            self.worker.start()

    def _work(self):
        while True:
            with self.lock:
                wait = max(0.0, self.rechecks[0][0] - time.time()) if self.rechecks else 60.0
            try:
                n = self.q.get(timeout=min(wait, 60.0))
            except queue.Empty:
                n = None
            if n:
                try:
                    self.handle_new(n)
                except Exception as e:
                    print("inventory: closer look failed", type(e).__name__, e)
            self.run_due_rechecks()

    def _may_look(self):
        now = time.time()
        with self.lock:
            self.looks = [t for t in self.looks if now - t < 3600]
            if len(self.looks) >= LOOKS_PER_HOUR:
                return False
            self.looks.append(now)
            return True

    def handle_new(self, n, probes=True, why=None):
        mac = n["mac"]
        with self.lock:
            st = (self.data["devices"].get(mac) or {}).get("status")
        if st in ("known", "ignore"):
            return None
        want = bool(self.opts.get("inventory_investigate", True))
        if probes and want and not self._may_look():
            probes, why = False, f"more than {LOOKS_PER_HOUR} new devices this hour"
        r = investigate.investigate(n, self.check_target, active=self.active, probes=probes and want)
        if why and not r.get("probed"):
            r["skipped"] = why
        with self.lock:
            d = self.data["devices"].get(mac)
            if d is not None:
                d["guess"] = r.get("guess")
                d["confidence"] = r.get("confidence")
                if (r.get("maker") or {}).get("name"):
                    d["maker"] = r["maker"]["name"][:80]
                nm, _ = best_name(r.get("names"))
                if nm:
                    d["seen_name"] = nm
                self._save()
        status = {"first_seen": n.get("first_seen") or int(time.time()), "state": "checking"}
        print("inventory: new device", mac, n.get("ip"), n.get("hostname"), "->", r.get("guess"), f"({r.get('ms')} ms)")
        self._audit("investigate", n.get("ip") or mac,
                    f"new device {mac}: {r.get('guess') or 'unknown'}; {len(r.get('open_ports') or [])} of "
                    f"{r.get('ports_checked') or 0} ports open; {'looked' if r.get('probed') else 'not probed: ' + str(r.get('skipped'))}")
        try:
            self.ha("POST", "/events/" + NEW_EVENT, {
                **{k: n.get(k) for k in ("mac", "ip", "hostname", "source", "private_mac")},
                "maker": (r.get("maker") or {}).get("name"), "name": best_name(r.get("names"))[0], "guess": r.get("guess"),
                "confidence": investigate.CONF_WORDS.get(r.get("confidence")), "services": r.get("services"),
                "open_ports": r.get("open_ports")})
        except Exception as e:
            print("inventory: event failed", e)
        notify = self.notify and self.opts.get("inventory_notify", True)
        if notify:
            self._notify(n, r, status)
            if self.phone:
                self._phone(n, r, status)
        with self.lock:
            self.alerts[mac] = (n, r, status)
            heapq.heappush(self.rechecks, (time.time() + RECHECK_S, mac))
        return r

    def _notify(self, n, r, status):
        try:
            self.ha("POST", "/services/persistent_notification/create",
                    {"title": "New device on your network", "message": render(n, r, status, self.tz(), bool(self.phone)),
                     "notification_id": "hark_gateway_new_" + n["mac"].replace(":", "")})
        except Exception as e:
            print("inventory: notification failed", e)

    def _phone(self, n, r, status):
        h = n["mac"].replace(":", "")
        name = best_name(r.get("names"))[0]
        what = name or (r.get("guess") or "an unnamed device")
        mk = (r.get("maker") or {}).get("short") or (r.get("maker") or {}).get("name")
        try:
            self.ha("POST", f"/services/notify/{self.phone}", {
                "title": "New device on your network",
                "message": f"{what}{' (' + mk[:30] + ')' if mk else ''} joined at {clock(status['first_seen'], self.tz())}. Is it yours?",
                "data": {"tag": "hark_gw_dev_" + h, "group": "hark_gateway_devices",
                         "actions": [{"action": f"HARKGW_DEV_KNOWN_{h}", "title": "Known"},
                                     {"action": f"HARKGW_DEV_IGNORE_{h}", "title": "Ignore"}]}}, timeout=15)
        except Exception as e:
            print("inventory: phone alert failed", e)

    # ---- re-check about 10 minutes later ----
    def run_due_rechecks(self, now=None):
        now = now or time.time()
        due = []
        with self.lock:
            while self.rechecks and self.rechecks[0][0] <= now:
                due.append(heapq.heappop(self.rechecks)[1])
        for mac in due:
            try:
                self.recheck(mac)
            except Exception as e:
                print("inventory: re-check failed", type(e).__name__, e)

    def recheck(self, mac):
        with self.lock:
            item = self.alerts.pop(mac, None)
            d = dict(self.data["devices"].get(mac) or {})
        if not item or d.get("status") in ("known", "ignore") or not self.active():
            return None
        n, r, status = item
        ip = d.get("ip") or n.get("ip")
        here = investigate.is_present(ip, mac, self.local_arp, self.local_nets)
        now = int(time.time())
        status = dict(status, checked_at=now, last_seen=d.get("last_seen") or status["first_seen"])
        if here is True:
            status["state"] = "online"
            with self.lock:
                if mac in self.data["devices"]:
                    self.data["devices"][mac]["last_seen"] = now
                    self._save()
        elif here is False:
            status["state"] = "left"
            with self.lock:
                if mac in self.data["devices"]:
                    self.data["devices"][mac]["left_at"] = now
                    self._save()
            try:
                self.ha("POST", "/events/" + LEFT_EVENT, {"mac": mac, "ip": ip, "first_seen": status["first_seen"],
                                                          "last_seen": status["last_seen"]})
            except Exception as e:
                print("inventory: event failed", e)
            if self.notify and self.opts.get("inventory_notify", True):
                self._notify(n, r, status)        # same notification id: the alert is updated, not duplicated
        else:
            status["state"] = "unknown"
        self._audit("investigate", ip or mac, f"re-check {mac}: {status['state']}")
        return status

    # ---- Known / Ignore ----
    def review(self, mac, action, name=None, via="Hark"):
        mac = norm_mac(mac)
        action = str(action or "").strip().lower()
        action = {"ignored": "ignore", "trust": "known", "mine": "known", "forget": "new", "unreview": "new"}.get(action, action)
        if not mac:
            raise ValueError("mac must be a hardware address like 00:00:5e:00:53:01")
        if action not in ACTIONS:
            raise ValueError("action must be known, ignore or new")
        name = clean_name(name) if name else None
        with self.lock:
            devs = self.data["devices"]
            d = devs.get(mac)
            if d is None:
                d = devs[mac] = {"private_mac": is_private_mac(mac), "added_by_review": True}
            if action == "new":
                d.pop("status", None)
            else:
                d["status"] = action
                d["reviewed_at"] = int(time.time())
            if name:
                d["name"] = name
            self.alerts.pop(mac, None)
            self._save()
            out = {"mac": mac, "status": d.get("status") or "new", "name": d.get("name"), "ip": d.get("ip")}
        if action != "new":
            try:
                self.ha("POST", "/services/persistent_notification/dismiss",
                        {"notification_id": "hark_gateway_new_" + mac.replace(":", "")})
            except Exception:
                pass
            if self.phone:
                try:
                    self.ha("POST", f"/services/notify/{self.phone}",
                            {"message": "clear_notification", "data": {"tag": "hark_gw_dev_" + mac.replace(":", "")}})
                except Exception:
                    pass
        self._audit("device_review", mac, f"marked {out['status']}{' as ' + name if name else ''} (via {via})")
        self.publish(None)
        return out

    def on_event(self, etype, data, ev=None):
        """Home Assistant events: the review event, and phone button taps. Returns True when it was ours."""
        if not isinstance(data, dict):
            return False
        if etype == REVIEW_EVENT:
            try:
                self.review(data.get("mac"), data.get("action"), data.get("name"), via="Home Assistant event")
            except ValueError as e:
                print("inventory: review event ignored:", e)
            return True
        if etype == PHONE_ACTION_EVENT:
            m = PHONE_ACTION_RE.match(str(data.get("action") or ""))
            if not m:
                return False
            user = str(((ev or {}).get("context") or {}).get("user_id") or "")
            if self.phone_user and user != self.phone_user:
                print("inventory: phone tap ignored (came from a different Home Assistant user)")
                return True
            self.review(m.group(2), m.group(1).lower(), via="phone")
            return True
        return False

    def publish(self, online):
        with self.lock:
            devs = self.data["devices"]
            day = time.time() - 86400
            recent = sorted(((m, d) for m, d in devs.items()
                             if d.get("new") and d.get("first_seen", 0) > day and d.get("status") not in ("known", "ignore")),
                            key=lambda x: -x[1]["first_seen"])[:10]
            total = len(devs)
            if online is None:
                online = getattr(self, "_online", None)
            self._online = online
        attrs = {"friendly_name": "Network devices (Hark Gateway)", "icon": "mdi:lan", "unit_of_measurement": "devices",
                 "seen_last_scan": online, "new_last_24h": len(recent),
                 "latest_new": [{"mac": m, "ip": d.get("ip"), "hostname": d.get("hostname"), "guess": d.get("guess"),
                                 "maker": d.get("maker"),
                                 "first_seen": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(d["first_seen"]))}
                                for m, d in recent[:5]],
                 "source": self.last_source, "last_scan": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "last_error": self.last_error}
        try:
            self.ha("POST", "/states/" + SENSOR, {"state": total, "attributes": attrs})
        except Exception as e:
            print("inventory: sensor failed", e)

    def report(self, match="", new_only=False, limit=200):
        with self.lock:
            rows = [dict(mac=m, **d) for m, d in self.data["devices"].items()]
        if match:
            ml = match.lower()
            rows = [r for r in rows if ml in r["mac"] or ml in str(r.get("ip")) or
                    any(ml in str(r.get(k) or "").lower() for k in ("hostname", "name", "seen_name", "maker", "guess"))]
        if new_only:
            rows = [r for r in rows if r.get("new") and r.get("status") not in ("known", "ignore")]
        rows.sort(key=lambda r: -r.get("last_seen", 0))
        return {"count": len(rows), "baseline_done": self.data.get("baseline_done"), "last_scan": self.last_scan,
                "source": self.last_source, "last_error": self.last_error, "devices": rows[:limit]}

    def run_forever(self, active=lambda: True):
        """active(): False while the kill switch is off; background scans, closer looks and re-checks pause too."""
        self.active = active
        self.background = True
        every = max(5, min(int(self.opts.get("inventory_every_min") or 15), 240)) * 60
        time.sleep(30)
        while True:
            try:
                if active():
                    self.scan()
            except Exception as e:
                self.last_error = str(e)[:200]
                print("inventory: scan error", e)
            time.sleep(every)

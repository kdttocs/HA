"""Internet health sensors (2.0.0). Stdlib only. Read-only.

Every health_every_min minutes:
  binary_sensor.hark_gateway_internet         on = the internet answers (router's WAN status when a router is set up,
                                              otherwise "public resolvers answer")
  sensor.hark_gateway_internet_latency        average round trip to the public test addresses (ms)
  sensor.hark_gateway_internet_packet_loss    % of test pings lost
  sensor.hark_gateway_router_latency          round trip to your router (ms)
Once a day at speedtest_time (local time, if speedtest_daily is on):
  sensor.hark_gateway_download_speed          Mbit/s from the fixed Cloudflare test endpoint (same rules and daily cap as
                                              the speedtest tool)
Events: hark_gateway_internet_down / hark_gateway_internet_up when the state changes (with how long it was down).
Only fixed public test addresses are used (well-known DNS resolvers); nothing else on the internet is contacted.
"""
import json, os, re, shutil, socket, subprocess, threading, time

DATA_DIR = os.environ.get("DATA_DIR", "/data")
FILE = os.path.join(DATA_DIR, "health.json")
DEFAULT_TARGETS = ["1.1.1.1", "8.8.8.8"]


def ping(ip, count=3, timeout=2):
    """(samples_ms list with None for losses). ICMP via busybox ping, else TCP connect to 53/443."""
    out = []
    if shutil.which("ping"):
        try:
            r = subprocess.run(["ping", "-c", str(count), "-W", str(timeout), "--", ip], capture_output=True, text=True,
                               timeout=count * (timeout + 1) + 5)
            got = [float(x) for x in re.findall(r"time=([\d.]+) ?ms", r.stdout)]
            if got:
                return got + [None] * (count - len(got))
        except Exception:
            pass
    for _ in range(count):
        t0 = time.time()
        ok = False
        for port in (443, 53):
            try:
                with socket.create_connection((ip, port), timeout=timeout):
                    ok = True
                    break
            except Exception:
                continue
        out.append(round((time.time() - t0) * 1000, 1) if ok else None)
    return out


class Health:
    def __init__(self, opts, ha, router_fn, gateway_fn, speedtest_fn, public_ok, now=time.time):
        self.opts, self.ha, self.router_fn, self.gateway_fn = opts, ha, router_fn, gateway_fn
        self.speedtest_fn, self.now = speedtest_fn, now
        t = [x.strip() for x in str(opts.get("health_targets") or "").split(",") if x.strip()]
        bad = [x for x in t if x not in public_ok]
        if bad:
            print("health: ignoring targets that are not on the fixed public list:", ", ".join(bad))
        self.targets = [x for x in t if x in public_ok][:4] or DEFAULT_TARGETS
        self.state = self._load()
        self.lock = threading.Lock()

    def _load(self):
        try:
            return json.load(open(FILE))
        except Exception:
            return {}

    def _save(self):
        try:
            fd = os.open(FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(self.state, f)
        except Exception as e:
            print("health: save failed", e)

    def check(self):
        samples = []
        for t in self.targets:
            samples += ping(t)
        got = [x for x in samples if x is not None]
        loss = round(100 * (len(samples) - len(got)) / max(len(samples), 1), 1)
        lat = round(sum(got) / len(got), 1) if got else None
        gw, gw_lat = self.gateway_fn(), None
        if gw:
            g = [x for x in ping(gw, 2) if x is not None]
            gw_lat = round(sum(g) / len(g), 1) if g else None
        wan, src = None, "public test addresses"
        try:
            r = self.router_fn()
            if r is not None:
                w = r.wan()
                if w.get("up") is not None:
                    wan, src = bool(w["up"]), f"{r.kind} WAN status"
        except Exception as e:
            self.state["router_error"] = str(e)[:150]
        up = wan if wan is not None else bool(got)
        if wan is True and not got:
            up, src = False, "router says WAN is up, but nothing on the internet answers"
        res = {"up": up, "source": src, "latency_ms": lat, "loss_pct": loss, "router_latency_ms": gw_lat,
               "checked_at": int(self.now()), "targets": self.targets}
        with self.lock:
            prev = self.state.get("up")
            if prev is not None and prev != up:
                if not up:
                    self.state["down_since"] = int(self.now())
                    self._event("hark_gateway_internet_down", {"source": src})
                else:
                    since = self.state.pop("down_since", None)
                    self._event("hark_gateway_internet_up", {"down_seconds": int(self.now() - since) if since else None})
            self.state.update(res)
            self._save()
        self.publish()
        return res

    def _event(self, name, data):
        try:
            self.ha("POST", "/events/" + name, data)
        except Exception as e:
            print("health: event failed", e)

    def _state(self, eid, state, attrs):
        try:
            self.ha("POST", "/states/" + eid, {"state": state, "attributes": attrs})
        except Exception as e:
            print("health: sensor failed", eid, e)

    def publish(self):
        s = self.state
        self._state("binary_sensor.hark_gateway_internet", "on" if s.get("up") else "off",
                    {"friendly_name": "Internet", "device_class": "connectivity", "source": s.get("source"),
                     "down_since": s.get("down_since")})
        common = {"state_class": "measurement"}
        self._state("sensor.hark_gateway_internet_latency", s.get("latency_ms") if s.get("latency_ms") is not None else "unknown",
                    dict(common, friendly_name="Internet latency", unit_of_measurement="ms", icon="mdi:timer-outline"))
        self._state("sensor.hark_gateway_internet_packet_loss", s.get("loss_pct", "unknown"),
                    dict(common, friendly_name="Internet packet loss", unit_of_measurement="%", icon="mdi:lan-disconnect"))
        self._state("sensor.hark_gateway_router_latency", s.get("router_latency_ms") if s.get("router_latency_ms") is not None else "unknown",
                    dict(common, friendly_name="Router latency", unit_of_measurement="ms", icon="mdi:router-network"))
        if s.get("speed_mbps") is not None:
            self._state("sensor.hark_gateway_download_speed", s["speed_mbps"],
                        dict(common, friendly_name="Internet download speed", unit_of_measurement="Mbit/s",
                             device_class="data_rate", icon="mdi:speedometer", tested_at=s.get("speed_at")))

    def speed_due(self, lt=None):
        if not self.opts.get("speedtest_daily", True):
            return False
        lt = lt or time.localtime(self.now())
        m = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", str(self.opts.get("speedtest_time") or "03:30").strip())
        hh, mm = (int(m.group(1)), int(m.group(2))) if m else (3, 30)
        today = time.strftime("%Y-%m-%d", lt)
        mins = lt.tm_hour * 60 + lt.tm_min
        return self.state.get("speed_date") != today and 0 <= mins - (hh * 60 + mm) < 180

    def speedtest(self):
        lt = time.localtime(self.now())
        self.state["speed_date"] = time.strftime("%Y-%m-%d", lt)
        try:
            r = self.speedtest_fn()
            self.state.update(speed_mbps=r.get("mbps"), speed_at=time.strftime("%Y-%m-%dT%H:%M:%S%z", lt))
            print("health: speed test", r.get("mbps"), "Mbit/s")
        except Exception as e:
            self.state["speed_error"] = str(e)[:150]
            print("health: speed test skipped:", e)
        self._save()
        self.publish()

    def report(self, check_now=False):
        if check_now:
            self.check()
        return {k: self.state.get(k) for k in ("up", "source", "latency_ms", "loss_pct", "router_latency_ms", "checked_at",
                                               "down_since", "speed_mbps", "speed_at", "targets", "router_error")}

    def run_forever(self, active=lambda: True):
        """active(): False while the kill switch is off; checks pause too."""
        every = max(1, min(int(self.opts.get("health_every_min") or 5), 60)) * 60
        time.sleep(20)
        last = 0
        while True:
            try:
                if not active():
                    time.sleep(30); continue
                if time.time() - last >= every:
                    last = time.time()
                    self.check()
                if self.speed_due():
                    self.speedtest()
            except Exception as e:
                print("health: error", e)
            time.sleep(30)

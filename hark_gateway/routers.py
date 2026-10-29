"""Router adapters behind the `firewall` tool (2.0.0). Stdlib only.

One adapter per router family, all with the same shape:
  call(op)      - one raw API call (read when method is GET, otherwise a change that needs the owner's approval)
  leases()/arp()/wan()/firmware() - normalized read-only summaries used by the inventory, health and check-up features
  snapshot(ops) - a backup taken BEFORE any change (the change is refused if this fails)
  restore(rec)  - put a backup back (the `undo`, itself a change that needs approval)

Families:
  opnsense - REST API, key + secret as HTTP Basic, https://<host>/api/<module>/<controller>/<command>.
             Backup = the newest config-history revision id + a full copy of config.xml kept in /data.
             Undo   = POST core/backup/revertBackup/<revision> (OPNsense does not restart services after a revert).
  pfsense  - pfSense REST API package v2 (pfrest), X-API-Key header (or local user + password as Basic).
             Backup = the current state of the object being changed (+ the newest config-history revision as a
             pointer for a manual restore). Undo = the opposite call (put the old object back / delete what was
             created / re-create what was deleted), then firewall/apply for firewall paths.
  openwrt  - ubus JSON-RPC at /ubus (rpcd), session login with a router user + password.
             Backup = every UCI config file as JSON. Undo = rewrite the UCI sections that differ, then commit.
             GET may only call the read-only ubus methods listed in OPENWRT_READ; everything else is a change.
  unifi    - UniFi Network application (UniFi OS consoles, or a classic controller), local user + password.
             Backup/undo like pfSense, on rest/<object>/<id>.
Only ever talks to the one router host (router_host option, or the network's default gateway). Credentials never
appear in results, logs or the audit trail.
"""
import base64, hashlib, http.client, json, os, re, secrets, socket, ssl, threading, time, urllib.parse

DATA_DIR = os.environ.get("DATA_DIR", "/data")
BACKUP_DIR = os.path.join(DATA_DIR, "router_backups")
BACKUP_KEEP = 30
MAX_BODY = 4 * 1024 * 1024
KINDS = ("opnsense", "pfsense", "openwrt", "unifi")
OPENWRT_READ = {"system/board", "system/info", "luci-rpc/getDHCPLeases", "luci-rpc/getHostHints",
                "luci-rpc/getNetworkDevices", "luci-rpc/getWirelessDevices", "network.interface/dump",
                "network.interface.wan/status", "network.interface.wan6/status", "network.interface.lan/status",
                "network.device/status", "uci/get", "uci/configs", "iwinfo/devices", "luci/getVersion"}


def _vendor(v):
    """Maker name some routers attach to a lease (OPNsense 'mac_info'/'man', UniFi 'oui'); text only, short."""
    v = v.get("vendor") or v.get("name") if isinstance(v, dict) else v
    v = str(v or "").strip()
    return v[:80] if v and v.lower() not in ("unknown", "none", "n/a", "-") else None


class RouterError(Exception):
    pass


class BackupError(RouterError):
    pass


def _ok_value(v):
    return isinstance(v, (str, int, float, bool)) and len(str(v)) <= 200


# ---------------- configuration ----------------
def config(opts):
    """Router settings from the app options. Old option names (opnsense_host/key/secret) keep working."""
    o = opts or {}
    kind = str(o.get("router_type") or "").strip().lower()
    user = str(o.get("router_user") or "").strip()
    pw = str(o.get("router_password") or "")
    host = str(o.get("router_host") or "").strip()
    if kind in ("", "opnsense"):
        user = user or str(o.get("opnsense_key") or "").strip()
        pw = pw or str(o.get("opnsense_secret") or "")
        host = host or str(o.get("opnsense_host") or "").strip()
        if not kind and user and pw:
            kind = "opnsense"
    if kind in ("", "none"):
        kind = "none"
    try:
        port = int(o.get("router_port") or 0)
    except (TypeError, ValueError):
        port = 0
    scheme = "http" if str(o.get("router_scheme") or "").lower() == "http" else "https"
    pin = re.sub(r"[^0-9a-f]", "", str(o.get("router_cert_sha256") or "").lower())
    return {"kind": kind, "host": host, "user": user, "password": pw, "port": port, "scheme": scheme,
            "site": str(o.get("router_site") or "default").strip() or "default", "pin": pin if len(pin) == 64 else ""}


def configured(opts):
    c = config(opts)
    if c["kind"] not in KINDS:
        return False
    if c["kind"] == "pfsense":
        return bool(c["password"])                    # API key alone, or user + password
    return bool(c["user"] and c["password"])


def describe(opts):
    c = config(opts)
    return {"type": c["kind"], "configured": configured(opts), "host_set": bool(c["host"]), "scheme": c["scheme"],
            "cert_pinned": bool(c["pin"])}


# ---------------- HTTP to the one router (pinned address, optional certificate pin) ----------------
class Transport:
    """Talks to the already-checked router IP. Self-signed certificates are normal on home routers; set the
    router_cert_sha256 option to require one exact certificate (checked BEFORE any password is sent)."""

    def __init__(self, ip, port, scheme="https", pin="", timeout=20, hostname=None):
        self.ip, self.port, self.scheme, self.pin, self.timeout = ip, port, scheme, pin, timeout
        self.hostname = hostname or ip
        self.seen_cert = None

    def request(self, method, path, body=None, headers=None):
        import tools
        hp = f"[{self.ip}]" if ":" in self.ip else self.ip
        if self.scheme == "https":
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            conn = tools._PinnedHTTPS(hp if self.hostname == self.ip else self.hostname, self.ip, self.port, self.timeout, ctx)
            conn.connect()
            der = conn.sock.getpeercert(binary_form=True) or b""
            self.seen_cert = hashlib.sha256(der).hexdigest()
            if self.pin and self.seen_cert != self.pin:
                conn.close()
                raise RouterError("the router's certificate does not match router_cert_sha256; nothing was sent")
        else:
            conn = tools._PinnedHTTP(hp, self.ip, self.port, self.timeout)
        data = None
        h = {"User-Agent": "hark-gateway/2.0", "Accept": "application/json"}
        h.update(headers or {})
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            h.setdefault("Content-Type", "application/json")
        try:
            conn.request(method, path, body=data, headers=h)
            r = conn.getresponse()
            raw = r.read(MAX_BODY + 1)
            if len(raw) > MAX_BODY:
                raise RouterError("router answer too large")
            return r.status, {k.lower(): v for k, v in r.getheaders()}, raw, r.getheader("Set-Cookie") and [
                v for k, v in r.getheaders() if k.lower() == "set-cookie"]
        except (OSError, http.client.HTTPException) as e:
            raise RouterError(f"router not reachable: {e}")
        finally:
            conn.close()


def _json(raw):
    try:
        return json.loads(raw or b"null")
    except ValueError:
        return None


# ---------------- base ----------------
class Router:
    kind = ""
    default_port = 443
    snapshot_kind = "none"

    def __init__(self, cfg, ip, transport=None):
        self.cfg, self.ip = cfg, ip
        self.use_helper = transport is None and not cfg.get("pin")
        self.t = transport or Transport(ip, cfg.get("port") or self.default_port, cfg.get("scheme", "https"), cfg.get("pin", ""))

    # raw API call: op = {"method", "path", "query", "body"} ; returns {"status", "json"|"body"}
    def call(self, op):
        raise NotImplementedError

    def check_op(self, op):
        """Validates an op; raises RouterError. Separate from call() so a change is checked before the backup."""
        return op

    def leases(self):
        return []

    def arp(self):
        return []

    def wan(self):
        return {"up": None, "detail": "not available for this router type"}

    def firmware(self):
        return {"update_available": None, "detail": "not available for this router type"}

    def cert(self):
        """SHA-256 fingerprint of the certificate the router presents (no login is sent)."""
        if self.t.scheme != "https":
            return {"sha256": None, "note": "router_scheme is http (no certificate)"}
        err = None
        try:
            self.t.request("HEAD", "/")
        except RouterError as e:
            err = str(e)
        return {"sha256": self.t.seen_cert, "pinned": bool(self.t.pin),
                "matches_pin": (self.t.seen_cert == self.t.pin) if self.t.pin else None, "error": err}

    def snapshot(self, ops):
        raise BackupError("this router type has no backup method")

    def after(self, rec, ops, results):
        return rec

    def restore(self, rec):
        raise RouterError("this backup can't be put back automatically")

    @staticmethod
    def _out(status, raw):
        j = _json(raw)
        return {"status": status, "json": j} if j is not None else {"status": status, "body": raw[:60000].decode(errors="replace")}

    def _need_ok(self, res, what):
        st = res.get("status") or 0
        if not (200 <= st < 300):
            raise RouterError(f"{what}: router answered HTTP {st}")
        return res.get("json")


# ---------------- OPNsense ----------------
OPN_PATH = re.compile(r"^[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-.]+){1,10}$")


class OPNsense(Router):
    kind = "opnsense"
    snapshot_kind = "opnsense_revision"

    def _auth(self):
        return {"Authorization": "Basic " + base64.b64encode(f"{self.cfg['user']}:{self.cfg['password']}".encode()).decode()}

    def check_op(self, op):
        path = str(op.get("path") or "").strip().lstrip("/")
        if path.startswith("api/"):
            path = path[4:]
        if not OPN_PATH.match(path) or ".." in path:
            raise RouterError("path must look like core/firmware/status")
        m = str(op.get("method") or "GET").upper()
        if m not in ("GET", "POST"):
            raise RouterError("the OPNsense API takes GET (read) or POST (change)")
        return {"method": m, "path": path, "body": op.get("body")}

    def call(self, op):
        op = self.check_op(op)
        if self.use_helper:     # same HTTP path as 1.x (pinned IP, no redirects, sensitive headers removed)
            import tools
            hp = f"[{self.ip}]" if ":" in self.ip else self.ip
            port = f":{self.cfg['port']}" if self.cfg.get("port") else ""
            try:
                r = dict(tools._http({"url": f"{self.cfg.get('scheme', 'https')}://{hp}{port}/api/{op['path']}",
                                  "username": self.cfg["user"], "password": self.cfg["password"],
                                  "body": op["body"] if op["method"] == "POST" else None, "timeout": 20,
                                  "max_bytes": 200000, "headers": {"Accept": "application/json"}}, op["method"]))
            except tools.ToolError as e:
                raise RouterError(str(e))
            try:
                r["json"] = json.loads(r.pop("body"))
            except Exception:
                pass
            return r
        st, _, raw, _ = self.t.request(op["method"], "/api/" + op["path"],
                                       op["body"] if op["method"] == "POST" else None, self._auth())
        return self._out(st, raw)

    def _get(self, path):
        return self.call({"method": "GET", "path": path})

    def leases(self):
        out = []
        for path, ip_k, mac_k in (("dhcpv4/leases/searchLease", "address", "mac"), ("kea/leases4/search", "address", "hwaddr"),
                                  ("dnsmasq/leases/search", "address", "hwaddr")):
            try:
                r = self._get(path)
            except RouterError:
                continue
            rows = (r.get("json") or {}).get("rows") if isinstance(r.get("json"), dict) else None
            if r.get("status") == 200 and isinstance(rows, list):
                for x in rows:
                    if isinstance(x, dict) and x.get(mac_k):
                        out.append({"ip": x.get(ip_k), "mac": str(x[mac_k]).lower(), "hostname": x.get("hostname") or x.get("client_hostname"),
                                    "vendor": _vendor(x.get("mac_info") or x.get("man") or x.get("vendor")), "source": "dhcp"})
                if out:
                    break
        return out

    def arp(self):
        for path in ("diagnostics/interface/search_arp", "diagnostics/interface/getArp"):
            try:
                r = self._get(path)
            except RouterError:
                continue
            j = r.get("json")
            rows = j.get("rows") if isinstance(j, dict) else j
            if r.get("status") == 200 and isinstance(rows, list):
                return [{"ip": x.get("ip"), "mac": str(x.get("mac") or "").lower(), "hostname": x.get("hostname") or None,
                         "source": "arp"} for x in rows if isinstance(x, dict) and x.get("mac")]
        return []

    def wan(self):
        j = self._need_ok(self._get("routes/gateway/status"), "gateway status") or {}
        items = [x for x in (j.get("items") or []) if isinstance(x, dict)]
        gws = [{"name": x.get("name"), "status": x.get("status_translated") or x.get("status"), "delay": x.get("delay"),
                "loss": x.get("loss")} for x in items]
        up = any(str(x.get("status")).lower() in ("none", "online") or str(x.get("status_translated")).lower() == "online" for x in items)
        return {"up": up if items else None, "gateways": gws}

    def firmware(self):
        j = self._need_ok(self._get("core/firmware/status"), "firmware status") or {}
        st = str(j.get("status") or "")
        prod = j.get("product") if isinstance(j.get("product"), dict) else {}
        return {"update_available": True if st in ("update", "upgrade") else (False if st in ("none", "ok") else None),
                "status": st or None, "message": str(j.get("status_msg") or "")[:300] or None,
                "version": prod.get("product_version"), "latest": prod.get("product_latest")}

    def snapshot(self, ops):
        try:
            r = self._get("core/backup/backups/this")
            items = (r.get("json") or {}).get("items") if r.get("status") == 200 and isinstance(r.get("json"), dict) else None
            if not items or not isinstance(items[0], dict) or not items[0].get("id"):
                raise BackupError("the router's configuration history is empty or unreadable")
            rev = str(items[0]["id"])
            st, _, raw, _ = self.t.request("GET", "/api/core/backup/download/this", None, self._auth())
            if st != 200 or b"<opnsense" not in raw[:4096]:
                raise BackupError(f"config download answered HTTP {st}")
        except RouterError as e:
            raise BackupError(f"could not back up the OPNsense configuration first: {e}")
        return {"kind": self.snapshot_kind, "revision": rev, "config_xml": raw.decode(errors="replace")}

    def restore(self, rec):
        rev = str(rec.get("revision") or "")
        if not re.fullmatch(r"[A-Za-z0-9_.\-]{1,80}", rev):
            raise RouterError("backup has no usable revision id")
        r = self.call({"method": "POST", "path": "core/backup/revertBackup/" + rev})
        self._need_ok(r, "revert")
        return {"reverted_to": rev, "result": r.get("json"),
                "note": "OPNsense restores the settings but does not restart services; reboot the router or apply the "
                        "affected pages for a clean state."}


# ---------------- REST-object routers (pfSense, UniFi): backup = old object, undo = opposite call ----------------
class RestRouter(Router):
    snapshot_kind = "rest_inverse"
    id_key = "id"

    def _id_of(self, op):
        b = op.get("body") if isinstance(op.get("body"), dict) else {}
        q = op.get("query") or {}
        return b.get(self.id_key, q.get(self.id_key))

    def _object(self, op):
        """Current state of the object an op would touch (None when it creates something new)."""
        raise NotImplementedError

    def _created_id(self, result):
        j = result.get("json") if isinstance(result, dict) else None
        d = j.get("data") if isinstance(j, dict) else None
        if isinstance(d, list) and d:
            d = d[0]
        return d.get(self.id_key) if isinstance(d, dict) else None

    def snapshot(self, ops):
        inv = []
        for op in ops:
            op = self.check_op(op)
            m = op["method"]
            if m in ("PUT", "PATCH", "DELETE"):
                try:
                    old = self._object(op)
                except RouterError as e:
                    raise BackupError(f"could not read the current settings before the change: {e}")
                if old is None:
                    raise BackupError("could not read the current settings before the change (object not found)")
                inv.append({"undo": "recreate" if m == "DELETE" else "put_back", "path": op["path"], "old": old})
            elif m == "POST":
                inv.append({"undo": "delete_created" if self.creates(op) else "manual", "path": op["path"]})
        return {"kind": self.snapshot_kind, "inverse": inv, "pointer": self.history_pointer()}

    def creates(self, op):
        return True

    def history_pointer(self):
        return None

    def after(self, rec, ops, results):
        for inv, res in zip(rec.get("inverse", []), results):
            if inv["undo"] == "delete_created":
                cid = self._created_id(res)
                if cid is None:
                    inv["undo"] = "manual"
                else:
                    inv["created_id"] = cid
        return rec

    def restore(self, rec):
        done, manual = [], []
        for inv in reversed(rec.get("inverse", [])):
            if inv["undo"] == "manual":
                manual.append(inv["path"]); continue
            op = self.inverse_op(inv)
            r = self.call(op)
            self._need_ok(r, f"undo {op['method']} {op['path']}")
            done.append(f"{op['method']} {op['path']}")
        self.after_restore(rec)
        out = {"undone": done}
        if manual:
            out["not_undone"] = manual
            out["note"] = "Some steps can't be reversed automatically; " + self.manual_hint(rec)
        return out

    def after_restore(self, rec):
        pass

    def manual_hint(self, rec):
        return "restore them from the router's own configuration history."


PF_PATH = re.compile(r"^[a-z0-9_]+(/[a-z0-9_]+){0,8}$")
PF_READONLY_FIELDS = {"tracker", "created_time", "updated_time", "created_by", "updated_by", "parent_id"}


def _query(q):
    if q in (None, ""):
        return {}
    if not isinstance(q, dict) or len(q) > 10:
        raise RouterError("query must be an object with up to 10 simple values")
    for k, v in q.items():
        if not re.fullmatch(r"[a-z_]{1,30}", str(k)) or not _ok_value(v):
            raise RouterError(f"query value {str(k)[:30]!r} is not allowed")
    return {str(k): v for k, v in q.items()}


class PfSense(RestRouter):
    kind = "pfsense"

    def _auth(self):
        if self.cfg.get("user"):
            return {"Authorization": "Basic " + base64.b64encode(f"{self.cfg['user']}:{self.cfg['password']}".encode()).decode()}
        return {"X-API-Key": self.cfg["password"]}

    def check_op(self, op):
        path = str(op.get("path") or "").strip().strip("/")
        if path.startswith("api/v2/"):
            path = path[7:]
        if not PF_PATH.match(path):
            raise RouterError("path must look like firewall/rules (pfSense REST API v2)")
        m = str(op.get("method") or "GET").upper()
        if m not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
            raise RouterError("method must be GET, POST, PUT, PATCH or DELETE")
        body = op.get("body")
        if body is not None and not isinstance(body, (dict, list)):
            raise RouterError("body must be JSON")
        return {"method": m, "path": path, "query": _query(op.get("query")), "body": body}

    def call(self, op):
        op = self.check_op(op)
        q = ("?" + urllib.parse.urlencode(op["query"])) if op["query"] else ""
        st, _, raw, _ = self.t.request(op["method"], "/api/v2/" + op["path"] + q,
                                       op["body"] if op["method"] != "GET" else None, self._auth())
        return self._out(st, raw)

    def _data(self, path, query=None):
        j = self._need_ok(self.call({"method": "GET", "path": path, "query": query}), path) or {}
        return j.get("data") if isinstance(j, dict) else None

    def _object(self, op):
        oid = self._id_of(op)
        if oid is None:
            raise RouterError("changing or deleting needs the object's id in body or query")
        d = self._data(op["path"], {"id": oid})
        if isinstance(d, list):
            d = d[0] if d else None
        return d

    def creates(self, op):
        return not (op["path"].endswith("/apply") or op["path"].startswith(("diagnostics/", "status/")))

    def history_pointer(self):
        try:
            d = self._data("diagnostics/config_history/revisions", {"limit": 1})
            if isinstance(d, list) and d and isinstance(d[0], dict):
                return {k: d[0].get(k) for k in ("time", "description", "id") if k in d[0]}
        except RouterError:
            pass
        return None

    def inverse_op(self, inv):
        if inv["undo"] == "delete_created":
            return {"method": "DELETE", "path": inv["path"], "query": {"id": inv["created_id"]}}
        old = {k: v for k, v in (inv["old"] or {}).items() if k not in PF_READONLY_FIELDS}
        if inv["undo"] == "recreate":
            old.pop("id", None)
            return {"method": "POST", "path": inv["path"], "body": old}
        return {"method": "PATCH", "path": inv["path"], "body": old}

    def after_restore(self, rec):
        if any(i["path"].startswith("firewall/") for i in rec.get("inverse", [])):
            try:
                self.call({"method": "POST", "path": "firewall/apply"})
            except RouterError:
                pass

    def manual_hint(self, rec):
        p = rec.get("pointer") or {}
        when = f" (the revision from {p.get('time')})" if p.get("time") else ""
        return f"restore the configuration from Diagnostics > Backup & Restore > Config History{when}."

    def leases(self):
        d = self._data("status/dhcp_server/leases") or []
        return [{"ip": x.get("ip"), "mac": str(x.get("mac") or "").lower(), "hostname": x.get("hostname") or None, "source": "dhcp"}
                for x in d if isinstance(x, dict) and x.get("mac")]

    def arp(self):
        d = self._data("diagnostics/arp_table") or []
        return [{"ip": x.get("ip_address"), "mac": str(x.get("mac_address") or "").lower(), "hostname": x.get("hostname") or None,
                 "source": "arp"} for x in d if isinstance(x, dict) and x.get("mac_address")]

    def wan(self):
        d = [x for x in (self._data("status/gateways") or []) if isinstance(x, dict)]
        gws = [{"name": x.get("name"), "status": x.get("status"), "delay": x.get("delay"), "loss": x.get("loss")} for x in d]
        return {"up": any(str(x.get("status")).lower() in ("online", "none") for x in d) if d else None, "gateways": gws}

    def firmware(self):
        d = self._data("system/version") or {}
        return {"update_available": None, "version": d.get("version") if isinstance(d, dict) else None,
                "detail": "pfSense reports its version; check System > Update for new releases"}


UNIFI_PATH = re.compile(r"^[a-z0-9_]+(/[A-Za-z0-9_]+){0,4}$")
UNIFI_READONLY_FIELDS = {"site_id", "attr_hidden_id", "attr_no_delete", "attr_hidden", "attr_no_edit"}


class UniFi(RestRouter):
    kind = "unifi"
    id_key = "_id"

    def __init__(self, cfg, ip, transport=None):
        super().__init__(cfg, ip, transport)
        self._session = None    # (prefix, headers)
        self._lock = threading.Lock()

    def _login(self):
        if self._session and time.time() - self._session[2] < 600:
            return self._session
        body = {"username": self.cfg["user"], "password": self.cfg["password"]}
        for path, prefix in (("/api/auth/login", "/proxy/network"), ("/api/login", "")):
            st, h, raw, cookies = self.t.request("POST", path, body)
            if st == 200:
                jar = "; ".join(c.split(";", 1)[0] for c in (cookies or []))
                hdr = {"Cookie": jar}
                csrf = h.get("x-csrf-token") or h.get("x-updated-csrf-token")
                if not csrf:
                    m = re.search(r"csrf_token=([^;\s]+)", " ".join(cookies or []))
                    csrf = m.group(1) if m else None
                if csrf:
                    hdr["X-CSRF-Token"] = csrf
                self._session = (prefix, hdr, time.time())
                return self._session
            if st in (401, 403):
                raise RouterError("UniFi login refused (check router_user / router_password; use a local account)")
        raise RouterError("could not log in to the UniFi Network application")

    def check_op(self, op):
        path = str(op.get("path") or "").strip().strip("/")
        if not UNIFI_PATH.match(path):
            raise RouterError("path must look like stat/sta or rest/firewallrule/<id>")
        m = str(op.get("method") or "GET").upper()
        if m not in ("GET", "POST", "PUT", "DELETE"):
            raise RouterError("method must be GET, POST, PUT or DELETE")
        body = op.get("body")
        if body is not None and not isinstance(body, (dict, list)):
            raise RouterError("body must be JSON")
        return {"method": m, "path": path, "query": {}, "body": body}

    def call(self, op):
        op = self.check_op(op)
        with self._lock:
            prefix, hdr, _ = self._login()
        site = re.sub(r"[^A-Za-z0-9_-]", "", self.cfg.get("site") or "default") or "default"
        st, _, raw, _ = self.t.request(op["method"], f"{prefix}/api/s/{site}/{op['path']}",
                                       op["body"] if op["method"] != "GET" else None, hdr)
        if st == 401:
            self._session = None
        return self._out(st, raw)

    def _data(self, path):
        j = self._need_ok(self.call({"method": "GET", "path": path}), path) or {}
        return j.get("data") if isinstance(j, dict) else None

    def _id_of(self, op):
        parts = op["path"].split("/")
        return parts[2] if len(parts) >= 3 and parts[0] == "rest" else None

    def _object(self, op):
        if not self._id_of(op):
            raise RouterError("changing or deleting needs a path like rest/<object>/<id>")
        d = self._data(op["path"])
        return d[0] if isinstance(d, list) and d else None

    def creates(self, op):
        return op["path"].startswith("rest/") and len(op["path"].split("/")) == 2

    def inverse_op(self, inv):
        if inv["undo"] == "delete_created":
            return {"method": "DELETE", "path": inv["path"] + "/" + str(inv["created_id"])}
        old = {k: v for k, v in (inv["old"] or {}).items() if k not in UNIFI_READONLY_FIELDS}
        if inv["undo"] == "recreate":
            old.pop("_id", None)
            return {"method": "POST", "path": "/".join(inv["path"].split("/")[:2]), "body": old}
        return {"method": "PUT", "path": inv["path"], "body": old}

    def manual_hint(self, rec):
        return "use UniFi's own automatic backups (Settings > System > Backups) to roll back."

    def leases(self):
        d = self._data("stat/sta") or []
        return [{"ip": x.get("ip"), "mac": str(x.get("mac") or "").lower(), "hostname": x.get("hostname") or x.get("name"),
                 "vendor": _vendor(x.get("oui")), "source": "unifi"} for x in d if isinstance(x, dict) and x.get("mac")]

    def wan(self):
        d = [x for x in (self._data("stat/health") or []) if isinstance(x, dict)]
        sub = {x.get("subsystem"): x for x in d}
        w, www = sub.get("wan") or {}, sub.get("www") or {}
        st = w.get("status") or www.get("status")
        return {"up": (str(st).lower() == "ok") if st else None, "latency_ms": www.get("latency"),
                "download_mbps": www.get("xput_down"), "upload_mbps": www.get("xput_up")}

    def firmware(self):
        d = [x for x in (self._data("stat/device") or []) if isinstance(x, dict)]
        devs = [{"name": x.get("name") or x.get("model"), "model": x.get("model"), "version": x.get("version"),
                 "upgradable": bool(x.get("upgradable")), "upgrade_to": x.get("upgrade_to_firmware")} for x in d]
        return {"update_available": any(x["upgradable"] for x in devs) if devs else None, "devices": devs}


# ---------------- OpenWrt (ubus JSON-RPC) ----------------
UBUS_NAME = re.compile(r"^[a-z0-9_.\-]{1,40}$")
NULL_SESSION = "0" * 32


class OpenWrt(Router):
    kind = "openwrt"
    snapshot_kind = "uci_snapshot"

    def __init__(self, cfg, ip, transport=None):
        super().__init__(cfg, ip, transport)
        self._sid = None
        self._lock = threading.Lock()
        self._id = 0

    def _rpc(self, sid, obj, method, args):
        self._id += 1
        st, _, raw, _ = self.t.request("POST", "/ubus", {"jsonrpc": "2.0", "id": self._id, "method": "call",
                                                         "params": [sid, obj, method, args or {}]})
        j = _json(raw)
        if st != 200 or not isinstance(j, dict):
            raise RouterError(f"ubus answered HTTP {st}")
        if j.get("error"):
            raise RouterError(f"ubus error: {str(j['error'].get('message') if isinstance(j['error'], dict) else j['error'])[:120]}")
        res = j.get("result") or []
        code = res[0] if res else -1
        if code != 0:
            raise RouterError(f"ubus {obj} {method} failed (code {code}; 6 = not allowed for this router user)")
        return res[1] if len(res) > 1 else {}

    def _session(self):
        with self._lock:
            if self._sid and time.time() - self._sid[1] < 240:
                return self._sid[0]
            r = self._rpc(NULL_SESSION, "session", "login", {"username": self.cfg["user"], "password": self.cfg["password"]})
            sid = (r or {}).get("ubus_rpc_session")
            if not sid:
                raise RouterError("OpenWrt login refused")
            self._sid = (sid, time.time())
            return sid

    def check_op(self, op):
        m = str(op.get("method") or "GET").upper()
        if m not in ("GET", "POST"):
            raise RouterError("OpenWrt calls take GET (read-only list) or POST (change)")
        calls = op.get("calls")
        if calls is None:
            path = str(op.get("path") or "").strip().strip("/")
            if "/" not in path:
                raise RouterError("path must look like system/board (ubus object/method)")
            obj, meth = path.rsplit("/", 1)
            calls = [[obj, meth, op.get("body") or {}]]
        if not isinstance(calls, list) or not 1 <= len(calls) <= 20:
            raise RouterError("calls must be a list of 1-20 [object, method, args]")
        out = []
        for c in calls:
            if not (isinstance(c, list) and len(c) in (2, 3)) or not all(UBUS_NAME.match(str(x)) for x in c[:2]):
                raise RouterError("each call must be [object, method, args]")
            args = c[2] if len(c) == 3 else {}
            if not isinstance(args, dict):
                raise RouterError("ubus args must be an object")
            if c[0] == "session":
                raise RouterError("session calls are not allowed")
            if m == "GET" and f"{c[0]}/{c[1]}" not in OPENWRT_READ:
                raise RouterError(f"{c[0]} {c[1]} is not on the read-only list; it needs method POST (a change you approve)")
            out.append([str(c[0]), str(c[1]), args])
        return {"method": m, "calls": out, "path": "/".join(out[0][:2])}

    def call(self, op):
        op = self.check_op(op)
        sid = self._session()
        results = [self._rpc(sid, o, me, a) for o, me, a in op["calls"]]
        return {"status": 200, "json": results[0] if len(results) == 1 else results}

    def _r(self, obj, method, args=None):
        return self._rpc(self._session(), obj, method, args or {})

    def leases(self):
        r = self._r("luci-rpc", "getDHCPLeases") or {}
        return [{"ip": x.get("ipaddr"), "mac": str(x.get("macaddr") or "").lower(), "hostname": x.get("hostname"), "source": "dhcp"}
                for x in (r.get("dhcp_leases") or []) if isinstance(x, dict) and x.get("macaddr")]

    def arp(self):
        r = self._r("luci-rpc", "getHostHints") or {}
        return [{"ip": (v.get("ipaddrs") or [None])[0], "mac": str(k).lower(), "hostname": v.get("name"), "source": "neighbors"}
                for k, v in r.items() if isinstance(v, dict)]

    def wan(self):
        try:
            r = self._r("network.interface.wan", "status") or {}
            return {"up": bool(r.get("up")), "uptime_s": r.get("uptime")}
        except RouterError:
            d = self._r("network.interface", "dump") or {}
            for i in d.get("interface") or []:
                if i.get("interface") in ("wan", "wan6"):
                    return {"up": bool(i.get("up")), "interface": i.get("interface")}
        return {"up": None}

    def firmware(self):
        b = self._r("system", "board") or {}
        rel = b.get("release") or {}
        return {"update_available": None, "version": rel.get("version"), "revision": rel.get("revision"),
                "detail": "OpenWrt has no built-in update check; compare with openwrt.org/downloads"}

    def snapshot(self, ops):
        try:
            names = (self._r("uci", "configs") or {}).get("configs") or []
            snap = {}
            for n in names[:80]:
                if UBUS_NAME.match(str(n)):
                    snap[n] = (self._r("uci", "get", {"config": n}) or {}).get("values") or {}
        except RouterError as e:
            raise BackupError(f"could not back up the OpenWrt settings first: {e}")
        if not snap:
            raise BackupError("could not back up the OpenWrt settings first (no UCI configs readable)")
        return {"kind": self.snapshot_kind, "uci": snap}

    def restore(self, rec):
        snap = rec.get("uci") or {}
        sid = self._session()
        changed = []
        for conf, want in snap.items():
            try:
                have = (self._rpc(sid, "uci", "get", {"config": conf}) or {}).get("values") or {}
            except RouterError:
                have = {}
            if have == want:
                continue
            for sec in have:
                if sec not in want or have[sec] != want[sec]:
                    self._rpc(sid, "uci", "delete", {"config": conf, "section": sec})
            for sec, vals in want.items():
                if have.get(sec) == vals:
                    continue
                v = {k: x for k, x in vals.items() if not k.startswith(".")}
                self._rpc(sid, "uci", "add", {"config": conf, "type": vals.get(".type"), "name": sec, "values": v})
            self._rpc(sid, "uci", "commit", {"config": conf})
            changed.append(conf)
        return {"restored_configs": changed,
                "note": "Committed; OpenWrt reloads the affected services. Section order may differ from before."}


ADAPTERS = {"opnsense": OPNsense, "pfsense": PfSense, "openwrt": OpenWrt, "unifi": UniFi}


def adapter(opts, check_target, default_gateway, transport=None):
    """Builds the adapter for the configured router. check_target pins the address (home network only)."""
    c = config(opts)
    if c["kind"] not in ADAPTERS:
        raise RouterError("no router configured: set router_type (opnsense, pfsense, openwrt or unifi) and its login")
    if not configured(opts):
        raise RouterError(f"the router tool is off: set the {c['kind']} login (router_user / router_password)")
    host = c["host"] or default_gateway()
    if not host:
        raise RouterError("no router address: set router_host (the default gateway could not be found)")
    ip = check_target(host, payload=True)
    return ADAPTERS[c["kind"]](c, ip, transport)


# ---------------- local backup store (/data/router_backups, private) ----------------
_bk_lock = threading.Lock()


def _bk_path(bid):
    if not re.fullmatch(r"rb\d{14}[0-9a-f]{6}", str(bid or "")):
        raise RouterError("backup id must look like rb20260101120000abcdef")
    return os.path.join(BACKUP_DIR, bid + ".json")


def save_backup(rec, meta):
    os.makedirs(BACKUP_DIR, mode=0o700, exist_ok=True)
    bid = "rb" + time.strftime("%Y%m%d%H%M%S") + secrets.token_hex(3)
    full = dict(rec, **meta, id=bid, at=int(time.time()))
    with _bk_lock:
        fd = os.open(_bk_path(bid), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(full, f)
        files = sorted(x for x in os.listdir(BACKUP_DIR) if x.endswith(".json"))
        for old in files[:-BACKUP_KEEP]:
            try:
                os.remove(os.path.join(BACKUP_DIR, old))
            except OSError:
                pass
    return bid


def load_backup(bid):
    try:
        return json.load(open(_bk_path(bid)))
    except FileNotFoundError:
        raise RouterError(f"no backup {bid} (the app keeps the last {BACKUP_KEEP})")


def mark_undone(bid, by):
    with _bk_lock:
        p = _bk_path(bid)
        rec = json.load(open(p))
        rec["undone_at"], rec["undone_by"] = int(time.time()), by
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(rec, f)


def list_backups():
    """Summaries only; never the saved settings themselves."""
    out = []
    try:
        names = sorted((x for x in os.listdir(BACKUP_DIR) if x.endswith(".json")), reverse=True)
    except FileNotFoundError:
        return out
    for n in names:
        try:
            r = json.load(open(os.path.join(BACKUP_DIR, n)))
        except Exception:
            continue
        out.append({k: r.get(k) for k in ("id", "at", "adapter", "host", "kind", "cmd_id", "change", "undone_at", "undone_by",
                                          "undo_of") if r.get(k) is not None})
    return out

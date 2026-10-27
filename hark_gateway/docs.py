"""Full-page document printing: private Worker queue -> network printer over IPP (port 631). Stdlib only.

Finds the printer automatically: the `doc_printer_ip` option if set, else the address it found last time
(/data/doc_printer.json), else Home Assistant's IPP integration (device configuration URL), else a scan of the local
network for an IPP printer. Daily job/page caps and a document safety check (caps.py) apply to every job.

Sending (1.1.1): the printer's IPP format list (document-format-supported) is logged and kept in STATE.
- lists application/pdf          -> IPP with document-format application/pdf
- lists application/octet-stream -> IPP with application/octet-stream (printer auto-senses the PDF)
- lists neither / refuses / aborts -> raw TCP 9100 with a PJL wrapper (ENTER LANGUAGE=PDF)
A printer is never skipped for its format list (many lasers print PDF directly without listing it).
"""
import ipaddress, json, os, re, socket, struct, threading, time, urllib.request, urllib.error, urllib.parse

import caps

IPP_PORT = 631
RAW_PORT = 9100
PJL_UEL = b"\x1b%-12345X"
# What the docs loop knows about the printer; reported by the status tool and sensor.document_printer.
STATE = {"ip": None, "path": None, "model": None, "formats": [], "send_as": None, "last_method": None,
         "last_error": None, "printed": 0}
HINT_FILE = os.path.join(os.environ.get("DATA_DIR", "/data"), "doc_printer.json")


def load_hint():
    try:
        return (json.load(open(HINT_FILE)) or {}).get("ip") or None
    except Exception:
        return None


def save_hint(ip, only_if_missing=False):
    if only_if_missing and load_hint():
        return False
    try:
        fd = os.open(HINT_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"ip": ip}, f)
        return True
    except Exception as e:
        print("docs: could not save printer address", e)
        return False


def counts_today():
    return caps.today()
PATHS = ["/ipp/print", "/ipp", "/ipp/printer", "/"]

# ---------------- tiny IPP codec ----------------
T_OP, T_JOB, T_END = 0x01, 0x02, 0x03
INT, BOOL, ENUM = 0x21, 0x22, 0x23
TEXT, NAME, KEYWORD, URI, CHARSET, LANG, MIME = 0x41, 0x42, 0x44, 0x45, 0x47, 0x48, 0x49
_rid = [0]


def _attr(tag, name, value):
    if tag in (INT, ENUM):
        v = struct.pack(">i", value)
    elif tag == BOOL:
        v = b"\x01" if value else b"\x00"
    else:
        v = str(value).encode()
    n = name.encode()
    return bytes([tag]) + struct.pack(">H", len(n)) + n + struct.pack(">H", len(v)) + v


def build(op, uri, op_attrs=(), job_attrs=(), data=b""):
    _rid[0] += 1
    b = struct.pack(">HHi", 0x0101, op, _rid[0]) + bytes([T_OP])
    b += _attr(CHARSET, "attributes-charset", "utf-8") + _attr(LANG, "attributes-natural-language", "en")
    b += _attr(URI, "printer-uri", uri)
    for a in op_attrs:
        b += _attr(*a)
    if job_attrs:
        b += bytes([T_JOB])
        for a in job_attrs:
            b += _attr(*a)
    return b + bytes([T_END]) + data


def parse(buf):
    """Returns (status_code, {name: [values]}) merging all groups."""
    status = struct.unpack(">H", buf[2:4])[0]
    i, attrs, last = 8, {}, None
    while i < len(buf):
        tag = buf[i]; i += 1
        if tag == T_END:
            break
        if tag < 0x10:
            continue
        nl = struct.unpack(">H", buf[i:i + 2])[0]; i += 2
        name = buf[i:i + nl].decode(errors="replace"); i += nl
        vl = struct.unpack(">H", buf[i:i + 2])[0]; i += 2
        raw = buf[i:i + vl]; i += vl
        if tag in (INT, ENUM) and vl == 4:
            val = struct.unpack(">i", raw)[0]
        elif tag == BOOL:
            val = raw != b"\x00"
        else:
            val = raw.decode(errors="replace")
        if name:
            last = name
            attrs.setdefault(name, []).append(val)
        elif last:
            attrs[last].append(val)
    return status, attrs


def ipp(ip, path, body, timeout=30):
    req = urllib.request.Request(f"http://{ip}:{IPP_PORT}{path}", data=body, method="POST",
                                 headers={"Content-Type": "application/ipp"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return parse(r.read())


def printer_info(ip, path=None):
    """Returns (path, attrs) for the first IPP path that answers, else (None, None)."""
    for p in ([path] if path else PATHS):
        try:
            st, a = ipp(ip, p, build(0x000B, f"ipp://{ip}{p}", [(KEYWORD, "requested-attributes", "all")]), timeout=5)
            if st < 0x0100 and (a.get("printer-make-and-model") or a.get("printer-name")):
                return p, a
        except Exception:
            continue
    return None, None


# ---------------- finding the printer ----------------
def from_home_assistant(ha):
    tpl = ("{% for e in integration_entities('ipp') %}"
           "{{ device_attr(device_id(e), 'configuration_url') }}|{{ device_attr(device_id(e), 'model') }}\n"
           "{% endfor %}")
    try:
        out = ha("POST", "/template", {"template": tpl})
    except Exception as e:
        print("docs: HA template failed", e)
        return []
    hosts = []
    for line in str(out or "").splitlines():
        url = line.split("|")[0].strip()
        h = urllib.parse.urlparse(url).hostname if "://" in url else None
        if h and h not in hosts:
            hosts.append(h)
    return hosts


def scan(nets):
    hits, lock = [], threading.Lock()

    def probe(ip):
        try:
            with socket.create_connection((ip, IPP_PORT), timeout=0.6):
                pass
        except Exception:
            return
        with lock:
            hits.append(ip)

    for net in nets:
        ths = []
        for h in net.hosts():
            t = threading.Thread(target=probe, args=(str(h),), daemon=True); t.start(); ths.append(t)
            if len(ths) >= 64:
                for t in ths: t.join()
                ths = []
        for t in ths: t.join()
    return hits


def find_printer(ha, nets, want_model=""):
    cands = from_home_assistant(ha)
    hint = load_hint()        # the printer used last time, tried before a full network scan
    if hint and hint not in cands:
        cands.insert(0, hint)
    print("docs: candidates:", cands)
    tried = set()
    for group in (cands, None):
        ips = group if group is not None else [ip for ip in scan(nets) if ip not in tried]
        for ip in ips:
            tried.add(ip)
            path, a = printer_info(ip)
            if not path:
                continue
            model = (a.get("printer-make-and-model") or a.get("printer-name") or ["?"])[0]
            fmts = a.get("document-format-supported", [])
            print("docs:", ip, model, "formats:", fmts or "(not reported)", "-> send as:", send_format(fmts) or "raw 9100 (PJL PDF)")
            if want_model and want_model.lower() not in model.lower():
                continue
            if "receipt" in model.lower():
                continue
            STATE["formats"] = list(fmts); STATE["send_as"] = send_format(fmts) or "raw 9100 (PJL PDF)"
            if ip != hint:
                save_hint(ip)
            return ip, path, model
    return None, None, None


# ---------------- printing ----------------
def send_format(fmts):
    """IPP document-format to use for a PDF, or None when IPP can't take it (then raw port 9100 is used)."""
    fmts = [str(f).lower() for f in (fmts or [])]
    if not fmts or "application/pdf" in fmts:
        return "application/pdf"   # not reported: try PDF, the printer refuses cleanly if it can't
    if "application/octet-stream" in fmts:
        return "application/octet-stream"
    return None


def pjl_wrap(pdf):
    return PJL_UEL + b"@PJL\r\n@PJL ENTER LANGUAGE=PDF\r\n" + pdf + PJL_UEL


def print_raw(ip, pdf, timeout=60):
    """Raw port 9100 (JetDirect) with a PJL wrapper. The printer gives no confirmation, only that it took the bytes."""
    try:
        with socket.create_connection((ip, RAW_PORT), timeout=timeout) as s:
            s.sendall(pjl_wrap(pdf))
            try:
                s.shutdown(socket.SHUT_WR)
            except Exception:
                pass
        return "printed", f"sent to {ip}:{RAW_PORT} as PDF via PJL ({len(pdf)} bytes; printer gives no confirmation)"
    except Exception as e:
        return "retry", f"could not reach printer on port {RAW_PORT}: {e}"


JOB_STATES = {3: "pending", 4: "held", 5: "processing", 6: "stopped", 7: "canceled", 8: "aborted", 9: "completed"}


def print_pdf(ip, path, pdf, name, opts, progress=lambda s: None, fmts=None):
    """Sends the PDF and waits for the printer to finish. Returns (outcome, detail):
    outcome is 'printed', 'failed_final' (printer rejected/aborted it) or 'retry'.
    Tries IPP in the best format the printer lists, then raw port 9100 with a PJL wrapper if IPP refuses or aborts."""
    fmt = send_format(fmts)
    tried = []
    if fmt:
        order = [fmt] + (["application/octet-stream"] if fmt == "application/pdf" and fmts else [])
        for f in order:
            outcome, detail = _print_ipp(ip, path, pdf, name, opts, progress, f)
            tried.append(f"IPP {f}: {detail}")
            if outcome == "printed":
                STATE["last_method"] = f"ipp {f}"
                return outcome, detail
            if outcome == "retry" and detail.startswith("could not reach"):
                break   # IPP port down: try 9100 below, it may still answer
    outcome, detail = print_raw(ip, pdf)
    if outcome == "printed":
        STATE["last_method"] = "raw 9100 pjl"
        if tried:
            print("docs: IPP did not take it (", " | ".join(tried), "); used port 9100")
        return outcome, detail
    return outcome, " | ".join(tried + [detail])


def _print_ipp(ip, path, pdf, name, opts, progress, fmt):
    uri = f"ipp://{ip}{path}"
    job = [(INT, "copies", int(opts.get("copies") or 1))]
    if opts.get("sides"):
        job.append((KEYWORD, "sides", opts["sides"]))
    if opts.get("color"):
        job.append((KEYWORD, "print-color-mode", opts["color"]))
    ops = [(NAME, "requesting-user-name", "Hark"), (NAME, "job-name", name[:60] or "document"), (MIME, "document-format", fmt)]
    try:
        st, a = ipp(ip, path, build(0x0002, uri, ops, job, pdf), timeout=120)
        if st in (0x040B, 0x0400) and len(job) > 1:  # attributes not supported -> drop extras and retry plain
            st, a = ipp(ip, path, build(0x0002, uri, ops, job[:1], pdf), timeout=120)
    except Exception as e:
        return "retry", f"could not reach printer: {e}"
    if st >= 0x0400:
        msg = (a.get("status-message") or [""])[0]
        return ("failed_final" if st < 0x0500 else "retry"), f"printer refused job (IPP status 0x{st:04x}) {msg}".strip()
    jid = (a.get("job-id") or [None])[0]
    if not jid:
        return "printed", "sent (printer gave no job id)"
    progress(f"printer job {jid} accepted")
    end, last = time.time() + 900, None
    while time.time() < end:
        time.sleep(3)
        try:
            st, a = ipp(ip, path, build(0x0009, uri, [(INT, "job-id", jid), (KEYWORD, "requested-attributes", "all")]), timeout=10)
        except Exception:
            continue
        if st == 0x0406:  # job gone from printer history -> it finished
            return "printed", f"printer job {jid} finished"
        s = (a.get("job-state") or [None])[0]
        reasons = ",".join(x for x in a.get("job-state-reasons", []) if x != "none")
        if s != last:
            print("docs: job", jid, JOB_STATES.get(s, s), reasons); last = s
        if s == 9:
            return "printed", f"printer job {jid} completed"
        if s in (7, 8):
            return "failed_final", f"printer job {jid} {JOB_STATES[s]} {reasons}".strip()
        if s == 6 or "media-empty" in reasons or "jam" in reasons:
            progress(f"printer job {jid} waiting: {reasons or 'stopped'}")
    return "printed", f"printer job {jid} still not reported done after 15 min (likely printed)"


POLL_EVERY = 60   # safety-net check of the Worker queue; Hark's print_doc nudge (via Home Assistant) wakes it at once


def run(ha, site_cfg, nets_fn, report, opts, wake=None):
    """Loop forever: print each job on the Worker's private document queue. Checks the queue when Hark nudges it
    (the `wake` event, set by a signed print_doc command arriving through Home Assistant) and otherwise once a
    minute with one short request. No long-polls."""
    wake = wake or threading.Event()
    state = STATE
    state.update(ip=opts.get("doc_printer_ip") or load_hint(), path=None, model=None, printed=0, err=None)
    last_scan = 0

    def rep(st, **kw):
        try:
            ha("POST", "/states/sensor.document_printer", {"state": st, "attributes": {
                "friendly_name": "Document printer (Hark)", "icon": "mdi:printer", "printer_ip": state["ip"],
                "model": state["model"], "printed_since_start": state["printed"], "last_error": state["err"],
                "formats": state.get("formats") or [], "send_as": state.get("send_as"),
                "last_method": state.get("last_method"), **kw}})
        except Exception as e:
            print("docs: report failed", e)

    def site_req(path, body=None, raw=False):
        site, token = site_cfg()
        req = urllib.request.Request(site + path, method="POST" if body is not None else "GET",
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "User-Agent": "hark-gateway/docs"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
            if raw:
                return r.status, data
            return r.status, (json.loads(data) if r.status == 200 and data else None)

    last_rep = 0
    while True:
        try:
            site, token = site_cfg()
            if not token:
                time.sleep(15); continue
            if not state["ip"] or not state["path"]:
                if time.time() - last_scan < 120:
                    time.sleep(10); continue
                last_scan = time.time()
                if state["ip"]:
                    p, a = printer_info(state["ip"])
                    if p:
                        f = a.get("document-format-supported", [])
                        state.update(path=p, model=(a.get("printer-make-and-model") or ["?"])[0], formats=list(f),
                                     send_as=send_format(f) or "raw 9100 (PJL PDF)")
                        print("docs:", state["ip"], state["model"], "formats:", f or "(not reported)", "-> send as:", state["send_as"])
                if not state["path"]:
                    ip, p, m = find_printer(ha, nets_fn(), opts.get("doc_printer_model", ""))
                    state.update(ip=ip, path=p, model=m)
                if not state["path"]:
                    rep("printer not found"); state["ip"] = opts.get("doc_printer_ip") or load_hint()
                    continue
                print("docs: using", state["ip"], state["path"], state["model"], "send as:", state.get("send_as"))
                rep("ready")
            label = f"{state['model']} @ {state['ip']}"
            if not caps.docs_allowed(opts):   # daily paper guard: leave jobs waiting on the server until tomorrow
                rep("daily limit reached", today=caps.today())
                wake.clear(); wake.wait(600); continue
            # one short request (no wait): is a document queued?
            wake.clear()
            code, j = site_req("/docs/next?printer=" + urllib.parse.quote(str(state["model"] or "printer")[:80]))
            if time.time() - last_rep > 300:
                rep("ready"); last_rep = time.time()
            if code != 200 or not j:
                if wake.wait(POLL_EVERY):
                    print("docs: nudged by Hark")
                continue
            print("docs: got job", j.get("id"), j.get("name"))
            jid = j["id"]
            _, pdf = site_req(f"/docs/file/{jid}", raw=True)
            ok, why, pages = caps.check_pdf(pdf, (j.get("opts") or {}).get("copies"), opts)
            if not ok:
                print("docs:", jid, "refused:", why)
                site_req("/docs/ack", {"id": jid, "status": "failed_final", "detail": "refused by the app: " + why})
                rep("ready", last_refused=why)
                continue
            caps.add(doc_jobs=1, doc_pages=pages)
            site_req("/docs/ack", {"id": jid, "status": "printing", "detail": "sending to the printer"})
            rep("printing", job=j.get("name"))
            outcome, detail = print_pdf(state["ip"], state["path"], pdf, j.get("name") or "document", j.get("opts") or {},
                                        progress=lambda d: site_req("/docs/ack", {"id": jid, "status": "printing", "detail": d}),
                                        fmts=state.get("formats"))
            print("docs:", jid, outcome, detail)
            if outcome == "printed":
                state["printed"] += 1; state["err"] = None; state["last_error"] = None
            else:
                state["err"] = detail; state["last_error"] = detail
                if "could not reach" in detail:
                    state["path"] = None; last_scan = 0  # printer moved or is off: look again
            site_req("/docs/ack", {"id": jid, "status": outcome if outcome != "retry" else "error", "detail": detail})
            rep("ready" if outcome == "printed" else "error")
        except urllib.error.HTTPError as e:
            state["err"] = f"site HTTP {e.code}"; print("docs: site error", e); time.sleep(15)
        except Exception as e:
            state["err"] = str(e); print("docs: error", e); time.sleep(10)

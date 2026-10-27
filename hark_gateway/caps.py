"""Daily print limits (paper guard). Printing is not stopped by the kill switch, so these caps are what keeps a
runaway or abused queue from emptying the paper tray. Counts live in /data/print_counts.json and reset each day."""
import json, os, re, threading, time

FILE = os.path.join(os.environ.get("DATA_DIR", "/data"), "print_counts.json")
DEFAULTS = {"daily_doc_jobs": 50, "daily_doc_pages": 500, "max_pages_per_job": 100, "daily_receipts": 200,
            "max_doc_mb": 25}
UEL = b"\x1b%-12345X"          # printer-language escape: a document containing it could smuggle printer commands
_lock = threading.Lock()


def limit(opts, key):
    try:
        v = int((opts or {}).get(key) or DEFAULTS[key])
    except (TypeError, ValueError):
        v = DEFAULTS[key]
    return max(1, v)


def _load():
    try:
        d = json.load(open(FILE))
    except Exception:
        d = {}
    today = time.strftime("%Y-%m-%d")
    if d.get("date") != today:
        d = {"date": today, "doc_jobs": 0, "doc_pages": 0, "receipts": 0}
    return d


def today():
    with _lock:
        return _load()


def add(**inc):
    with _lock:
        d = _load()
        for k, v in inc.items():
            d[k] = int(d.get(k, 0)) + int(v)
        try:
            fd = os.open(FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(d, f)
        except Exception as e:
            print("print counts save failed", e)
        return d


def pdf_pages(pdf):
    """Rough page count (counts /Type /Page objects). 0 = unknown (pages hidden in compressed object streams)."""
    return len(re.findall(rb"/Type\s*/Page(?![s\w])", pdf))


def check_pdf(pdf, copies, opts):
    """Returns (ok, reason, pages_to_charge)."""
    max_bytes = limit(opts, "max_doc_mb") * 1024 * 1024
    if len(pdf) > max_bytes:
        return False, f"document is {len(pdf) // 1048576} MB; the limit is {max_bytes // 1048576} MB", 0
    if not pdf.startswith(b"%PDF-"):
        return False, "not a PDF", 0
    if UEL in pdf:
        return False, "document contains printer-control escape codes; refused for safety", 0
    copies = max(1, min(int(copies or 1), 20))
    pages = (pdf_pages(pdf) or 1) * copies
    if pages > limit(opts, "max_pages_per_job"):
        return False, f"job is about {pages} pages; the per-job limit is {limit(opts, 'max_pages_per_job')}", 0
    d = today()
    if d["doc_pages"] + pages > limit(opts, "daily_doc_pages"):
        return False, f"daily page limit reached ({d['doc_pages']} of {limit(opts, 'daily_doc_pages')} printed today)", 0
    return True, "", pages


def docs_allowed(opts):
    d = today()
    return d["doc_jobs"] < limit(opts, "daily_doc_jobs") and d["doc_pages"] < limit(opts, "daily_doc_pages")


def receipts_allowed(opts):
    return today()["receipts"] < limit(opts, "daily_receipts")

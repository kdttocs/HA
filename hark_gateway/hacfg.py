"""Home Assistant configuration tools for the Hark HA Gateway (1.3.0). Stdlib only.

What Hark can do here, and the fences around it:
  read tier (runs on its own)
    stage        - park a piece of a file in the app's own /data/stage folder (nothing in Home Assistant changes).
                   Commands are limited to 16 KB, so big files arrive as zlib+base64 parts.
    ha_file_read - read configuration.yaml or a file under packages/ (never secrets.yaml, .storage, or anything else).
                   Lines that look like passwords or tokens are blanked.
    lovelace_get - a summary of a dashboard (views, size, fingerprint), not its contents.
    ha_check_config - ask Home Assistant to check its configuration (changes nothing).
  change tier (only with an approval signed by Hark's separate approval key, which Hark sends only after the owner
  says yes to that exact change)
    ha_file_write - write configuration.yaml or packages/<name>.yaml from staged parts. The approved command names the
                    SHA-256 fingerprint of the exact content, so nothing else can be written under that approval.
                    The old file is copied to hark_backups/ first.
    lovelace_save - replace one dashboard's configuration from staged JSON, same fingerprint rule. The old dashboard
                    is saved to /data/lovelace_backups/ first.
  Restarting Home Assistant stays with the existing ha_service tool (homeassistant.restart, change tier).
"""
import base64, hashlib, json, os, re, time, zlib

import haapi

CONFIG_DIR = os.environ.get("HA_CONFIG_DIR", "/homeassistant")   # where the homeassistant_config map lands
DATA_DIR = os.environ.get("DATA_DIR", "/data")
STAGE_DIR = os.path.join(DATA_DIR, "stage")
LL_BACKUPS = os.path.join(DATA_DIR, "lovelace_backups")
FILE_BACKUPS = "hark_backups"
MAX_FILE = 512 * 1024
MAX_PARTS = 64
STAGE_KEEP = 3600
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,40}$")
PKG_RE = re.compile(r"^packages/[a-z0-9][a-z0-9_-]{0,60}\.yaml$")
URL_PATH_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,60}$")
SECRET_LINE = re.compile(r"(?i)^(\s*[\w.-]*(password|passwd|token|secret|api_?key|client_secret|private_key)[\w.-]*\s*:\s*)(?!\s*!secret)(\S.*)$")


class CfgError(Exception):
    pass


def _check_path(path):
    p = str(path or "").strip()
    if p != "configuration.yaml" and not PKG_RE.match(p):
        raise CfgError("only configuration.yaml or packages/<name>.yaml (lowercase letters, digits, - and _)")
    full = os.path.realpath(os.path.join(CONFIG_DIR, p))
    root = os.path.realpath(CONFIG_DIR)
    if not full.startswith(root + os.sep):
        raise CfgError("path escapes the configuration folder")
    if os.path.islink(os.path.join(CONFIG_DIR, p)):
        raise CfgError("refusing to follow a symbolic link")
    return p, full


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _clean_stage():
    try:
        now = time.time()
        for f in os.listdir(STAGE_DIR):
            fp = os.path.join(STAGE_DIR, f)
            if now - os.path.getmtime(fp) > STAGE_KEEP:
                os.remove(fp)
    except FileNotFoundError:
        pass


def t_stage(a):
    """{"name": "dash", "part": 1, "parts": 3, "z": "<zlib+base64 piece>"}"""
    name = str(a.get("name") or "")
    if not NAME_RE.match(name):
        raise CfgError("name: lowercase letters, digits, - and _")
    part, parts = a.get("part"), a.get("parts")
    if not (isinstance(part, int) and isinstance(parts, int) and 1 <= part <= parts <= MAX_PARTS):
        raise CfgError(f"part and parts must be whole numbers, 1 <= part <= parts <= {MAX_PARTS}")
    z = str(a.get("z") or "")
    if not re.fullmatch(r"[A-Za-z0-9+/=]{1,15000}", z):
        raise CfgError("z must be base64 text")
    os.makedirs(STAGE_DIR, exist_ok=True)
    _clean_stage()
    with open(os.path.join(STAGE_DIR, f"{name}.{parts}.{part}"), "w") as f:
        f.write(z)
    have = sorted(int(x.rsplit(".", 1)[1]) for x in os.listdir(STAGE_DIR) if x.startswith(f"{name}.{parts}."))
    return {"name": name, "part": part, "parts": parts, "have": have, "complete": have == list(range(1, parts + 1))}


def _assemble(name, sha256):
    if not NAME_RE.match(str(name or "")):
        raise CfgError("stage name missing or malformed")
    if not re.fullmatch(r"[0-9a-f]{64}", str(sha256 or "")):
        raise CfgError("sha256 (64 hex characters) of the exact content is required")
    files = [x for x in os.listdir(STAGE_DIR) if x.startswith(name + ".")] if os.path.isdir(STAGE_DIR) else []
    if not files:
        raise CfgError("nothing staged under that name (staged parts expire after an hour)")
    parts = {int(x.split(".")[1]) for x in files}
    if len(parts) != 1:
        raise CfgError("staged parts disagree on how many parts there are; stage again")
    n = parts.pop()
    blob = ""
    for i in range(1, n + 1):
        fp = os.path.join(STAGE_DIR, f"{name}.{n}.{i}")
        if not os.path.exists(fp):
            raise CfgError(f"part {i} of {n} is missing")
        blob += open(fp).read()
    try:
        raw = zlib.decompress(base64.b64decode(blob), bufsize=MAX_FILE + 1)
    except Exception as e:
        raise CfgError(f"staged data does not unpack: {e}")
    if len(raw) > MAX_FILE:
        raise CfgError("content too large")
    if _sha(raw) != sha256:
        raise CfgError("content does not match the approved fingerprint; nothing written")
    for x in files:
        try:
            os.remove(os.path.join(STAGE_DIR, x))
        except OSError:
            pass
    return raw


def t_file_read(a):
    p, full = _check_path(a.get("path"))
    if not os.path.exists(full):
        return {"path": p, "exists": False}
    raw = open(full, "rb").read()
    text = raw.decode("utf-8", errors="replace")
    lines = [SECRET_LINE.sub(lambda m: m.group(1) + "[redacted]", ln) for ln in text.splitlines()]
    return {"path": p, "exists": True, "bytes": len(raw), "sha256": _sha(raw), "content": "\n".join(lines)}


def t_file_write(a):
    p, full = _check_path(a.get("path"))
    raw = _assemble(a.get("stage"), a.get("sha256"))
    try:
        raw.decode("utf-8")
    except UnicodeDecodeError:
        raise CfgError("content must be UTF-8 text")
    backup = None
    if os.path.exists(full):
        old = open(full, "rb").read()
        if old == raw:
            return {"path": p, "written": False, "note": "already identical", "sha256": _sha(raw)}
        bdir = os.path.join(CONFIG_DIR, FILE_BACKUPS)
        os.makedirs(bdir, exist_ok=True)
        backup = os.path.join(FILE_BACKUPS, time.strftime("%Y%m%d-%H%M%S-") + p.replace("/", "__"))
        with open(os.path.join(CONFIG_DIR, backup), "wb") as f:
            f.write(old)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    tmp = full + ".hark-tmp"
    with open(tmp, "wb") as f:
        f.write(raw)
    os.replace(tmp, full)
    return {"path": p, "written": True, "bytes": len(raw), "sha256": _sha(raw), "backup": backup}


def _ll_get(url_path):
    r = haapi.ws_commands([{"type": "lovelace/config", "url_path": url_path, "force": True}], timeout=20)[0]
    if not r.get("success"):
        raise CfgError("could not read dashboard: " + json.dumps(r.get("error"))[:200])
    return r.get("result")


def _summary(cfg):
    raw = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()
    views = [{"title": v.get("title"), "path": v.get("path"), "sections": len(v.get("sections") or []),
              "cards": len(v.get("cards") or [])} for v in (cfg or {}).get("views", [])]
    return {"title": (cfg or {}).get("title"), "views": views, "bytes": len(raw), "sha256": _sha(raw)}


def t_lovelace_get(a):
    url_path = str(a.get("url_path") or "")
    if not URL_PATH_RE.match(url_path):
        raise CfgError("url_path like dashboard-home")
    return {"url_path": url_path, **_summary(_ll_get(url_path))}


def t_lovelace_save(a):
    url_path = str(a.get("url_path") or "")
    if not URL_PATH_RE.match(url_path):
        raise CfgError("url_path like dashboard-home")
    raw = _assemble(a.get("stage"), a.get("sha256"))
    try:
        cfg = json.loads(raw)
    except ValueError as e:
        raise CfgError(f"dashboard content is not JSON: {e}")
    if not isinstance(cfg, dict) or not isinstance(cfg.get("views"), list):
        raise CfgError("dashboard content must be an object with a views list")
    old = _ll_get(url_path)
    os.makedirs(LL_BACKUPS, exist_ok=True)
    bname = f"{url_path}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    with open(os.path.join(LL_BACKUPS, bname), "w") as f:
        json.dump(old, f)
    keep = sorted(x for x in os.listdir(LL_BACKUPS) if x.startswith(url_path + "-"))
    for x in keep[:-20]:
        os.remove(os.path.join(LL_BACKUPS, x))
    r = haapi.ws_commands([{"type": "lovelace/config/save", "url_path": url_path, "config": cfg}], timeout=20)[0]
    if not r.get("success"):
        raise CfgError("Home Assistant refused the dashboard: " + json.dumps(r.get("error"))[:300])
    return {"url_path": url_path, "saved": True, "backup": bname, "before": _summary(old), "after": _summary(cfg)}


def t_check_config(a):
    out = haapi.ha("POST", "/config/core/check_config", {}, timeout=90)
    return out

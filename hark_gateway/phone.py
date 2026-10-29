"""Optional second factor for changes: approve or deny on your phone (2.0.0). Stdlib only.

Off by default (phone_approval). When on, a change command that ALREADY carries a valid approval signed with Hark's
Ed25519 approval key is held, and the Home Assistant companion app on your phone shows an actionable notification
("Approve" / "Deny"). The change runs only if you tap Approve within phone_approval_timeout_s seconds.

What a tap can and can't do (by design):
  - A tap can only CO-SIGN a change that Hark's approval key already approved, or DENY it.
  - A tap alone can never start or approve anything: a command without the Ed25519 approval is refused before any
    notification is sent.
  - No tap, a timeout, a failed notification, or the app not listening to Home Assistant = refused (fails closed).
Each request uses a fresh random token in the button ids, accepted once. Set phone_approver_user_id to the Home
Assistant user id of the phone's owner to also require that the tap came from that user. Limit (documented): anyone
with Home Assistant admin rights can watch service calls and could fire a fake tap event; give Hark's Home Assistant
token its own non-admin-equivalent user where you can, and set phone_approver_user_id.
"""
import re, secrets, threading, time

ACTION_EVENT = "mobile_app_notification_action"
SERVICE_RE = re.compile(r"^[a-z0-9_]{2,80}$")
USER_RE = re.compile(r"^[0-9a-f]{32}$")
MAX_PENDING = 2


class PhoneApproval:
    def __init__(self, opts, ha, listening=lambda: True):
        self.opts, self.ha, self.listening = opts or {}, ha, listening
        self.enabled = bool(self.opts.get("phone_approval"))
        svc = str(self.opts.get("phone_notify_service") or "").strip()
        if svc.startswith("notify."):
            svc = svc[7:]
        self.service = svc if SERVICE_RE.match(svc) else ""
        uid = str(self.opts.get("phone_approver_user_id") or "").strip().lower()
        self.user_id = uid if USER_RE.match(uid) else ""
        try:
            self.timeout = max(30, min(int(self.opts.get("phone_approval_timeout_s") or 300), 900))
        except (TypeError, ValueError):
            self.timeout = 300
        self.pending = {}
        self.lock = threading.Lock()

    def problem(self):
        if not self.enabled:
            return ""
        if not self.service:
            return "phone approval is on but phone_notify_service is not set (e.g. mobile_app_my_phone)"
        return ""

    def on_event(self, etype, data, ev):
        """Called for every mobile_app_notification_action event. Ignores anything that isn't one of our tokens."""
        if etype != ACTION_EVENT or not isinstance(data, dict):
            return
        m = re.fullmatch(r"HARKGW_(OK|NO)_([0-9a-f]{32})", str(data.get("action") or ""))
        if not m:
            return
        with self.lock:
            p = self.pending.get(m.group(2))
            if not p or p["decision"] is not None:
                return
            ctx_user = str(((ev or {}).get("context") or {}).get("user_id") or "")
            if self.user_id and ctx_user != self.user_id:
                print("phone approval: tap ignored (came from a different Home Assistant user)")
                return
            p["decision"] = m.group(1) == "OK"
            p["user"] = ctx_user
            p["done"].set()

    def confirm(self, cmd_id, tool, summary):
        """Blocks until the owner taps, or the timeout. Returns (ok, reason)."""
        why = self.problem()
        if why:
            return False, why
        if not self.listening():
            return False, "phone approval needs the app's live connection to Home Assistant, which is down"
        token = secrets.token_hex(16)
        with self.lock:
            if len(self.pending) >= MAX_PENDING:
                return False, "another change is already waiting for a tap on your phone; try again after it"
            self.pending[token] = {"decision": None, "done": threading.Event(), "cmd": cmd_id}
        tag = "hark_gw_" + token[:12]
        try:
            self.ha("POST", f"/services/notify/{self.service}", {
                "title": "Hark wants to make a change",
                "message": f"{summary[:220]}\nApprove within {self.timeout // 60 or 1} min, or Deny.",
                "data": {"tag": tag, "ttl": 0, "priority": "high", "sticky": "true",
                         "push": {"interruption-level": "time-sensitive"},
                         "actions": [{"action": f"HARKGW_NO_{token}", "title": "Deny"},
                                     {"action": f"HARKGW_OK_{token}", "title": "Approve"}]}}, timeout=15)
        except Exception as e:
            with self.lock:
                self.pending.pop(token, None)
            return False, f"could not send the approval request to your phone ({type(e).__name__}); nothing was changed"
        p = self.pending[token]
        p["done"].wait(self.timeout)
        with self.lock:
            self.pending.pop(token, None)
        try:
            self.ha("POST", f"/services/notify/{self.service}", {"message": "clear_notification", "data": {"tag": tag}}, timeout=10)
        except Exception:
            pass
        if p["decision"] is True:
            return True, ""
        if p["decision"] is False:
            return False, "denied on your phone"
        return False, f"no answer on your phone within {self.timeout} s; nothing was changed"

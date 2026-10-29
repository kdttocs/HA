// Internet Receipt Printer relay: a self-hostable Cloudflare Worker (free plan) for the Internet Receipt Printer app.
// One Worker + one SQLite Durable Object. Routes:
//   /, /api/*          the public web form (only when RECEIPT_FORM = "on")
//   /bridge/next|ack   the receipt queue the app collects from (RECEIPT_TOKEN)
//   /healthz           "ok"

const BLOCKLIST = [
  // keep short and obvious; extend with EXTRA_BLOCKLIST (comma separated) in vars
  "nigger", "nigga", "faggot", "fag", "retard", "kike", "spic", "chink", "tranny", "cunt",
  "rape", "kill yourself", "kys",
];

const app = {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      const form = env.RECEIPT_FORM === "on";
      if (form && req.method === "GET" && p === "/") return html(pageHtml(env));
      if (form && req.method === "POST" && p === "/api/submit") return submit(req, env);
      if (form && req.method === "GET" && p === "/api/challenge") return challenge(req, env);
      if (form && req.method === "GET" && p.startsWith("/api/status/")) return status(p.split("/").pop(), env);
      if (form && req.method === "GET" && p === "/api/stats") return stats(env);
      if (p === "/bridge/next") return bridgeNext(req, env);
      if (p === "/bridge/ack") return bridgeAck(req, env);
      if (p === "/healthz") return new Response("ok");
      return new Response("Not found", { status: 404 });
    } catch (e) {
      console.error(e);
      return json({ error: "Server error" }, 500);
    }
  },
};

/* ---------------- helpers ---------------- */
const now = () => Math.floor(Date.now() / 1000);
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
const html = (b, s = 200) => new Response(b, { status: s, headers: { "content-type": "text/html; charset=utf-8" } });
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const int = (v, d) => (Number.isFinite(parseInt(v)) ? parseInt(v) : d);

function newId() {
  const a = "23456789abcdefghjkmnpqrstuvwxyz";
  let s = "";
  const r = crypto.getRandomValues(new Uint8Array(10));
  for (const b of r) s += a[b % a.length];
  return s;
}

async function sha(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
}

async function getSetting(env, k) {
  const r = await env.DB.prepare("SELECT value FROM settings WHERE key=?").bind(k).first();
  return r ? r.value : null;
}
const setSetting = (env, k, v) =>
  env.DB.prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(k, String(v)).run();

// Thermal printers speak ASCII-ish; normalize everything else.
function cleanText(s) {
  return String(s ?? "")
    .replace(/[\u2018\u2019\u201A\u2032]/g, "'")
    .replace(/[\u201C\u201D\u201E\u2033]/g, '"')
    .replace(/[\u2013\u2014\u2212]/g, "-")
    .replace(/\u2026/g, "...")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/\r\n?/g, "\n")
    .replace(/[^\x20-\x7E\n]/g, "")
    .replace(/[ \t]+\n/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function localParts(env, ts = now()) {
  const f = new Intl.DateTimeFormat("en-US", {
    timeZone: env.TIMEZONE || "UTC",
    month: "short", day: "numeric", hour: "numeric", minute: "2-digit", hour12: true,
  });
  const h = parseInt(new Intl.DateTimeFormat("en-US", { timeZone: env.TIMEZONE || "UTC", hour: "numeric", hour12: false }).format(new Date(ts * 1000))) % 24;
  return { label: f.format(new Date(ts * 1000)), hour: h };
}

function inQuietHours(env) {
  const s = int(env.QUIET_START_HOUR, -1), e = int(env.QUIET_END_HOUR, -1);
  if (s < 0 || e < 0 || s === e) return false;
  const h = localParts(env).hour;
  return s > e ? h >= s || h < e : h >= s && h < e;
}

const LEET = { 0: "o", 1: "i", 3: "e", 4: "a", 5: "s", 7: "t", "@": "a", "$": "s", "!": "i" };
function blocked(text, env) {
  const extra = (env.EXTRA_BLOCKLIST || "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
  const low = text.toLowerCase().replace(/[013457@$!]/g, (c) => LEET[c]);
  const t = " " + low.replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, " ") + " ";
  const squashed = low.replace(/[^a-z]/g, ""); // catches "n.i.g.g.e.r", "f a g g o t"
  return [...BLOCKLIST, ...extra].some((w) => t.includes(" " + w + " ") ||
    (w.replace(/ /g, "").length >= 5 && squashed.includes(w.replace(/ /g, ""))));
}

/* ---------------- abuse guardrails ---------------- */
// Key for the bot-check challenges and for hashing visitor addresses. Without IP_SALT, fall back to RECEIPT_TOKEN
// (also secret) rather than a fixed word anyone could read here and use to forge bot-check challenges.
const salt = (env) => env.IP_SALT || env.RECEIPT_TOKEN || "unset";
// IPv6 users get a whole /64 (billions of addresses), so limits apply per /64, not per address.
function ipKey(ip) {
  if (!ip.includes(":")) return ip;
  let [a, b = ""] = ip.split("::");
  const A = a ? a.split(":") : [], B = b ? b.split(":") : [];
  const full = ip.includes("::") ? [...A, ...Array(8 - A.length - B.length).fill("0"), ...B] : A;
  return full.slice(0, 4).map((x) => parseInt(x || "0", 16).toString(16)).join(":") + "::/64";
}
async function isBanned(env, ipHash) {
  const b = await env.DB.prepare("SELECT until FROM bans WHERE ip_hash=? AND until>?").bind(ipHash, now()).first();
  return !!b;
}
// Every refused attempt is a strike. Too many in an hour = 24h ban. A flood of strikes site-wide = lockdown.
async function strike(env, ipHash, kind) {
  const t = now();
  await env.DB.prepare("INSERT INTO abuse(ip_hash, kind, ts) VALUES(?,?,?)").bind(ipHash, kind, t).run();
  const mine = await env.DB.prepare("SELECT COUNT(*) AS n FROM abuse WHERE ip_hash=? AND ts>?").bind(ipHash, t - 3600).first();
  if (mine.n >= int(env.STRIKES_PER_HOUR, 15))
    await env.DB.prepare("INSERT INTO bans(ip_hash, until, reason) VALUES(?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET until=excluded.until, reason=excluded.reason")
      .bind(ipHash, t + 86400, kind).run();
  const all = await env.DB.prepare("SELECT COUNT(*) AS n FROM abuse WHERE ts>?").bind(t - 3600).first();
  if (all.n >= int(env.LOCKDOWN_STRIKES_PER_HOUR, 150)) await startLockdown(env, "too many refused attempts");
}
async function startLockdown(env, why) {
  const until = now() + int(env.LOCKDOWN_HOURS, 6) * 3600;
  if (int(await getSetting(env, "lockdown_until"), 0) < now()) await setSetting(env, "lockdown_reason", why);
  await setSetting(env, "lockdown_until", until);
}
const inLockdown = async (env) => int(await getSetting(env, "lockdown_until"), 0) > now();
async function housekeepAbuse(env) {
  const t = now();
  await env.DB.prepare("DELETE FROM abuse WHERE ts<?").bind(t - 2 * 86400).run();
  await env.DB.prepare("DELETE FROM bans WHERE until<?").bind(t).run();
  await env.DB.prepare("DELETE FROM pow_used WHERE ts<?").bind(t - 3600).run();
}

// Proof of work: the page must burn ~1s of CPU per message. Trivial for a person, expensive for a script sending
// thousands. Gets harder automatically when the site is busy.
const powKey = (env) => salt(env) + ":pow";
async function challenge(req, env) {
  const t = now();
  const hour = await env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE created_at>?").bind(t - 3600).first();
  const strikes = await env.DB.prepare("SELECT COUNT(*) AS n FROM abuse WHERE ts>?").bind(t - 600).first();
  const busy = hour.n >= int(env.GLOBAL_HOURLY, 30) / 2 || strikes.n >= 20 || (await inLockdown(env));
  const bits = busy ? int(env.POW_BITS_BUSY, 20) : int(env.POW_BITS, 18);
  const base = `${t}.${bits}.${newId()}`;
  return json({ c: base + "." + (await hmacHex(powKey(env), base)).slice(0, 32), bits });
}
async function powCheck(env, c, n) {
  const parts = String(c || "").split(".");
  if (parts.length !== 4 || !/^\d{1,12}$/.test(String(n ?? ""))) return "missing";
  const [ts, bits] = parts.map(Number);
  if (!safeEq(parts[3], (await hmacHex(powKey(env), parts.slice(0, 3).join("."))).slice(0, 32))) return "forged";
  if (now() - ts > 900 || ts > now() + 60 || bits < int(env.POW_BITS, 18)) return "expired";
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(c + ":" + n)));
  let z = 0; for (const b of d) { if (b === 0) { z += 8; continue; } z += Math.clz32(b) - 24; break; }
  if (z < bits) return "wrong";
  if (await env.DB.prepare("SELECT 1 AS x FROM pow_used WHERE c=?").bind(c).first()) return "reused";
  await env.DB.prepare("INSERT INTO pow_used(c, ts) VALUES(?,?)").bind(c, now()).run();
  return "";
}

/* ---------------- public API ---------------- */
async function submit(req, env) {
  const t = now();
  const ip = req.headers.get("cf-connecting-ip") || "0.0.0.0";
  const ipHash = await sha(salt(env) + ipKey(ip));
  // read (or drop) the body first; a real message is well under 2 KB
  const big = int(req.headers.get("content-length"), 0) > 8192;
  let raw = "";
  if (big) { try { await req.body?.cancel(); } catch {} } else raw = await req.text();
  if (await isBanned(env, ipHash)) return json({ error: "This connection is taking a break from printing. Try again tomorrow." }, 429);
  await housekeepAbuse(env);
  const refuse = async (kind, msg, code = 400) => { await strike(env, ipHash, kind); return json({ error: msg }, code); };

  if (big || raw.length > 8192) return refuse("size", "That's too big.", 413);
  const ct = req.headers.get("content-type") || "";
  let body;
  try {
    body = ct.includes("application/json") ? JSON.parse(raw) : Object.fromEntries(await new Response(raw, { headers: { "content-type": ct } }).formData());
  } catch { return refuse("junk", "Couldn't read that."); }
  if (!body || typeof body !== "object") return refuse("junk", "Couldn't read that.");

  // honeypot: bots fill the hidden field; pretend it worked
  if (body.website) { await strike(env, ipHash, "honeypot"); return json({ ok: true, id: "x", status: "queued" }); }

  const pow = await powCheck(env, body.pow_c, body.pow_n);
  if (pow) return refuse("pow", "Bot check failed. Refresh the page and try again.");

  if (env.TURNSTILE_SECRET) {
    const fd = new FormData();
    fd.append("secret", env.TURNSTILE_SECRET);
    fd.append("response", body["cf-turnstile-response"] || "");
    fd.append("remoteip", ip);
    const v = await (await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body: fd })).json();
    if (!v.success) return refuse("turnstile", "Bot check failed. Refresh and try again.");
  }

  const max = int(env.MAX_LEN, 280);
  const text = cleanText(body.message);
  const author = cleanText(body.name).replace(/\n/g, " ").slice(0, 24);
  if (!text) return json({ error: "Write something first." }, 400);
  if (text.length > max) return refuse("long", `Keep it under ${max} characters.`);
  if (text.split("\n").length > 12) return refuse("lines", "Too many line breaks.");
  if (/(https?:\/\/|www\.|\b[a-z0-9-]+\.(com|net|org|io|ly|gg|xyz|me|co|app|lol)\b)/i.test(text + " " + author)) return refuse("link", "No links, please.");
  if (/[^\s@]+@[^\s@]+\.[a-z]{2,}/i.test(text + " " + author) || /(\d[\s().-]*){10,}/.test(text + " " + author))
    return refuse("contact", "No phone numbers or email addresses, please.");
  if (/(.)\1{14,}/.test(text) || /(.{2,8})\1{8,}/.test(text)) return refuse("waste", "That looks like a paper-waster.");
  if ((text.match(/[a-z0-9]/gi) || []).length < Math.min(3, text.length)) return refuse("waste", "That looks like a paper-waster.");
  if (blocked(text + " " + author, env)) return refuse("blocked", "Let's keep it kind.");

  // same words already sent in the last day (one person on many connections, or a copy-paste flood)
  const fp = await sha("fp:" + text.toLowerCase().replace(/[^a-z0-9]/g, ""));
  if (await env.DB.prepare("SELECT 1 AS x FROM messages WHERE fp=? AND created_at>?").bind(fp, t - 86400).first())
    return refuse("dupe", "Someone already sent that one today. Try something original.", 409);

  // per-connection limits
  const cool = int(env.PER_IP_COOLDOWN_SEC, 60);
  const last = await env.DB.prepare("SELECT MAX(created_at) AS t FROM messages WHERE ip_hash=?").bind(ipHash).first();
  if (last?.t && t - last.t < cool) return refuse("rate", `Easy, tiger. Try again in ${cool - (t - last.t)}s.`, 429);
  const mineHr = await env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE ip_hash=? AND created_at>?").bind(ipHash, t - 3600).first();
  if (mineHr.n >= int(env.PER_IP_HOURLY, 4)) return refuse("rate", "That's plenty for this hour. Come back later.", 429);
  const day = await env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE ip_hash=? AND created_at>?").bind(ipHash, t - 86400).first();
  if (day.n >= int(env.PER_IP_DAILY, 10)) return refuse("rate", "That's your limit for today. Come back tomorrow.", 429);

  // site-wide limits (protect the paper no matter how many connections an attacker has)
  const live = "status IN ('pending','queued','sent','printed')";
  const gMin = await env.DB.prepare(`SELECT COUNT(*) AS n FROM messages WHERE ${live} AND created_at>?`).bind(t - 60).first();
  if (gMin.n >= int(env.GLOBAL_PER_MIN, 4)) return json({ error: "The printer's swamped. Try again in a minute." }, 429);
  const gHr = await env.DB.prepare(`SELECT COUNT(*) AS n FROM messages WHERE ${live} AND created_at>?`).bind(t - 3600).first();
  if (gHr.n >= int(env.GLOBAL_HOURLY, 30)) {
    await startLockdown(env, "hourly limit reached");
    return json({ error: "The printer's had a busy hour. Try again later." }, 429);
  }
  const global = await env.DB.prepare(`SELECT COUNT(*) AS n FROM messages WHERE ${live} AND created_at>?`).bind(t - 86400).first();
  if (global.n >= int(env.GLOBAL_DAILY, 150)) return json({ error: "The printer's out of paper for today. Try tomorrow." }, 429);
  const waiting = await env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE status IN ('pending','queued')").first();
  if (waiting.n >= int(env.MAX_WAITING, 40)) return json({ error: "The line's full right now. Try again later." }, 429);

  // there is no admin page: during a lockdown new messages are turned away instead of waiting for approval
  if (await inLockdown(env)) return json({ error: "The printer's taking a break. Try again later." }, 429);
  const id = newId();
  const st = "queued";
  await env.DB.prepare("INSERT INTO messages(id,body,author,ip_hash,status,created_at,fp) VALUES(?,?,?,?,?,?,?)")
    .bind(id, text, author || null, ipHash, st, t, fp).run();
  if (st === "queued") env.NOTIFY?.("bridge");
  return json({ ok: true, id, status: st });
}

async function status(id, env) {
  if (!/^[a-z0-9]{10}$/.test(id)) return json({ error: "Not found" }, 404);
  const m = await env.DB.prepare("SELECT rowid AS n, status, created_at FROM messages WHERE id=?").bind(id).first();
  if (!m) return json({ error: "Not found" }, 404);
  let ahead = 0;
  if (m.status === "queued" || m.status === "pending")
    ahead = (await env.DB.prepare("SELECT COUNT(*) AS c FROM messages WHERE status IN ('queued','sent') AND created_at<?").bind(m.created_at).first()).c;
  const lastPoll = int(await getSetting(env, "last_poll"), 0);
  return json({ number: m.n, status: m.status, ahead, printerOnline: now() - lastPoll < 180, quiet: inQuietHours(env) });
}

async function stats(env) {
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE status='printed'").first();
  const lastPoll = int(await getSetting(env, "last_poll"), 0);
  return json({ printed: r.n, printerOnline: now() - lastPoll < 180, quiet: inQuietHours(env) });
}

/* ---------------- job queue ---------------- */
async function nextJob(env) {
  await setSetting(env, "last_poll", now());
  if ((await getSetting(env, "paused")) === "1" || inQuietHours(env)) return null;
  const t = now();
  // anything "sent" with no result after 2 minutes goes back in line (max 3 tries)
  await env.DB.prepare("UPDATE messages SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END WHERE status='sent' AND sent_at<?").bind(t - 120).run();
  const m = await env.DB.prepare("SELECT rowid AS n, * FROM messages WHERE status='queued' ORDER BY created_at LIMIT 1").first();
  if (!m) return null;
  await env.DB.prepare("UPDATE messages SET status='sent', sent_at=?, attempts=attempts+1 WHERE id=?").bind(t, m.id).run();
  return m;
}

async function markResult(env, id, ok) {
  if (!id) return;
  if (ok) await env.DB.prepare("UPDATE messages SET status='printed', printed_at=? WHERE id=?").bind(now(), id).run();
  else await env.DB.prepare("UPDATE messages SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END WHERE id=?").bind(id).run();
}

// Long-poll helper: ?wait=N (max 28 s) holds the request until `fn` returns something or a NOTIFY on `ch` fires.
async function longPoll(env, url, ch, fn) {
  let r = await fn();
  const wait = Math.min(Math.max(int(url.searchParams.get("wait"), 0), 0), 28) * 1000;
  if (r || !wait || !env.WAIT) return r;
  const end = Date.now() + wait;
  while (!r && Date.now() < end) {
    await env.WAIT(ch, end - Date.now());
    r = await fn();
  }
  return r;
}

/* ---------------- receipt queue (collected by the app) ---------------- */
// Only RECEIPT_TOKEN opens it. Nothing else on this relay is private.
function bridgeAuthed(req, env) {
  return !!env.RECEIPT_TOKEN && safeEq(req.headers.get("authorization"), "Bearer " + env.RECEIPT_TOKEN);
}
async function bridgeNext(req, env) {
  if (!bridgeAuthed(req, env)) return json({ error: "unauthorized" }, 401);
  const m = await longPoll(env, new URL(req.url), "bridge", () => nextJob(env));
  if (!m) return new Response(null, { status: 204 });
  return json({ id: m.id, number: m.n, body: m.body, author: m.author, when: localParts(env, m.created_at).label, title: env.SITE_TITLE || "INCOMING" });
}
async function bridgeAck(req, env) {
  if (!bridgeAuthed(req, env)) return json({ error: "unauthorized" }, 401);
  const { id, ok } = await req.json();
  await markResult(env, id, !!ok);
  return json({ ok: true });
}

/* ---------------- crypto helpers ---------------- */
const hexOf = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmacHex(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hexOf(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
function safeEq(a, b) {
  a = String(a || ""); b = String(b || "");
  if (a.length !== b.length || !a.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

/* ---------------- public page ---------------- */
function pageHtml(env) {
  const max = int(env.MAX_LEN, 280);
  const ts = env.TURNSTILE_SITE_KEY;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(env.SITE_TITLE)}</title>
<meta name="description" content="Type a message. It prints on a real receipt printer.">
${ts ? '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>' : ""}
<style>
:root{--ink:#1b1b1b;--paper:#fbfaf6;--bg:#e9e6df;--accent:#d2452c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 ui-monospace,"SF Mono",Menlo,Consolas,monospace;min-height:100vh;display:flex;justify-content:center;padding:4vh 1rem}
.wrap{width:100%;max-width:420px}
h1{font-size:1.05rem;letter-spacing:.2em;text-transform:uppercase;text-align:center;margin:0 0 .25rem}
.sub{text-align:center;font-size:.8rem;opacity:.7;margin-bottom:1.25rem}
.receipt{background:var(--paper);padding:1.4rem 1.2rem 2rem;box-shadow:0 8px 24px rgba(0,0,0,.12);position:relative;
 -webkit-mask:conic-gradient(from -45deg at bottom,#0000,#000 1deg 89deg,#0000 90deg) 50%/14px 100%;mask:conic-gradient(from -45deg at bottom,#0000,#000 1deg 89deg,#0000 90deg) 50%/14px 100%}
.rule{border-top:1px dashed #999;margin:.8rem 0}
textarea,input{width:100%;font:inherit;background:transparent;border:0;outline:0;resize:none;color:var(--ink)}
textarea{min-height:9rem}
input{border-bottom:1px dashed #bbb;padding:.3rem 0}
.row{display:flex;justify-content:space-between;align-items:center;font-size:.8rem;opacity:.75}
button{width:100%;margin-top:1rem;padding:.9rem;font:inherit;font-weight:700;letter-spacing:.15em;background:var(--ink);color:var(--paper);border:0;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
.msg{min-height:1.5rem;margin-top:.8rem;text-align:center;font-size:.9rem}
.err{color:var(--accent)}
.dot{display:inline-block;width:.55rem;height:.55rem;border-radius:50%;background:#aaa;margin-right:.35rem}
.on{background:#2e9e4f}
.hp{position:absolute;left:-9999px}
</style></head><body><div class="wrap">
<h1>${esc(env.SITE_TITLE)}</h1>
<div class="sub">Type it here. It prints on a real receipt printer.</div>
<form class="receipt" id="f">
 <div class="row"><span><span class="dot" id="dot"></span><span id="pstat">checking printer...</span></span><span id="count"></span></div>
 <div class="rule"></div>
 <textarea name="message" id="m" maxlength="${max}" placeholder="What should it say?" required></textarea>
 <div class="rule"></div>
 <input name="name" maxlength="24" placeholder="Sign it (optional)">
 <input class="hp" name="website" tabindex="-1" autocomplete="off">
 ${ts ? `<div class="cf-turnstile" data-sitekey="${esc(ts)}" style="margin-top:1rem"></div>` : ""}
 <div class="row" style="margin-top:.6rem"><span>Be kind. No links.</span><span id="left">${max}</span></div>
 <button id="b">PRINT IT</button>
 <div class="msg" id="out"></div>
</form></div>
<script>
const K=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];
function h0(s){const l=s.length,n=((l+8)>>6)+1<<4,w=new Int32Array(n),W=new Int32Array(64);for(let i=0;i<l;i++)w[i>>2]|=s.charCodeAt(i)<<(24-(i&3)*8);w[l>>2]|=128<<(24-(l&3)*8);w[n-1]=l*8;
let H=[1779033703,-1150833019,1013904242,-1521486534,1359893119,-1694144372,528734635,1541459225];
for(let j=0;j<n;j+=16){for(let i=0;i<16;i++)W[i]=w[j+i];for(let i=16;i<64;i++){const a=W[i-15],b=W[i-2];W[i]=((a>>>7|a<<25)^(a>>>18|a<<14)^(a>>>3))+W[i-7]+((b>>>17|b<<15)^(b>>>19|b<<13)^(b>>>10))+W[i-16]|0}
let[A,B,C,D,E,F,G,X]=H;for(let i=0;i<64;i++){const t1=X+((E>>>6|E<<26)^(E>>>11|E<<21)^(E>>>25|E<<7))+((E&F)^(~E&G))+K[i]+W[i]|0,t2=((A>>>2|A<<30)^(A>>>13|A<<19)^(A>>>22|A<<10))+((A&B)^(A&C)^(B&C))|0;X=G;G=F;F=E;E=D+t1|0;D=C;C=B;B=A;A=t1+t2|0}
H=[H[0]+A|0,H[1]+B|0,H[2]+C|0,H[3]+D|0,H[4]+E|0,H[5]+F|0,H[6]+G|0,H[7]+X|0]}return H[0]>>>0}
async function solve(){const j=await (await fetch('/api/challenge')).json();const c=j.c+':',sh=32-j.bits;let n=0;
 for(;;){for(let k=0;k<25000;k++,n++)if((h0(c+n)>>>sh)===0)return{c:j.c,n,at:Date.now()};await new Promise(r=>setTimeout(r,0))}}
let powP=solve().catch(()=>null);
const MAX=${max},f=document.getElementById('f'),m=document.getElementById('m'),out=document.getElementById('out'),b=document.getElementById('b');
m.addEventListener('input',()=>{document.getElementById('left').textContent=MAX-m.value.length});
async function stats(){try{const s=await (await fetch('/api/stats')).json();
 document.getElementById('dot').className='dot'+(s.printerOnline&&!s.quiet?' on':'');
 document.getElementById('pstat').textContent=s.quiet?'printer sleeping (queues till morning)':s.printerOnline?'printer online':'printer offline (will queue)';
 document.getElementById('count').textContent=s.printed+' printed';}catch(e){}}
stats();setInterval(stats,30000);
async function watch(id){for(let i=0;i<60;i++){await new Promise(r=>setTimeout(r,4000));
 const s=await (await fetch('/api/status/'+id)).json();
 if(s.status==='printed'){out.textContent='Printed! Ticket #'+String(s.number).padStart(4,'0')+'.';return}
 if(s.status==='rejected'||s.status==='failed'){out.textContent='That one did not print.';out.className='msg err';return}
 out.textContent=s.status==='pending'?'Waiting for approval...':s.ahead>0?s.ahead+' ahead of you...':'Printing...';}}
f.addEventListener('submit',async e=>{e.preventDefault();b.disabled=true;out.className='msg';out.textContent="Checking you're human...";
 try{let p=await powP;if(!p||Date.now()-p.at>600000){powP=solve().catch(()=>null);p=await powP}
  const fd=new FormData(f);if(p){fd.append('pow_c',p.c);fd.append('pow_n',p.n)}powP=solve().catch(()=>null);out.textContent='Sending...';
  const r=await fetch('/api/submit',{method:'POST',body:fd});const j=await r.json();
  if(!r.ok){out.className='msg err';out.textContent=j.error||'Something went wrong.'}
  else{f.reset();document.getElementById('left').textContent=MAX;out.textContent='Queued.';watch(j.id)}}
 catch(err){out.className='msg err';out.textContent='Network hiccup. Try again.'}
 b.disabled=false;if(window.turnstile)turnstile.reset();});
</script></body></html>`;
}

/* ---------------- storage: one Durable Object with SQLite, behind a tiny D1-style shim ---------------- */
import { DurableObject } from "cloudflare:workers";

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, body TEXT NOT NULL, author TEXT, ip_hash TEXT NOT NULL,
     status TEXT NOT NULL, created_at INTEGER NOT NULL, sent_at INTEGER, printed_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS idx_status_created ON messages(status, created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_ip_created ON messages(ip_hash, created_at)`,
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `INSERT OR IGNORE INTO settings(key, value) VALUES ('paused', '0')`,
  `INSERT OR IGNORE INTO settings(key, value) VALUES ('last_poll', '0')`,
  `CREATE TABLE IF NOT EXISTS abuse (ip_hash TEXT NOT NULL, kind TEXT NOT NULL, ts INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_abuse_ip ON abuse(ip_hash, ts)`,
  `CREATE INDEX IF NOT EXISTS idx_abuse_ts ON abuse(ts)`,
  `CREATE TABLE IF NOT EXISTS bans (ip_hash TEXT PRIMARY KEY, until INTEGER NOT NULL, reason TEXT)`,
  `CREATE TABLE IF NOT EXISTS pow_used (c TEXT PRIMARY KEY, ts INTEGER NOT NULL)`,
];

function shim(sql) {
  return {
    prepare(q) {
      let args = [];
      const st = {
        bind(...a) { args = a; return st; },
        async first() { const r = sql.exec(q, ...args).toArray(); return r[0] ?? null; },
        async all() { return { results: sql.exec(q, ...args).toArray() }; },
        async run() { sql.exec(q, ...args); return { success: true }; },
      };
      return st;
    },
  };
}

export class Store extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    for (const q of SCHEMA) ctx.storage.sql.exec(q);
    try { ctx.storage.sql.exec("ALTER TABLE messages ADD COLUMN fp TEXT"); } catch {} // already there
    ctx.storage.sql.exec("CREATE INDEX IF NOT EXISTS idx_fp ON messages(fp, created_at)");
    this.db = shim(ctx.storage.sql);
    this.waiters = new Map(); // channel -> Set of resolve functions (long-poll)
  }
  wait(ch, ms) {
    return new Promise((res) => {
      if (!this.waiters.has(ch)) this.waiters.set(ch, new Set());
      const set = this.waiters.get(ch);
      const done = (v) => { clearTimeout(t); set.delete(done); res(v); };
      const t = setTimeout(() => done(false), Math.max(ms, 0));
      set.add(done);
    });
  }
  notify(ch) {
    const set = this.waiters.get(ch);
    if (set) for (const f of [...set]) f(true);
  }
  async fetch(req) {
    return app.fetch(req, { ...this.env, DB: this.db, WAIT: (c, ms) => this.wait(c, ms), NOTIFY: (c) => this.notify(c) },
      { waitUntil: (p) => this.ctx.waitUntil(p) });
  }
}

/* ---- shared encoder ---- */
const enc = new TextEncoder();

export default {
  async fetch(req, env) {
    const stub = env.STORE.get(env.STORE.idFromName("main"));
    return stub.fetch(req);
  },
};

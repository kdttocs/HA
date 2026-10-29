// Hark Home Assistant Gateway relay: a self-hostable Cloudflare Worker (free plan) for the Hark Home Assistant Gateway app.
// One Worker + one SQLite Durable Object. Routes:
//   /gw/*         command relay between Hark and the app (every route needs the signed X-GW-Auth header)
//   /docs/*       private document queue: Hark uploads PDFs (DOC_TOKEN), the app fetches and prints them (PRINT_TOKEN)
//   /setup/claim  2.0.3: one-time hand-over of the relay's own secrets to Hark (needs Hark's approval-key signature)
//   /setup/pair   2.0.4: pairing through the relay (the app posts a one-time PUBLIC key; Hark answers sealed to it)
//   /gw/ws        2.0.4: "doorbell" WebSocket the app keeps open (signed); the relay rings it when a command or a
//                 document is queued, and the app then fetches it over the normal signed /gw/next or /docs/next
//   /healthz      {"ok":true,"claimed":true|false}
// Nothing here is public: every route needs a secret or Hark's signature, except /healthz and /setup/pair (which only
// takes a one-time public key and hands back ciphertext that only the app that asked can open).
//
// 2.0.3 secrets: the relay makes its own GATEWAY_SECRET, DOC_TOKEN, PRINT_TOKEN and IP_SALT (32 random bytes each)
// the first time Hark claims it, and keeps them in its Durable Object storage (in your Cloudflare account). A secret
// set by hand (`wrangler secret put` or the dashboard) always wins over the stored one. Until secrets exist, /gw and
// /docs refuse everything.

const app = {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const p = url.pathname;
    try {
      if (p === "/healthz") return json({ ok: true, claimed: (await claimState(env)) !== "" });
      if (p === "/setup/claim") return claimRoute(req, env, url);
      if (p === "/setup/pair" || p.startsWith("/setup/pair/")) return pairRoute(req, await withSecrets(env), url, p);
      if (!p.startsWith("/docs/") && !p.startsWith("/gw/")) return new Response("Not found", { status: 404 });
      env = await withSecrets(env);
      if (p.startsWith("/docs/")) return docsRoute(req, env, url, p);
      return gwRoute(req, env, url, p);
    } catch (e) {
      console.error(e);
      return json({ error: "Server error" }, 500);
    }
  },
};

/* ---------------- helpers ---------------- */
const now = () => Math.floor(Date.now() / 1000);
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "content-type": "application/json" } });
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

// IPv6 users get a whole /64 (billions of addresses), so failure limits apply per /64, not per address.
function ipKey(ip) {
  if (!ip.includes(":")) return ip;
  let [a, b = ""] = ip.split("::");
  const A = a ? a.split(":") : [], B = b ? b.split(":") : [];
  const full = ip.includes("::") ? [...A, ...Array(8 - A.length - B.length).fill("0"), ...B] : A;
  return full.slice(0, 4).map((x) => parseInt(x || "0", 16).toString(16)).join(":") + "::/64";
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

/* ---------------- private full-page document queue (printed by the app over IPP) ---------------- */
// Hark uploads PDFs with DOC_TOKEN; the app fetches them with PRINT_TOKEN. Nothing here is public.
// PRINT_TOKEN was called BRIDGE_TOKEN in earlier copies of this template; the old name still works.
const printToken = (env) => env.PRINT_TOKEN || env.BRIDGE_TOKEN;
const CHUNK = 1024 * 1024;           // DO SQLite values max 2 MB, so PDFs are stored in 1 MB chunks
const DOC_MAX = 25 * 1024 * 1024;
const authed = (req, tok) => !!tok && safeEq(req.headers.get("authorization"), "Bearer " + tok);

async function docsRoute(req, env, url, p) {
  const isHark = authed(req, env.DOC_TOKEN), isPrinter = authed(req, printToken(env));
  if (!isHark && !isPrinter) return json({ error: "unauthorized" }, 401);
  const parts = p.split("/").filter(Boolean); // ["docs", action, id?]
  const action = parts[1], id = parts[2];

  if (isHark && req.method === "POST" && action === "upload") {
    const buf = new Uint8Array(await req.arrayBuffer());
    if (buf.length < 5 || buf.length > DOC_MAX) return json({ error: "PDF must be 1 byte to 25 MB" }, 413);
    if (String.fromCharCode(...buf.slice(0, 5)) !== "%PDF-") return json({ error: "body must be a PDF" }, 415);
    const q = url.searchParams;
    const did = newId();
    const opts = {
      copies: Math.min(Math.max(int(q.get("copies"), 1), 1), 20),
      sides: ["one-sided", "two-sided-long-edge", "two-sided-short-edge"].includes(q.get("sides")) ? q.get("sides") : "one-sided",
      color: ["color", "monochrome"].includes(q.get("color")) ? q.get("color") : "",
    };
    for (let i = 0; i * CHUNK < buf.length; i++)
      await env.DB.prepare("INSERT INTO doc_chunks(doc_id, seq, data) VALUES(?,?,?)").bind(did, i, buf.slice(i * CHUNK, (i + 1) * CHUNK)).run();
    await env.DB.prepare("INSERT INTO docs(id, name, bytes, opts, status, created_at) VALUES(?,?,?,?, 'queued', ?)")
      .bind(did, String(q.get("name") || "document.pdf").slice(0, 120), buf.length, JSON.stringify(opts), now()).run();
    env.NOTIFY?.("docs");
    return json({ id: did, status: "queued" });
  }
  // (bridge_seen_sec_ago in the answers below = seconds since the app last checked this queue; name kept for Hark)
  if (isHark && req.method === "GET" && action === "status" && id) {
    const d = await env.DB.prepare("SELECT id,name,bytes,opts,status,detail,attempts,created_at,sent_at,done_at FROM docs WHERE id=?").bind(id).first();
    if (!d) return json({ error: "not found" }, 404);
    const lp = int(await getSetting(env, "docs_last_poll"), 0);
    return json({ ...d, opts: JSON.parse(d.opts), printer: await getSetting(env, "docs_printer"), bridge_seen_sec_ago: lp ? now() - lp : null });
  }
  if (isHark && req.method === "GET" && action === "list") {
    const r = await env.DB.prepare("SELECT id,name,status,detail,created_at,done_at FROM docs ORDER BY created_at DESC LIMIT 20").all();
    const lp = int(await getSetting(env, "docs_last_poll"), 0);
    return json({ jobs: r.results, printer: await getSetting(env, "docs_printer"), bridge_seen_sec_ago: lp ? now() - lp : null });
  }
  if (isHark && req.method === "POST" && action === "cancel" && id) {
    await env.DB.prepare("UPDATE docs SET status='canceled', done_at=? WHERE id=? AND status IN ('queued','sent')").bind(now(), id).run();
    await env.DB.prepare("DELETE FROM doc_chunks WHERE doc_id=?").bind(id).run();
    return json({ ok: true });
  }

  if (isPrinter && action === "next") {
    const t0 = now();
    await setSetting(env, "docs_last_poll", t0);
    const pr = url.searchParams.get("printer");
    if (pr) await setSetting(env, "docs_printer", pr.slice(0, 200));
    // a job handed out but never answered within 10 minutes goes back in line (max 3 tries)
    await env.DB.prepare("UPDATE docs SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END, done_at=CASE WHEN attempts>=3 THEN ? ELSE done_at END, detail='no answer from the app' WHERE status='sent' AND sent_at<?").bind(t0, t0 - 600).run();
    await env.DB.prepare("UPDATE docs SET status='unknown', detail='printer never reported finishing', done_at=? WHERE status='printing' AND sent_at<?").bind(t0, t0 - 1800).run();
    await env.DB.prepare("DELETE FROM doc_chunks WHERE doc_id IN (SELECT id FROM docs WHERE status IN ('failed','canceled','printed','unknown') AND done_at < ?)").bind(t0 - 86400).run();
    // ?wait=25 turns this into a long-poll: answers the moment Hark uploads a job (old clients without wait are unchanged)
    const d = await longPoll(env, url, "docs", async () => {
      const x = await env.DB.prepare("SELECT id,name,bytes,opts FROM docs WHERE status='queued' ORDER BY created_at LIMIT 1").first();
      if (!x) return null;
      await env.DB.prepare("UPDATE docs SET status='sent', sent_at=?, attempts=attempts+1 WHERE id=?").bind(now(), x.id).run();
      return x;
    });
    if (!d) return new Response(null, { status: 204 });
    return json({ ...d, opts: JSON.parse(d.opts) });
  }
  if (isPrinter && action === "file" && id) {
    const r = await env.DB.prepare("SELECT data FROM doc_chunks WHERE doc_id=? ORDER BY seq").bind(id).all();
    if (!r.results.length) return json({ error: "not found" }, 404);
    const bufs = r.results.map((x) => new Uint8Array(x.data));
    const out = new Uint8Array(bufs.reduce((a, b) => a + b.length, 0));
    let o = 0; for (const b of bufs) { out.set(b, o); o += b.length; }
    return new Response(out, { headers: { "content-type": "application/pdf" } });
  }
  if (isPrinter && req.method === "POST" && action === "ack") {
    const { id: did, status: st, detail } = await req.json();
    if (!did) return json({ error: "id required" }, 400);
    if (st === "printing") {
      await env.DB.prepare("UPDATE docs SET status='printing', detail=?, sent_at=? WHERE id=?").bind(String(detail || "").slice(0, 300), now(), did).run();
    } else if (st === "printed") {
      await env.DB.prepare("UPDATE docs SET status='printed', detail=?, done_at=? WHERE id=?").bind(String(detail || "").slice(0, 300), now(), did).run();
      await env.DB.prepare("DELETE FROM doc_chunks WHERE doc_id=?").bind(did).run();
    } else if (st === "failed_final") {
      await env.DB.prepare("UPDATE docs SET status='failed', detail=?, done_at=? WHERE id=?").bind(String(detail || "").slice(0, 300), now(), did).run();
      await env.DB.prepare("DELETE FROM doc_chunks WHERE doc_id=?").bind(did).run();
    } else {
      await env.DB.prepare("UPDATE docs SET status=CASE WHEN attempts>=3 THEN 'failed' ELSE 'queued' END, done_at=CASE WHEN attempts>=3 THEN ? ELSE done_at END, detail=? WHERE id=?").bind(now(), String(detail || "error").slice(0, 300), did).run();
      env.NOTIFY?.("docs");
    }
    // keep storage tidy: drop file data of anything finished more than a day ago (failed after 3 tries, or stuck)
    await env.DB.prepare("DELETE FROM doc_chunks WHERE doc_id IN (SELECT id FROM docs WHERE status IN ('failed','canceled','printed') AND done_at < ?)").bind(now() - 86400).run();
    return json({ ok: true });
  }
  return json({ error: "not found" }, 404);
}

/* ---------------- self-generated secrets + one-time claim (2.0.3) ---------------- */
const SECRET_NAMES = ["GATEWAY_SECRET", "DOC_TOKEN", "PRINT_TOKEN", "IP_SALT"];
const CLAIM_MAX_FAILS = 20;   // failed claims per address (IPv6: per /64) per hour
const randHex = () => hexOf(crypto.getRandomValues(new Uint8Array(32)));
// claim state: "" (never claimed), "claimed" (secrets handed over, Hark hasn't used them yet), "confirmed" (in use)
const claimState = async (env) => (await getSetting(env, "claim_state")) || "";
// Secrets set by hand always win; stored ones fill the gaps. Before the first claim nothing is stored, so the
// /gw and /docs routes see no secrets and refuse everything (fail closed).
async function withSecrets(env) {
  const out = { ...env };
  for (const k of SECRET_NAMES) {
    if (k === "PRINT_TOKEN" && env.BRIDGE_TOKEN) continue;   // older relays: BRIDGE_TOKEN is their PRINT_TOKEN
    if (!env[k]) { const v = await getSetting(env, "secret_" + k); if (v) out[k] = v; }
  }
  return out;
}
async function makeSecrets(env) {
  for (const k of SECRET_NAMES)
    await env.DB.prepare("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)").bind("secret_" + k, randHex()).run();
}
// POST /setup/claim {host, ts, nonce, sig}: sig = Ed25519 by Hark's approval key over
//   "hark-relay-claim-v1\n<host>\n<ts>\n<nonce>"   (host = this relay's host name, as Hark addressed it)
// First valid claim: makes the secrets and returns GATEWAY_SECRET + DOC_TOKEN (PRINT_TOKEN reaches the app via the
// signed /gw/hello). Once Hark has used them (its first signed /gw request), every later claim gets 409 and nothing.
// A claim that is valid but arrives before that (the answer got lost on the way) gets the same values again.
async function claimRoute(req, env, url) {
  const no = (s, e) => json({ error: e }, s);
  if (req.method !== "POST") return no(405, "POST only");
  if (!env.GW_APPROVAL_PUB) return no(503, "relay not set up: GW_APPROVAL_PUB (Hark's approval public key) is missing");
  const ipHash = await sha("claim" + ipKey(req.headers.get("cf-connecting-ip") || "0.0.0.0"));
  const fails = (await env.DB.prepare("SELECT COUNT(*) AS n FROM abuse WHERE ip_hash=? AND kind='claim' AND ts>?").bind(ipHash, now() - 3600).first()).n;
  if (fails >= CLAIM_MAX_FAILS) return no(429, "too many failed attempts");
  const fail = async (s, e) => {
    await env.DB.prepare("DELETE FROM abuse WHERE kind='claim' AND ts<?").bind(now() - 86400).run();  // stays small before the first claim
    await env.DB.prepare("INSERT INTO abuse(ip_hash, kind, ts) VALUES(?,?,?)").bind(ipHash, "claim", now()).run();
    return no(s, e);
  };
  const raw = await req.text();
  if (raw.length > 2000) return fail(413, "too large");
  let b; try { b = JSON.parse(raw); } catch { return fail(400, "bad request"); }
  if (!b || typeof b !== "object") return fail(400, "bad request");
  const host = String(b.host || "").toLowerCase();
  if (!host || host !== url.host.toLowerCase()) return fail(401, "unauthorized: wrong relay");
  if (!fresh(b.ts)) return fail(401, "unauthorized: stale or missing timestamp");
  if (!(await claimSigOk(env, host, b))) return fail(401, "unauthorized: bad signature");
  if (!(await useNonce(env, b.nonce))) return fail(401, "unauthorized: nonce reused");
  if (env.GATEWAY_SECRET || env.DOC_TOKEN)
    return no(409, "this relay's secrets were set by hand; give them to Hark through its secure form");
  const st = await claimState(env);
  if (st === "confirmed") return no(409, "already claimed");
  await makeSecrets(env);
  if (!st) await setSetting(env, "claim_state", "claimed");
  const s = await withSecrets(env);
  return new Response(JSON.stringify({ ok: true, claimed: true, gateway_secret: s.GATEWAY_SECRET, doc_token: s.DOC_TOKEN }),
    { headers: { "content-type": "application/json", "cache-control": "no-store" } });
}
async function claimSigOk(env, host, b) {
  try {
    const hex = (h) => Uint8Array.from(String(h).match(/../g) || [], (x) => parseInt(x, 16));
    const sigb = hex(b.sig || "");
    if (sigb.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(env.GW_APPROVAL_PUB)) return false;
    const key = await crypto.subtle.importKey("raw", hex(env.GW_APPROVAL_PUB), { name: "Ed25519" }, false, ["verify"]);
    const msg = ["hark-relay-claim-v1", host, String(b.ts), String(b.nonce)].join("\n");
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sigb, enc.encode(msg));
  } catch (e) {
    return false;
  }
}

/* ---------------- pairing through the relay (2.0.4) ---------------- */
// For homes where Hark can't reach Home Assistant. The app (relay address set, not paired yet) posts a one-time
// Diffie-Hellman PUBLIC key; you read the pairing code from the app's Log and tell Hark; Hark lists the waiting
// requests (signed /gw/pairing), picks the one whose fingerprint matches your code, and posts the pairing data sealed
// to that key (signed /gw/pairing/answer). The app fetches the sealed answer by its request id. The relay only ever
// sees public keys and ciphertext. Requests expire after an hour; at most 10 wait at a time.
const PAIR_MAX_WAITING = 10, PAIR_TTL = 3600, PAIR_MAX_PER_IP = 10;
async function pairHousekeep(env) {
  await env.DB.prepare("DELETE FROM pair_reqs WHERE created_at<?").bind(now() - PAIR_TTL).run();
  await env.DB.prepare("DELETE FROM abuse WHERE kind='pair' AND ts<?").bind(now() - 86400).run();
}
async function pairRoute(req, env, url, p) {
  if (!env.GATEWAY_SECRET) return json({ error: "relay not claimed by Hark yet" }, 503);
  await pairHousekeep(env);
  if (req.method === "POST" && p === "/setup/pair") {
    const ipHash = await sha((env.IP_SALT || "salt") + "pair" + ipKey(req.headers.get("cf-connecting-ip") || "0.0.0.0"));
    const mine = (await env.DB.prepare("SELECT COUNT(*) AS n FROM abuse WHERE ip_hash=? AND kind='pair' AND ts>?").bind(ipHash, now() - 3600).first()).n;
    if (mine >= PAIR_MAX_PER_IP) return json({ error: "too many pairing requests" }, 429);
    await env.DB.prepare("INSERT INTO abuse(ip_hash, kind, ts) VALUES(?,?,?)").bind(ipHash, "pair", now()).run();
    const raw = await req.text();
    if (raw.length > 2000) return json({ error: "too large" }, 413);
    let b; try { b = JSON.parse(raw); } catch { return json({ error: "bad request" }, 400); }
    const pub = String((b && b.app_public) || "").toLowerCase();
    if (!/^[0-9a-f]{64,600}$/.test(pub)) return json({ error: "app_public must be a hex public key" }, 400);
    const waiting = (await env.DB.prepare("SELECT COUNT(*) AS n FROM pair_reqs WHERE answer IS NULL").first()).n;
    if (waiting >= PAIR_MAX_WAITING) return json({ error: "too many pairing requests waiting; try again later" }, 429);
    const id = newId() + newId();
    await env.DB.prepare("INSERT INTO pair_reqs(id, app_public, v, created_at) VALUES(?,?,?,?)")
      .bind(id, pub, String((b && b.v) || "").slice(0, 20), now()).run();
    return json({ id, expires_in: PAIR_TTL });
  }
  const id = p.split("/")[3];
  if (req.method === "GET" && id && /^[a-z0-9]{20}$/.test(id)) {
    const row = await longPoll(env, url, "pair:" + id, async () => {
      const r = await env.DB.prepare("SELECT answer FROM pair_reqs WHERE id=?").bind(id).first();
      return r && r.answer ? r : null;
    });
    if (row) {   // one-shot: the sealed answer is handed out once, then forgotten
      await env.DB.prepare("DELETE FROM pair_reqs WHERE id=?").bind(id).run();
      return new Response(JSON.stringify({ answer: JSON.parse(row.answer) }), { headers: { "content-type": "application/json", "cache-control": "no-store" } });
    }
    const still = await env.DB.prepare("SELECT 1 AS x FROM pair_reqs WHERE id=?").bind(id).first();
    return still ? new Response(null, { status: 204 }) : json({ error: "not found or expired" }, 404);
  }
  return json({ error: "not found" }, 404);
}

/* ---------------- command queue ---------------- */
// Hark signs every command with GATEWAY_SECRET (HMAC-SHA256). Change-tier commands wait as "pending_approval" until a
// separately signed approve call arrives. v1.1: Hark normally pushes commands through Home Assistant (event
// hark_gateway_command); this queue is the record + safety net, checked by the app with a short /gw/next once a minute.
// Must match the app's tools.tier_of(): change-tier commands are held here until an approval arrives.
const GW_CHANGE_TOOLS = ["wol", "ssh", "ha_service", "ha_file_write", "lovelace_save"];
// 1.2: every /gw route needs request auth (X-GW-Auth); approvals must also carry an Ed25519 "esig" made with Hark's
// separate approval key when GW_APPROVAL_PUB (hex public key) is set. Repeated auth failures from one address get 429.
function gwTier(tool, args) {
  if (GW_CHANGE_TOOLS.includes(tool)) return "change";
  const m = String((args && args.method) || "GET").toUpperCase();
  if (tool === "http" && !["GET", "HEAD"].includes(m)) return "change";
  if ((tool === "opnsense" || tool === "firewall") && m !== "GET") return "change";
  return "read";
}
async function gwIpHash(req, env) {
  return sha((env.IP_SALT || "salt") + ipKey(req.headers.get("cf-connecting-ip") || "0.0.0.0"));
}
async function gwFailures(env, ipHash) {
  return (await env.DB.prepare("SELECT COUNT(*) AS n FROM abuse WHERE ip_hash=? AND kind='gw' AND ts>?").bind(ipHash, now() - 3600).first()).n;
}
async function gwApprovalOk(env, kind, a, c) {
  if (!env.GW_APPROVAL_PUB) return false;           // fail closed: no approval key configured = no approvals
  try {
    const hex = (h) => Uint8Array.from(String(h).match(/../g) || [], (x) => parseInt(x, 16));
    const sigb = hex(a.esig || "");
    if (sigb.length !== 64) return false;
    const key = await crypto.subtle.importKey("raw", hex(env.GW_APPROVAL_PUB), { name: "Ed25519" }, false, ["verify"]);
    const body = await sha256Hex(c.tool + "\n" + c.args);
    const msg = ["hark-gw-approve-v2", kind, a.id, a.ts, a.nonce, c.sig, body].join("\n");
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sigb, enc.encode(msg));
  } catch (e) {
    return false;
  }
}
const hexOf = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmacHex(secret, msg) {
  const k = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hexOf(await crypto.subtle.sign("HMAC", k, enc.encode(msg)));
}
const sha256Hex = async (s) => hexOf(await crypto.subtle.digest("SHA-256", typeof s === "string" ? enc.encode(s) : s));
function safeEq(a, b) {
  a = String(a || ""); b = String(b || "");
  if (a.length !== b.length || !a.length) return false;
  let r = 0; for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const GW_MAX_AGE = 120;
async function useNonce(env, nonce) {
  if (!/^[A-Za-z0-9_-]{12,64}$/.test(String(nonce || ""))) return false;
  if (await env.DB.prepare("SELECT 1 AS x FROM gw_nonces WHERE nonce=?").bind(nonce).first()) return false;
  if (await env.DB.prepare("SELECT 1 AS x FROM gw_cmds WHERE nonce=?").bind(nonce).first()) return false;
  await env.DB.prepare("INSERT INTO gw_nonces(nonce, ts) VALUES(?,?)").bind(nonce, now()).run();
  return true;
}
const fresh = (ts) => Number.isFinite(+ts) && Math.abs(now() - +ts) <= GW_MAX_AGE;
// Request auth (polls, results, reads): header X-GW-Auth: "<ts>.<nonce>.<hex sig>",
// sig = HMAC(secret, "req\n" + METHOD + "\n" + path + "\n" + ts + "\n" + nonce + "\n" + sha256(body))
async function gwReqAuth(req, env, path, bodyBytes) {
  const [ts, nonce, sig] = String(req.headers.get("x-gw-auth") || "").split(".");
  if (!ts || !nonce || !sig || !fresh(ts)) return false;
  const msg = ["req", req.method, path, ts, nonce, await sha256Hex(bodyBytes || new Uint8Array())].join("\n");
  if (!safeEq(sig, await hmacHex(env.GATEWAY_SECRET, msg))) return false;
  return useNonce(env, nonce);
}
const cmdMsg = (c) => [c.id, c.ts, c.nonce, c.tool, c.args].join("\n");
const approveMsg = (kind, a, cmdSig) => [kind, a.id, a.ts, a.nonce, cmdSig].join("\n");
const gwView = (r) => r && ({
  id: r.id, ts: r.ts, nonce: r.nonce, tool: r.tool, tier: r.tier, status: r.status, sig: r.sig, ok: r.ok === null ? null : !!r.ok,
  args: (() => { try { return JSON.parse(r.args); } catch { return r.args; } })(),
  result: r.result ? (() => { try { return JSON.parse(r.result); } catch { return r.result; } })() : null,
  created_at: r.created_at, sent_at: r.sent_at, done_at: r.done_at,
});

async function gwHousekeep(env) {
  const t = now();
  await env.DB.prepare("UPDATE gw_cmds SET status='expired', done_at=? WHERE status IN ('pending_approval','queued') AND created_at<?").bind(t, t - 86400).run();
  await env.DB.prepare("UPDATE gw_cmds SET status='lost', done_at=? WHERE status='sent' AND sent_at<?").bind(t, t - 900).run();
  await env.DB.prepare("DELETE FROM gw_nonces WHERE ts<?").bind(t - 600).run();
  await env.DB.prepare("DELETE FROM gw_cmds WHERE created_at<?").bind(t - 30 * 86400).run();
  // results and arguments (which can hold device passwords or command output) are dropped after 7 days
  await env.DB.prepare("UPDATE gw_cmds SET result=NULL, args='{}' WHERE done_at IS NOT NULL AND done_at<? AND result IS NOT NULL").bind(t - 7 * 86400).run();
  await env.DB.prepare("DELETE FROM abuse WHERE kind IN ('gw','claim') AND ts<?").bind(t - 86400).run();
}

async function gwRoute(req, env, url, p) {
  if (!env.GATEWAY_SECRET) return json({ error: "gateway not configured" }, 503);
  const parts = p.split("/").filter(Boolean); // ["gw", action, id?]
  const action = parts[1], id = parts[2];
  const body = req.method === "POST" ? new Uint8Array(await req.arrayBuffer()) : new Uint8Array();
  if (body.length > 300000) return json({ error: "too large" }, 413);
  const parse = () => { try { return JSON.parse(new TextDecoder().decode(body)); } catch { return null; } };
  // every route needs request auth; too many failures from one address in an hour -> 429 without further work
  const ipHash = await gwIpHash(req, env);
  if (!(await gwReqAuth(req, env, p, body))) {
    if ((await gwFailures(env, ipHash)) >= 60) return json({ error: "too many failed attempts" }, 429);
    await env.DB.prepare("INSERT INTO abuse(ip_hash, kind, ts) VALUES(?,?,?)").bind(ipHash, "gw", now()).run();
    return json({ error: "unauthorized" }, 401);
  }
  // first correctly signed request with the claimed secrets: Hark has them, so the claim can never be repeated
  if ((await getSetting(env, "claim_state")) === "claimed") await setSetting(env, "claim_state", "confirmed");

  // ---- Hark: enqueue a command (signed body, no header needed) ----
  if (req.method === "POST" && action === "cmd") {
    const c = parse();
    if (!c || typeof c.args !== "string" || !c.id || !c.tool || !c.sig) return json({ error: "unauthorized" }, 401);
    if (!/^[A-Za-z0-9_-]{6,40}$/.test(c.id) || !/^[a-z_]{2,30}$/.test(c.tool) || c.args.length > 16000) return json({ error: "bad command" }, 400);
    if (!fresh(c.ts)) return json({ error: "unauthorized: stale or missing timestamp" }, 401);
    if (!safeEq(c.sig, await hmacHex(env.GATEWAY_SECRET, cmdMsg(c)))) return json({ error: "unauthorized: bad signature" }, 401);
    let args; try { args = JSON.parse(c.args); } catch { return json({ error: "args must be JSON" }, 400); }
    if (await env.DB.prepare("SELECT 1 AS x FROM gw_cmds WHERE id=?").bind(c.id).first()) return json({ error: "duplicate id" }, 409);
    if (!(await useNonce(env, c.nonce))) return json({ error: "unauthorized: nonce reused" }, 401);
    await env.DB.prepare("DELETE FROM gw_nonces WHERE nonce=?").bind(c.nonce).run(); // kept on the command row instead
    const tier = gwTier(c.tool, args);
    const st = tier === "change" ? "pending_approval" : "queued";
    await env.DB.prepare("INSERT INTO gw_cmds(id,ts,nonce,tool,args,sig,tier,status,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
      .bind(c.id, +c.ts, c.nonce, c.tool, c.args, c.sig, tier, st, now()).run();
    await gwHousekeep(env);
    if (st === "queued") env.NOTIFY?.("gw");
    return json({ id: c.id, tier, status: st });
  }
  // ---- Hark: approve / deny a held change command (signed body bound to the command's signature) ----
  if (req.method === "POST" && (action === "approve" || action === "deny")) {
    const a = parse();
    if (!a || !a.id || !a.sig || !fresh(a.ts)) return json({ error: "unauthorized" }, 401);
    const c = await env.DB.prepare("SELECT * FROM gw_cmds WHERE id=?").bind(a.id).first();
    if (!c) return json({ error: "not found" }, 404);
    if (!safeEq(a.sig, await hmacHex(env.GATEWAY_SECRET, approveMsg(action, a, c.sig)))) return json({ error: "unauthorized: bad signature" }, 401);
    if (!(await gwApprovalOk(env, action, a, c))) return json({ error: "unauthorized: approval key signature missing or bad" }, 401);
    if (!(await useNonce(env, a.nonce))) return json({ error: "unauthorized: nonce reused" }, 401);
    if (c.status !== "pending_approval") return json({ error: "command is " + c.status }, 409);
    if (action === "deny") {
      await env.DB.prepare("UPDATE gw_cmds SET status='denied', done_at=? WHERE id=?").bind(now(), c.id).run();
      env.NOTIFY?.("res:" + c.id);
      return json({ id: c.id, status: "denied" });
    }
    const approval = JSON.stringify({ id: a.id, ts: +a.ts, nonce: a.nonce, sig: a.sig, esig: String(a.esig || "").slice(0, 128) });
    // v1.1: ?via=ha means Hark already delivered command + approval through Home Assistant; keep this as the record
    // only (status 'sent'), so the app's safety-net check of /gw/next never delivers it a second time.
    if (url.searchParams.get("via") === "ha") {
      await env.DB.prepare("UPDATE gw_cmds SET status='sent', sent_at=?, approval=? WHERE id=?").bind(now(), approval, c.id).run();
      return json({ id: c.id, status: "sent", via: "ha" });
    }
    await env.DB.prepare("UPDATE gw_cmds SET status='queued', approval=? WHERE id=?").bind(approval, c.id).run();
    env.NOTIFY?.("gw");
    return json({ id: c.id, status: "queued" });
  }

  // (request auth already checked above for every route)

  if (req.method === "GET" && action === "hello") { // app start-up: hands over PRINT_TOKEN (nothing extra to paste)
    await setSetting(env, "gw_hello", JSON.stringify({ t: now(), v: url.searchParams.get("v") || "" }));
    // the field is named bridge_token because that is the name the app reads; it carries PRINT_TOKEN
    return json({ ok: true, bridge_token: printToken(env) || null, site: url.origin, server_time: now() });
  }
  // ---- app: the doorbell WebSocket (2.0.4). Carries only "wake" notices, never commands. ----
  if (req.method === "GET" && action === "ws") {
    if ((req.headers.get("upgrade") || "").toLowerCase() !== "websocket" || !env.ACCEPT_WS) return json({ error: "websocket upgrade required" }, 426);
    return env.ACCEPT_WS();
  }
  // ---- Hark: pairing through the relay (2.0.4) ----
  if (req.method === "GET" && action === "pairing") {
    await pairHousekeep(env);
    const r = await env.DB.prepare("SELECT id, app_public, v, created_at FROM pair_reqs WHERE answer IS NULL ORDER BY created_at DESC LIMIT 10").all();
    return json({ requests: r.results });
  }
  if (req.method === "POST" && action === "pairing" && id === "answer") {
    const a = parse();
    if (!a || !/^[a-z0-9]{20}$/.test(String(a.id || "")) || !a.answer || typeof a.answer !== "object") return json({ error: "id and answer required" }, 400);
    const s = JSON.stringify(a.answer);
    if (s.length > 4000) return json({ error: "too large" }, 413);
    const row = await env.DB.prepare("SELECT answer FROM pair_reqs WHERE id=?").bind(a.id).first();
    if (!row) return json({ error: "not found or expired" }, 404);
    if (row.answer) return json({ error: "already answered" }, 409);
    await env.DB.prepare("UPDATE pair_reqs SET answer=? WHERE id=?").bind(s, a.id).run();
    env.NOTIFY?.("pair:" + a.id);
    return json({ ok: true });
  }
  if (req.method === "GET" && action === "next") {
    await setSetting(env, "gw_last_poll", JSON.stringify({ t: now(), v: url.searchParams.get("v") || "", enabled: url.searchParams.get("enabled"), ha: url.searchParams.get("ha") }));
    await gwHousekeep(env);
    const c = await longPoll(env, url, "gw", async () => {
      const x = await env.DB.prepare("SELECT * FROM gw_cmds WHERE status='queued' ORDER BY created_at LIMIT 1").first();
      if (!x) return null;
      await env.DB.prepare("UPDATE gw_cmds SET status='sent', sent_at=? WHERE id=?").bind(now(), x.id).run();
      return x;
    });
    if (!c) return new Response(null, { status: 204 });
    return json({ cmd: { id: c.id, ts: c.ts, nonce: c.nonce, tool: c.tool, args: c.args, sig: c.sig, tier: c.tier,
      approval: c.approval ? JSON.parse(c.approval) : null }, server_time: now() });
  }
  if (req.method === "POST" && action === "result") {
    const r = parse();
    if (!r || !r.id) return json({ error: "id required" }, 400);
    const st = r.status === "rejected" ? "rejected" : r.ok ? "done" : "error";
    // v1.1: commands delivered through Home Assistant have no row yet; the app sends the signed command along
    const c = r.cmd;
    if (c && c.id === r.id && typeof c.args === "string" && c.nonce && c.tool) {
      let a = null; try { a = JSON.parse(c.args); } catch {}
      await env.DB.prepare("INSERT OR IGNORE INTO gw_cmds(id,ts,nonce,tool,args,sig,tier,status,created_at,sent_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind(String(c.id).slice(0, 40), int(c.ts, now()), String(c.nonce).slice(0, 64), String(c.tool).slice(0, 30), c.args.slice(0, 16000),
          String(c.sig || ""), gwTier(c.tool, a), "sent", now(), now()).run();
    }
    // a duplicate delivery is refused by the app as a replay; never let that refusal overwrite the real result
    const guard = st === "rejected" ? " AND status NOT IN ('done','error')" : "";
    await env.DB.prepare("UPDATE gw_cmds SET status=?, ok=?, result=?, done_at=? WHERE id=?" + guard)
      .bind(st, r.ok ? 1 : 0, JSON.stringify(r.result ?? null).slice(0, 250000), now(), r.id).run();
    if (r.via === "ha") await setSetting(env, "gw_last_ha_result", String(now()));
    env.NOTIFY?.("res:" + r.id);
    return json({ ok: true });
  }
  if (req.method === "GET" && action === "result" && id) {
    const done = ["done", "error", "rejected", "denied", "expired", "lost"];
    const row = await longPoll(env, url, "res:" + id, async () => {
      const x = await env.DB.prepare("SELECT * FROM gw_cmds WHERE id=?").bind(id).first();
      return x && done.includes(x.status) ? x : null;
    }) || await env.DB.prepare("SELECT * FROM gw_cmds WHERE id=?").bind(id).first();
    if (!row) return json({ error: "not found" }, 404);
    return json(gwView(row));
  }
  if (req.method === "GET" && action === "list") {
    const r = await env.DB.prepare("SELECT * FROM gw_cmds ORDER BY created_at DESC LIMIT 30").all();
    return json({ commands: r.results.map((x) => { const v = gwView(x); if (v.result && JSON.stringify(v.result).length > 400) v.result = "(large; fetch /gw/result/" + x.id + ")"; return v; }) });
  }
  if (req.method === "GET" && action === "status") {
    const lp = JSON.parse((await getSetting(env, "gw_last_poll")) || "null");
    const hello = JSON.parse((await getSetting(env, "gw_hello")) || "null");
    const pend = await env.DB.prepare("SELECT COUNT(*) AS n FROM gw_cmds WHERE status='pending_approval'").first();
    const dlp = int(await getSetting(env, "docs_last_poll"), 0);
    const lhr = int(await getSetting(env, "gw_last_ha_result"), 0);
    return json({ app_seen_sec_ago: lp ? now() - lp.t : null, app_version: lp?.v || hello?.v || null, app_enabled: lp?.enabled ?? null,
      app_listening_on_ha: lp?.ha == null ? null : lp.ha === "1", last_ha_result_sec_ago: lhr ? now() - lhr : null,
      app_hello_sec_ago: hello ? now() - hello.t : null, pending_approval: pend.n,
      docs_poll_sec_ago: dlp ? now() - dlp : null, docs_printer: await getSetting(env, "docs_printer") });
  }
  return json({ error: "not found" }, 404);
}

/* ---------------- storage: one Durable Object with SQLite, behind a tiny D1-style shim ---------------- */
import { DurableObject } from "cloudflare:workers";

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS docs (id TEXT PRIMARY KEY, name TEXT, bytes INTEGER, opts TEXT, status TEXT NOT NULL, detail TEXT,
     attempts INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, sent_at INTEGER, done_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS idx_docs_status ON docs(status, created_at)`,
  `CREATE TABLE IF NOT EXISTS doc_chunks (doc_id TEXT NOT NULL, seq INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY (doc_id, seq))`,
  `CREATE TABLE IF NOT EXISTS gw_cmds (id TEXT PRIMARY KEY, ts INTEGER NOT NULL, nonce TEXT NOT NULL UNIQUE, tool TEXT NOT NULL, args TEXT NOT NULL,
     sig TEXT NOT NULL, tier TEXT NOT NULL, status TEXT NOT NULL, approval TEXT, result TEXT, ok INTEGER, created_at INTEGER NOT NULL,
     sent_at INTEGER, done_at INTEGER)`,
  `CREATE INDEX IF NOT EXISTS idx_gw_status ON gw_cmds(status, created_at)`,
  `CREATE TABLE IF NOT EXISTS gw_nonces (nonce TEXT PRIMARY KEY, ts INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS abuse (ip_hash TEXT NOT NULL, kind TEXT NOT NULL, ts INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS idx_abuse_ip ON abuse(ip_hash, ts)`,
  `CREATE INDEX IF NOT EXISTS idx_abuse_ts ON abuse(ts)`,
  `CREATE TABLE IF NOT EXISTS pair_reqs (id TEXT PRIMARY KEY, app_public TEXT NOT NULL, v TEXT, answer TEXT, created_at INTEGER NOT NULL)`,
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
    this.db = shim(ctx.storage.sql);
    this.waiters = new Map(); // channel -> Set of resolve functions (long-poll)
    // doorbell keep-alive: "ping" gets "pong" without waking this object (hibernation keeps it free when idle)
    try { ctx.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong")); } catch (e) {}
  }
  acceptWs() {
    const old = this.ctx.getWebSockets("app");
    for (const ws of old.slice(0, Math.max(0, old.length - 2))) { try { ws.close(4000, "replaced"); } catch (e) {} }  // keep at most 3
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, ["app"]);
    server.send(JSON.stringify({ hello: true, server_time: now() }));
    return new Response(null, { status: 101, webSocket: client });
  }
  webSocketMessage(ws, msg) {
    if (msg === "ping") ws.send("pong");
  }
  webSocketClose(ws, code) {
    try { ws.close(code === 1005 || code === 1006 ? 1000 : code, "bye"); } catch (e) {}
  }
  webSocketError(ws) {
    try { ws.close(1011, "error"); } catch (e) {}
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
    if (ch === "gw" || ch === "docs")   // ring the app's doorbell; it fetches the work over the signed HTTP routes
      for (const ws of this.ctx.getWebSockets("app")) { try { ws.send(JSON.stringify({ wake: ch })); } catch (e) {} }
  }
  async fetch(req) {
    return app.fetch(req, { ...this.env, DB: this.db, WAIT: (c, ms) => this.wait(c, ms), NOTIFY: (c) => this.notify(c),
      ACCEPT_WS: () => this.acceptWs() },
      { waitUntil: (p) => this.ctx.waitUntil(p) });
  }
}

/* ---- shared encoder (request signing) ---- */
const enc = new TextEncoder();

export default {
  async fetch(req, env) {
    const stub = env.STORE.get(env.STORE.idFromName("main"));
    return stub.fetch(req);
  },
};

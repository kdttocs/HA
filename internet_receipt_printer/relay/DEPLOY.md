# Deploy your receipt relay (free Cloudflare Worker)

The relay is a tiny program that runs on Cloudflare's servers, not in your home. It shows the public web page where
people type a message, keeps the messages in a queue, and hands them to the Internet Receipt Printer app in your Home
Assistant, which prints them. You run your own copy, so the messages sit in your own Cloudflare account, and nothing
is opened on your router.

**Cost:** nothing on Cloudflare's free plan. The app checks the queue about once a minute while the printer is
ready (roughly 1,500 requests a day; the free plan allows 100,000 a day for your whole Cloudflare account), plus a
few requests per message. Check current limits at https://developers.cloudflare.com/workers/platform/pricing/ and
https://developers.cloudflare.com/durable-objects/platform/pricing/.

**Time:** about 15 minutes, once.

---

## What you need

1. A computer (Windows, Mac or Linux) for the setup. Only for these 15 minutes; it doesn't have to stay on.
2. A free Cloudflare account: https://dash.cloudflare.com/sign-up
3. **Node.js** (the free program that runs Cloudflare's setup tool): install the "LTS" version from
   https://nodejs.org. To check it worked, open a terminal (Mac: *Terminal*; Windows: *PowerShell*) and type
   `node --version`. You should see a version number.

## Step 1. Get the relay files

Download the repository: on https://github.com/kdttocs/HA tap **Code > Download ZIP** and unzip it. Open a terminal
in the `internet_receipt_printer/relay` folder inside it. (Mac: right-click the folder > *New Terminal at Folder*.
Windows: open the folder, click the address bar, type `powershell`, press Enter.)

## Step 2. Make your settings file

Copy `wrangler.toml.example` to a new file named `wrangler.toml` in the same folder.

- Optional: change `name = "receipt-relay"` to any name you like (letters, digits, dashes). Your relay's address
  will start with `https://<name>.` followed by your free Cloudflare subdomain.
- Set `SITE_TITLE` (the page's title, also printed on each receipt) and `TIMEZONE` (for example
  `"America/New_York"` or `"Europe/Berlin"`; used for receipt times and quiet hours).
- Leave `RECEIPT_FORM = "off"` for now. You switch the form on in step 7, once the printer works.
- The other settings (limits, quiet hours) are explained next to each one; the defaults suit most homes.

## Step 3. Sign in to Cloudflare from the terminal

```
npx wrangler login
```

The first time, it asks to install "wrangler" (Cloudflare's tool); answer **y**. A browser window opens: allow access.

## Step 4. Put the relay online

```
npx wrangler deploy
```

At the end it prints your relay's address (starting with `https://receipt-relay.`). **Write it down.** Check it
works by opening `https://<your address>/healthz` in a browser: it should say `ok`.

## Step 5. Add the secrets

Make each secret with this command (it prints 64 random characters; run it once per secret):

```
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Then store each with `npx wrangler secret put NAME`, paste the value when asked, and press Enter:

| Secret | What it is |
| --- | --- |
| `RECEIPT_TOKEN` | The key the app uses to collect messages. **Keep a copy** for step 6. |
| `IP_SALT` | Scrambles visitor addresses for the rate limits (any random value; you never need it again). |
| `TURNSTILE_SECRET` | Optional, only with Cloudflare Turnstile (see "Protections"). |

## Step 6. Connect the app to the relay

Install **Internet Receipt Printer** in Home Assistant (see its Documentation tab), then connect it one of two ways:

- **Paste:** in the app's **Configuration** tab, put your relay address in `queue_url` and `RECEIPT_TOKEN` in
  `queue_token`. Save, then start the app.
- **Pair with Hark (no pasting in Home Assistant), only if Hark can reach your Home Assistant with an access
  token:** give Hark, through its secure form (never in a chat message),
  your relay address and `RECEIPT_TOKEN`. Leave `queue_url` and `queue_token` empty, start the app, and tell Hark
  "pair the receipt printer". Hark checks the app's pairing fingerprint against the app's own log and sends the
  address and token sealed (encrypted) for this app only. The log then says `receipt pairing: done`.

Watch the app's **Log**: it finds the printer and prints a short "Hello" receipt the first time.

## Step 7. Switch the form on

In `wrangler.toml` set `RECEIPT_FORM = "on"` and run `npx wrangler deploy` again. Open your relay address in a
browser, type a message, and watch it print. Share the address with whoever you like.

To take the form offline again, set `RECEIPT_FORM = "off"` and deploy. Messages already waiting stay in the queue.

## Protections

Built into the public form: a small proof-of-work puzzle in the visitor's browser (stops scripts), per-visitor and
site-wide limits, a daily paper cap (`GLOBAL_DAILY`), a cap on waiting messages (`MAX_WAITING`), no links/phone
numbers/e-mail addresses, a word filter (`EXTRA_BLOCKLIST` adds your own), duplicate detection, temporary bans for
repeated refused attempts, an automatic pause after a flood, and quiet hours (`QUIET_START_HOUR`/`QUIET_END_HOUR`).
Optional extra bot check: Cloudflare Turnstile (`TURNSTILE_SITE_KEY` in `wrangler.toml` + secret `TURNSTILE_SECRET`).

## Updating later

Download the new files, keep your `wrangler.toml`, and run `npx wrangler deploy` again from the
`internet_receipt_printer/relay` folder. Secrets and waiting messages stay.

## What the relay does (for the curious)

| Address | Who uses it | Protection |
| --- | --- | --- |
| `/`, `/api/*` | the public form (only when `RECEIPT_FORM = "on"`) | the protections above |
| `/bridge/next`, `/bridge/ack` | the app: take the next message, report it printed | `RECEIPT_TOKEN` |
| `/healthz` | you | says `ok` |

Everything else answers "Not found". Messages stay in your relay's storage; visitor addresses are kept only as
scrambled (salted) hashes.

## Troubleshooting

- `wrangler deploy` says something about Durable Objects or migrations: make sure your `wrangler.toml` still has the
  `[[durable_objects.bindings]]` and `[[migrations]]` parts from the example.
- The app says "relay error" and its log mentions 401: its `queue_token` doesn't match `RECEIPT_TOKEN`.
- The page says "Not found": `RECEIPT_FORM` is still `"off"` (step 7).
- Messages queue but don't print: check quiet hours (`QUIET_START_HOUR`/`QUIET_END_HOUR`) and the app's status
  (`sensor.internet_receipt_printer`).

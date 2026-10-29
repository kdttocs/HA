# Set up your relay (free Cloudflare Worker)

The relay is a tiny program that runs on Cloudflare's servers, not in your home. It is the meeting point between
Hark and the Hark Home Assistant Gateway app in your Home Assistant:

- Hark leaves its signed commands on the relay. The app keeps a connection open *out* to the relay, so the relay can
  tell it at once when something is waiting (usually within a second or two); the app also checks once a minute as a
  safety net. Hark doesn't need access to your Home Assistant.
- Hark puts documents it wants printed in the relay's private document queue; the app picks them up and prints them.

It holds no passwords to your home. Everything Hark sends through it is signed, and changes need an approval signed
with a key only Hark holds. You run your own copy, so your data sits in your own Cloudflare account.

**Cost:** nothing on Cloudflare's free plan. The app makes roughly 3,000 requests a day plus a few hundred for its
open connection's keep-alive (the free plan allows 100,000 a day for your whole Cloudflare account). The open
connection rests ("hibernates") between messages, so it uses almost none of the free compute time, and the relay
uses a small fraction of the free storage. Check current limits
at https://developers.cloudflare.com/workers/platform/pricing/ and
https://developers.cloudflare.com/durable-objects/platform/pricing/.

---

## Quick setup (about 3 minutes, no terminal)

You need a free **Cloudflare** account (https://dash.cloudflare.com/sign-up) and a free **GitHub** account
(https://github.com/signup). Cloudflare puts a copy of the relay in your GitHub account and runs it from there.

1. **Ask Hark for its approval public key.** Say "give me the approval public key for my relay". It is 64 letters
   and digits, and it is safe to share (it can only *check* Hark's signatures, never make them). (Hark: your side
   of this setup is in `hark_gateway/hark/HARK.md` in this repository.)
2. **Click the button**, sign in to Cloudflare and GitHub when asked, paste the key into **GW_APPROVAL_PUB**, and
   press **Deploy**. You can keep every other setting as it is.

   [![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/kdttocs/HA/tree/main/hark_gateway/relay)

3. **Give Hark your relay's address.** When the deploy finishes, Cloudflare shows it (it starts with
   `https://hark-relay.`). Send it to Hark. Hark claims the relay: the relay makes its
   own secret keys, hands them to Hark once over a signed request, and from then on refuses to hand them out again.
   You never see or copy a secret.

Then install **Hark Home Assistant Gateway** in Home Assistant (see its Documentation tab), put this relay's address
into the app's **Relay address** option, start it, and read Hark the pairing code from the app's Log.

To check the relay is up, open `https://<your address>/healthz`: it shows `"ok":true`, and `"claimed":true` once
Hark has claimed it.

## Updating later

Your relay runs from the copy in your GitHub account, and Cloudflare redeploys it automatically every time that copy
changes. The relay's secrets and queued items stay through every update.

To update to a newer relay:

1. Open the newest `worker.js` at https://github.com/kdttocs/HA/blob/main/hark_gateway/relay/worker.js and copy all
   of it (the **Copy raw file** button at the top right of the file).
2. In your own GitHub copy, open `worker.js`, tap the **pencil** (Edit), select everything, paste, and tap
   **Commit changes**.
3. Cloudflare redeploys within a minute or two (you can watch it under your Worker > **Deployments**).

Or ask Hark to walk you through it. You don't need to update unless a new version's notes say the relay changed.
App version 2.0.4 changed the relay: relays from before it have no fast path (commands take up to a minute) and
can't pair through the relay, so update yours if you set it up earlier.

## If something goes wrong

- **Hark says the claim was refused with "set by hand".** Someone set `GATEWAY_SECRET` or `DOC_TOKEN` on the relay
  by hand. Use the manual way below, or delete those two secrets in the Cloudflare dashboard (Worker > **Settings** >
  **Variables and Secrets**) and ask Hark to claim again.
- **Hark lost the relay's keys, or you think they leaked.** A relay hands out its keys only once, so set new ones by
  hand: in the Cloudflare dashboard (Worker > **Settings** > **Variables and Secrets**) add `GATEWAY_SECRET` and
  `DOC_TOKEN` as secrets with new random values (a value you set there always wins over the relay's own), give
  them to Hark through its secure form, and re-pair the app (`reset_pairing`, see the app's Documentation tab).
  Or delete the Worker and deploy a fresh one with the button.
- **"GW_APPROVAL_PUB is missing"**: add it in the Cloudflare dashboard (Worker > **Settings** > **Variables and
  Secrets**, type *Secret*) with the key from Hark.
- **The app's log says "401"**: the relay's `GATEWAY_SECRET` doesn't match what the app was paired with. Tell Hark.
- **Documents don't print and the app's log says "print token missing"**: restart the app; it fetches the print
  token from the relay when it starts.

---

## Advanced: manual setup with the terminal

Only if you prefer not to use the button. About 15 minutes.

**You need:** a computer (Windows, Mac or Linux) for these 15 minutes, a free Cloudflare account, and **Node.js**
(install the "LTS" version from https://nodejs.org; `node --version` in a terminal should print a version number).

1. **Get the files.** On https://github.com/kdttocs/HA tap **Code > Download ZIP**, unzip it, and open a terminal in
   the `hark_gateway/relay` folder. (Mac: right-click the folder > *New Terminal at Folder*. Windows: open the
   folder, click the address bar, type `powershell`, press Enter.)
2. **Optional:** in `wrangler.toml`, change `name = "hark-relay"` to any name you like (letters, digits, dashes).
3. **Sign in:** `npx wrangler login` (answer **y** to install wrangler, Cloudflare's tool; allow access in the
   browser window that opens).
4. **Put it online:** `npx wrangler deploy`. Write down the address it prints at the end.
5. **Add Hark's approval public key:** `npx wrangler secret put GW_APPROVAL_PUB` and paste the key from Hark.
6. **Hand it to Hark**, one of two ways:
   - **Easiest:** give Hark the relay's address. Hark claims it, exactly as in the quick setup.
   - **Or set every secret yourself.** Make each value with
     `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` and store it with
     `npx wrangler secret put NAME`. Then give Hark your relay address, `GATEWAY_SECRET` and `DOC_TOKEN` through
     its secure form (never in a chat message). A relay with secrets set by hand refuses claims.

| Secret | What it is | Needed? |
| --- | --- | --- |
| `GW_APPROVAL_PUB` | The **public** half of Hark's approval key; approvals and claims that don't match it are refused | always (ask Hark) |
| `GATEWAY_SECRET` | Hark and the app sign every message with it | only for the set-it-yourself way |
| `DOC_TOKEN` | Lets Hark upload documents to print | only for the set-it-yourself way |
| `PRINT_TOKEN` | Lets the app fetch those documents (the app gets it from the relay by itself) | optional; the relay makes one |
| `IP_SALT` | Scrambles addresses for the failed-attempt limit | optional; the relay makes one |

**Updating a manual relay:** download the new files, keep your `wrangler.toml` changes, and run
`npx wrangler deploy` again from the `hark_gateway/relay` folder. Secrets and queued items stay.

- `PRINT_TOKEN` was called `BRIDGE_TOKEN` in earlier copies of this template. A relay that already has
  `BRIDGE_TOKEN` keeps working.
- Relays set up by hand before 2.0.3 keep working unchanged: secrets you set always win, and such a relay never
  hands anything out.
- Earlier copies of this template (app version 2.0.0) also carried a public receipt web form. This template no
  longer does: redeploying it over such a relay removes the form and its queue. If you use that form, set it up
  again from the guide of the app that prints it before you redeploy.

## What the relay does (for the curious)

| Address | Who uses it | Protection |
| --- | --- | --- |
| `/gw/*` | Hark and the app: command queue, approvals, results, status | every request signed with `GATEWAY_SECRET` (time-limited, single-use); approvals also need Hark's approval key; 60 failed attempts an hour from one address = blocked; results deleted after 7 days; refuses everything until the relay has secrets |
| `/docs/*` | Hark uploads, the app prints | `DOC_TOKEN` (upload, status, cancel) / `PRINT_TOKEN` (fetch, report); file data deleted after printing or cancelling (failed jobs: a day later); refuses everything until the relay has secrets |
| `/gw/ws` | the app: the "doorbell" connection | opened with a signed request like every `/gw` call; carries only "something is waiting" notices, never commands or secrets |
| `/setup/pair` | the app (posts a one-time public key) and then fetches Hark's sealed answer | takes only a public key; Hark answers only the request matching the code you read it; answers are encrypted for that app, handed out once; requests expire after an hour; at most 10 waiting, 10 new an hour per address |
| `/setup/claim` | Hark, once | needs a signature from Hark's approval key, for this relay's address, under 2 minutes old, single-use; answers once; 20 failed attempts an hour from one address = blocked |
| `/healthz` | you | `{"ok":true,"claimed":true}` or `false` |

Everything else answers "Not found". The relay's own secrets are kept in its storage (a Durable Object) inside your
Cloudflare account.

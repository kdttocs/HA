# Internet Receipt Printer

Put a little web page on the internet where anyone with the link can type a short message, and it prints on a
receipt printer at your home. Messages wait in **your own relay** (a free Cloudflare Worker you deploy from this
app's `relay` folder); this app collects them and prints them. Nothing is opened on your router.

```
someone's phone  ->  your relay's web form  ->  receipt queue  ->  this app  ->  receipt printer on your network
```

## What you need

- A network receipt printer that speaks **ESC/POS on port 9100** (most point-of-sale receipt printers with an Ethernet or Wi-Fi
  interface). Paper loaded, plugged into your network.
- Your receipt relay (one time, about 15 minutes, free), with the step-by-step guide:
  https://github.com/kdttocs/HA/blob/main/internet_receipt_printer/relay/DEPLOY.md
  You'll need its address (the `https://receipt-relay...` address Cloudflare printed when you deployed) and its
  `RECEIPT_TOKEN`.

## Install

1. Home Assistant: **Settings > Apps > App store > ⋮ > Repositories**, add `https://github.com/kdttocs/HA` (skip if
   it's already there).
2. Find **Internet Receipt Printer**, tap **Install**.
3. Connect it to your relay, one of two ways:
   - **Paste (the usual way):** **Configuration** tab: your relay address into `queue_url` and the `RECEIPT_TOKEN`
     into `queue_token`. Save.
   - **Pair (no pasting), only if Hark can reach your Home Assistant with an access token** and has your relay
     address and `RECEIPT_TOKEN` (relay guide, step 6): leave both
     empty. Start the app (next step) and tell Hark "pair the receipt printer". The app opens a 30-minute pairing
     window, Hark checks the window's fingerprint against this app's own log and answers with the relay address and
     receipt token sealed (encrypted) for this app only. The log then says `receipt pairing: done`.
4. **Info** tab: turn on **Start on boot**, tap **Start**. Watch the **Log**: it finds the printer and prints a short
   "Hello" receipt the first time.
5. Switch the relay's form on (relay guide, step 7), open your relay's address in a browser, type a message, and
   watch it print.

## How it behaves

- Checks the queue once a minute with one short request, and **only while the printer is ready**, so messages are
  never taken off the queue while the printer is off, out of paper, or has its cover open. They wait on the relay.
- Finds the printer by itself on your network. It never sends anything to a page (laser/inkjet) printer: any device
  that answers on IPP (port 631) is skipped, because whatever reaches a page printer's port 9100 gets printed.
  If it doesn't find yours, set `printer_ip` (a home address like `10.20.30.40`).
- Daily paper guard: at most `daily_receipts` receipts a day (default 200). The relay has its own limits too.
- Printer-control characters are removed from messages before printing.
- Status: `sensor.internet_receipt_printer`: `ready`, `offline`, `no_paper`, `cover_open`, `searching for printer`,
  `printer not found`, `needs setup`, `waiting for pairing`, `daily limit reached` or `relay error`.

## Options

| Option | What it does |
| --- | --- |
| `queue_url` | Your relay's address, `https://...` (no path needed). |
| `queue_token` | The relay's `RECEIPT_TOKEN`. |
| `printer_ip` | Only if the printer isn't found by itself. |
| `daily_receipts` | Most receipts per day (paper guard). |
| `hello_receipt` | Print one "Hello" receipt the first time the printer is found. |
| `pairing` | Allow the 30-minute pairing window when `queue_url`/`queue_token` are empty and nothing is saved (default on). |
| `reset_pairing` | Switch on + restart to forget a saved pairing and pair again (once per switch-on); switch off afterwards. |

## Permissions (and why)

- `host_network`: to find the printer on your home network and reach it.
- `homeassistant_api`: to publish `sensor.internet_receipt_printer` and, only while the pairing window is open, to
  publish a one-time public key (`sensor.internet_receipt_printer_pairing_request`) and read the sealed answer
  (`sensor.internet_receipt_printer_pairing`). Both are deleted when pairing ends.
- Nothing else: no Supervisor access, no folders, no ports opened.

## Pairing safety

(More in this app's security notes: https://github.com/kdttocs/HA/blob/main/internet_receipt_printer/SECURITY.md)

- Only a one-time **public** key is written to Home Assistant. The answer is sealed to that key, so the token never
  sits readable in Home Assistant's history. An answer sealed for an older request is refused.
- Hark refuses to answer if the request's fingerprint doesn't match the one in this app's own log (only Home
  Assistant admins and Hark can read app logs), so nobody can swap in their own key to catch the token.
- After pairing, the log names the relay's host and the fingerprint of the key that answered; Hark checks that it was
  its own answer. Someone with Home Assistant admin rights could, in theory, answer first with their own relay; they
  would only get to print on this receipt printer (within `daily_receipts`), and Hark would report the mismatch.
- The receipt token only opens the receipt queue (`/bridge/next`, `/bridge/ack`); there is nothing else private on
  the relay.
- Options always win: if `queue_url` and `queue_token` are filled in, the app never opens a pairing window.

## Troubleshooting

- **"needs setup":** fill in `queue_url` and `queue_token`, save, restart (or restart and let Hark pair it).
- **"waiting for pairing":** the pairing window is open; ask Hark to pair, or fill in the options.
- **"relay error":** the log says why. With 401, `queue_token` doesn't match the relay's `RECEIPT_TOKEN`; with 404,
  `queue_url` isn't your receipt relay's address.
- **"printer not found":** printer off, not on the same network, or it answers on IPP (then it isn't treated as a
  receipt printer). Set `printer_ip`.
- **Nothing prints but the page says queued:** check the relay's quiet hours (`QUIET_START_HOUR`/`QUIET_END_HOUR`).

# Security: Internet Receipt Printer

How this app and its relay protect your home and your paper, in plain words. Report a problem privately through
GitHub's "Report a vulnerability" (Security tab) rather than in a public issue.

## The big rules

1. **Outbound only.** The app only makes outgoing connections: to your printer on your home network and to your own
   relay. No ports are opened on your router.
2. **The relay key opens one thing.** `RECEIPT_TOKEN` (the app's `queue_token`) only lets its holder take the next
   message off the receipt queue and report it printed (`/bridge/next`, `/bridge/ack`). Your relay has nothing else
   private on it.
3. **Never a page printer.** Receipt (ESC/POS) bytes are never sent to a page printer (laser or inkjet): any device
   that answers on IPP (port 631) is skipped before anything is sent, because whatever reaches a page printer's port
   9100 gets printed.
4. **Paper guards on both ends.** The app prints at most `daily_receipts` a day; the relay has its own daily cap
   (`GLOBAL_DAILY`) and limits. Messages are only taken off the queue while the printer is ready, so nothing is lost
   while it is off or out of paper.
5. **Clean text only.** Printer-control characters are removed from messages before printing; the relay also
   reduces messages to plain printable text.

## The public form (your relay)

The form is off until you set `RECEIPT_FORM = "on"`. Anyone with the link can then send a message, within these
limits:

- a small proof-of-work puzzle in the visitor's browser for every message (stops scripts), harder when busy;
- per-visitor limits (cooldown, hourly, daily; IPv6 counted per /64 network) and site-wide limits (per minute,
  hourly, daily paper cap, a cap on waiting messages);
- no links, phone numbers or e-mail addresses; a word filter (`EXTRA_BLOCKLIST` adds your own); duplicate detection;
- every refused attempt is a strike: too many from one connection = 24-hour ban; a flood site-wide = the form pauses
  for `LOCKDOWN_HOURS`;
- quiet hours (messages wait until morning); optional Cloudflare Turnstile bot check;
- a hidden trap field that bots fill in; requests over 8 KB are refused.

## Pairing (optional, instead of pasting)

- Pairing only happens when `queue_url` and `queue_token` are empty and nothing is saved, for 30 minutes after the
  app starts. Filled-in options always win and disable pairing.
- The app publishes only a one-time **public** key (`sensor.internet_receipt_printer_pairing_request`) and prints
  its fingerprint in its own log. Hark refuses to answer if the published key doesn't match the log (only Home
  Assistant admins and Hark can read app logs), so nobody can swap in their own key to catch the token.
- The answer (relay address + `RECEIPT_TOKEN`) is sealed to that key, so the token never sits readable in Home
  Assistant's history. An answer sealed for an older request is refused. Both pairing sensors are deleted afterwards.
- The pairing is saved in the app's private `/data` folder (readable only by the app).
- Honest limit: someone with Home Assistant admin rights could answer first with their own relay. They would only
  get to print on this receipt printer (within `daily_receipts`); the log names the relay's host and the key that
  answered, and Hark checks afterwards that the app accepted its own answer.

## Privacy

- Messages stay in your relay's storage (your own Cloudflare account). Visitor addresses are stored only as salted
  hashes, used for the rate limits.
- The app keeps only its own state (printer address, daily count, saved pairing) in its private `/data` folder.

## Container permissions

- `host_network`: to find the printer on your home network and reach it.
- `homeassistant_api`: to publish `sensor.internet_receipt_printer` and, only while the pairing window is open, the
  pairing sensors.
- Not requested: `hassio_api`, `docker_api`, `full_access`, `privileged`, devices, ports, folder maps. AppArmor on.
- Stdlib Python on Home Assistant's pinned base image (Python 3.12, Alpine 3.20); nothing is downloaded and run.

## Known limits

- Anyone with the form's link can print, within the limits above. Share the link only as widely as you're happy with.
- Anyone with Home Assistant admin rights can stop the app, change its options or read its log.
- Keep **Auto update** off for this app and use 2FA on any account that can push to this repository.

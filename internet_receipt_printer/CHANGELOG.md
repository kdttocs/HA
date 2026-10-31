# Changelog

## 1.0.4
- Fix: a sleeping laser printer could answer on port 9100 before its IPP service woke up, so the printer search
  mistook it for a receipt printer and its probe printed a junk page (a sheet reading "IC"). The search now checks
  IPP first, then again after waking the printer, and skips any host it is unsure about.

## 1.0.3
- Message text now prints at normal height instead of double height, so longer messages and lists read naturally
  and use less paper.

## 1.0.2
- Relay template fix: a relay without `IP_SALT` used a fixed, public word to sign its bot-check challenges, so they
  could be made up in advance. It now falls back to its secret `RECEIPT_TOKEN`. Redeploy the relay to get the fix
  (the app itself is unchanged).
- Documentation: pasting the relay address and token is the normal setup; pairing through Hark needs Hark to have
  access to your Home Assistant.

## 1.0.1
Housekeeping release; nothing changes in how the app prints.
- Everything about this app now lives in its own folder: its own relay template with a step-by-step guide
  (`relay/DEPLOY.md`, which now also explains pairing with Hark) and its security notes (`SECURITY.md`).
- The relay template carries only the public form and the receipt queue. Fix: a visitor who signed a message
  "admin" was left out of the form's site-wide limits; every message now counts.
- The Configuration tab now explains every option in plain words.
- 32-bit ARM (armv7) is no longer offered; Home Assistant dropped 32-bit support in 2025.12.

## 1.0.0
- First release: your public web form -> your relay's receipt queue -> a network
  ESC/POS receipt printer. Own options (`queue_url`, `queue_token`, `printer_ip`, `daily_receipts`, `hello_receipt`).
- Never sends bytes to a page printer (hosts answering on IPP port 631 are skipped).
- Takes a job off the queue only while the printer is ready; daily paper limit; printer status in
  `sensor.internet_receipt_printer`.
- Strips printer-control characters from web messages before printing.
- Optional pairing instead of pasting: with `queue_url`/`queue_token` empty, a 30-minute window publishes a
  one-time public key; Hark (after checking its fingerprint against this app's log) answers with the relay address
  and receipt token sealed to that key. Saved in /data (0600). New options `pairing` (default on) and
  `reset_pairing`. Options always win over a saved pairing.

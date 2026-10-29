# Changelog

## 2.0.5
- **New-device alerts now say what the device probably is.** Before alerting, the app takes a short, polite look at
  the new device (about 6 seconds at most, in the background): who made it (an offline copy of the public IEEE maker
  list is now part of the app, with plain hints for contract makers like Foxconn and chip makers like Espressif),
  whether it hides behind a private Wi-Fi address, any name it gives (your router, reverse DNS, its own mDNS
  announcement, its Windows name, its UPnP description) and which common services it offers (AirPlay, Chromecast,
  printing, HomeKit...). The alert ends with a **best guess** and how sure it is, for example "a laptop, game console,
  smart TV or smart speaker (low confidence)". Times are shown in Home Assistant's time zone.
- **Re-check after 10 minutes:** if the device has left by then, the same notification is updated ("left after about
  12 minutes") and the event `hark_gateway_device_left` fires.
- **Known / Ignore:** tell Hark ("the new device is the living room TV"), fire the Home Assistant event
  `hark_gateway_device` (`mac`, `action: known` or `ignore`, optional `name`), or, with the new option
  `inventory_phone_notify`, tap **Known** or **Ignore** on your phone. That dismisses the alert, names the device and
  keeps it out of the "new" lists. A device marked before it ever shows up never alerts.
- New options: `inventory_investigate` (the closer look; on by default) and `inventory_phone_notify` (off by default).
  The look is read-only, limited to 20 devices an hour, skipped while the kill switch is off, never touches a
  printer's raw print ports (9100-9103, 515), and is recorded in the audit log.
- Routers that already name the maker (OPNsense, UniFi) have that name used first.
- The `devices` tool can now mark a device (`{"mark": "known", "mac": "...", "name": "..."}`).

## 2.0.4
- **Works without giving Hark access to Home Assistant.** Your relay is now the normal way in, and it's fast: the
  app keeps a connection open *out* to the relay (the "doorbell"), so Hark's commands and print jobs arrive within a
  second or two instead of up to a minute. Still outbound only, still on Cloudflare's free plan. Needs the 2.0.4
  relay (relay guide, "Updating later"); with an older relay the app keeps its once-a-minute check.
- **Pairing through the relay:** put your relay's address in the new **Relay address** option (`site`), start the
  app, and read Hark the pairing code from the app's Log. Pairing through Home Assistant still works for those who
  gave Hark a Home Assistant token.
- **Hark's side is now in this folder** (`hark/hark_gw.py` and `hark/HARK.md`): any Hark can generate its keys,
  claim a relay, pair, send signed commands and approvals by following it. Nothing personal in it.
- Security hardening: approval keys and signatures with "low-order" Ed25519 values are refused; if the system tool
  that lists this machine's own addresses is missing, the app reads them from the kernel instead of allowing
  everything; staged configuration files can no longer expand beyond 512 KB while being unpacked; the relay keeps its
  failed-claim records small and has per-version preview addresses switched off.
- Documentation: the relay is described as the normal path; honest notes that `probe` may send a short message to a
  device and that a web page read can affect badly designed devices.

## 2.0.3
- **Much simpler relay setup:** a **Deploy to Cloudflare** button. Ask Hark for its approval public key, click the
  button, paste the key, deploy, and give Hark the relay's address. About 3 minutes, no terminal, nothing secret to
  copy. The app itself works exactly as before.
- The relay now makes its own secret keys and hands them to Hark once, over a request signed with Hark's approval key
  (`/setup/claim`); after that it never hands them out again. Until then, `/gw` and `/docs` refuse everything.
  Secrets set by hand still win, so relays set up by hand keep working unchanged.
- `/healthz` now answers `{"ok":true,"claimed":true|false}`.
- The relay folder is now ready to deploy as is (`wrangler.toml`, `package.json`); `wrangler.toml.example` is gone.

## 2.0.2
- Renamed to **Hark Home Assistant Gateway**. Nothing else changes; settings and pairing carry over.

## 2.0.1
Housekeeping release; nothing changes in how the app works.
- Everything about this app now lives in its own folder: the relay template and its step-by-step guide
  (`relay/DEPLOY.md`) and the security notes (`SECURITY.md`).
- The relay template now only carries what this app uses (`/gw/*` commands and the `/docs/*` document queue). The
  token the app uses to fetch documents is called `PRINT_TOKEN` in the template (older relays with `BRIDGE_TOKEN`
  keep working). Failed print jobs' file data is now cleaned up after a day.
- The Configuration tab now explains every option in plain words.
- Documentation: every tool switch (`tool_*`) explained one by one; older options (`opnsense_*`, `tool_opnsense`,
  `site`, `print_token`) listed as such; `doc_printer_model` explained; receipt notes are refused while the kill
  switch is off (as before, now written down).
- 32-bit ARM (armv7) is no longer offered; Home Assistant dropped 32-bit support in 2025.12.

## 2.0.0 (community edition)
- **Split:** the public receipt queue moved out of this app. This app no longer checks any public receipt queue.
  Hark can still print a receipt on request (`print_receipt`), and documents Hark queues still print on your page
  printer.
- **Routers:** the router tool (`firewall`) now speaks OPNsense, pfSense (REST API package, beta), OpenWrt (ubus, beta) and UniFi (beta). The beta adapters are tested against simulated routers only.
  New options `router_type`, `router_host`, `router_port`, `router_scheme`, `router_user`, `router_password`,
  `router_site`, `router_cert_sha256`. The old `opnsense_*` options keep working. Reads run freely; changes need
  your approval as before.
- **Backup + undo:** every router change is backed up first and refused if the backup fails. `firewall {"undo": id}`
  puts a backup back (a change: needs approval, and backs up the current state first).
- **Device alerts:** new devices on your network raise a notification, the event `hark_gateway_new_device`, and show in
  `sensor.hark_gateway_devices`.
- **Internet health:** `binary_sensor.hark_gateway_internet`, latency, packet loss, router latency, and a nightly
  speed test (`sensor.hark_gateway_download_speed`).
- **Weekly network check-up:** risky open ports, waiting updates (Home Assistant + router firmware), certificates
  about to expire; notification + `sensor.hark_gateway_checkup`.
- **Approve on your phone (optional):** `phone_approval` adds a tap on Approve in the Home Assistant phone app as a
  second factor. A tap can only co-sign or deny; Hark's signed approval is still required.
- Background monitors pause while the kill switch is off.
- New option `doc_raw_fallback` (on): the port-9100 PDF fallback for page printers can now be switched off.
- Relay: deploy your own free Cloudflare Worker from a template, with a step-by-step guide.

## 1.3.0
- New: Hark can update Home Assistant's configuration and dashboards, only with your approval.
  - Reads (on its own): configuration.yaml and packages/*.yaml (password-looking lines blanked), a dashboard's
    outline, and Home Assistant's own configuration check.
  - Changes (each needs your yes): write configuration.yaml or packages/<name>.yaml, and replace one dashboard.
    The approval names a fingerprint (SHA-256) of the exact content, so nothing else can be written under it. The
    old file goes to hark_backups/ in your config folder; the old dashboard to the app's own storage (last 20 kept).
  - Never: secrets.yaml, .storage, custom_components, or any other file.
- The app now maps your Home Assistant config folder (read/write) for this. Switch it all off with the new
  `tool_ha_config` option.

## 1.2.1
- Fix: the receipt printer search no longer prints junk pages on page (laser/inkjet) printers. It skips the
  document printer and any host that answers on IPP (port 631) before sending ESC/POS bytes, and forgets a
  remembered address that turns out to be a page printer.
- The probe tool refuses to send data to raw printer ports (9100-9103, 515); anything sent there prints.

## 1.2.0
Security hardening release.
- Change commands now need an approval signed with a separate key that only Hark holds (Ed25519). The app stores
  only the public half, so a copy of the app's data can't be used to approve changes.
- Pairing now also delivers Hark's server address and the approval public key; there is no built-in server address.
  The pairing request's fingerprint is printed in the app's Log so Hark can detect a swapped request. Pairing closes
  after success (and 30 minutes after start); re-pair with the new `reset_pairing` option. Already-paired installs
  get the missing settings from Hark through Home Assistant.
- Network targets: only private home-network addresses. Loopback, 0.0.0.0, link-local/metadata addresses, Home
  Assistant's internal networks and names, and (for tools that send data) the Home Assistant machine itself are
  refused. Names are resolved once and the checked address is used; HTTP redirects are not followed.
- DNS tool limited to home-network or well-known public resolvers; speed test uses one fixed endpoint; Wake-on-LAN
  broadcast limited to your network.
- Home Assistant reads redact tokens, passwords, cookies and GPS coordinates, and can't reach other API paths.
  Home Assistant service calls: `hassio.*` and the app's own kill switch are never allowed; risky domains need an
  explicit flag in the approved command.
- Results written to Home Assistant are encrypted. Web/firewall results no longer include session cookies or login
  headers.
- Kill switch fails closed: missing or unavailable means network tools are refused.
- Stricter command checks, unsigned events can't affect anything, bounded command queue and rate limits, bounded
  replay memory, size caps on events and WebSocket messages.
- SSH: no config file, no agent/X11/port forwarding, identity file only, host key remembered on first use and enforced.
- Printing: daily job/page/receipt limits, per-document page and size limits, documents with printer-control escape
  codes refused. The document printer's address is remembered between restarts.
- Files in `/data` are private to the app. The firewall tool defaults to the network's default gateway when no host is
  set. No device addresses or server addresses are built in.

## 1.1.1
- Printers are no longer skipped when their IPP format list leaves out PDF; the app picks PDF, octet-stream (printer
  auto-detects) or raw port 9100, and falls back to 9100 if IPP refuses the job.
- The status tool shows the printer's format list and send method.
- The app's home moved to GitHub.

## 1.1.0
- Hark pushes commands through Home Assistant events; results come back in Home Assistant.
- Only short safety-net checks of Hark's server once a minute.
- Pairing without pasting a secret.

## 1.0.0
- First release: printing (full page over IPP, receipts over ESC/POS) and Hark's network tools with signed commands,
  approval for changes, kill switch, per-tool switches, rate limits and an audit trail.

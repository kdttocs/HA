# Changelog

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

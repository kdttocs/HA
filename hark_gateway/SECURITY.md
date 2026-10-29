# Security: Hark Home Assistant Gateway

How this app protects your home, in plain words. Report a problem privately through GitHub's
"Report a vulnerability" (Security tab) rather than in a public issue.

## The big rules

1. **Looking is free, changing needs your yes.** Hark Home Assistant Gateway runs read-only tools on its own. Anything that changes
   something (router settings and undo, Wake-on-LAN, HTTP writes, SSH, Home Assistant service calls, configuration and
   dashboard writes) is refused unless it carries an approval signed with Hark's **separate Ed25519 approval key**,
   bound to that exact command (its signature and a hash of tool + arguments), and less than 2 minutes old.
2. **The app can't approve itself.** It stores only the public half of the approval key. A stolen copy of the app's
   data (for example from a Home Assistant backup) can't approve changes. Your relay also checks approvals against
   the same public key and refuses approvals when none is configured.
3. **Every message is signed and single-use.** Commands are signed (HMAC-SHA256) with the gateway secret; stale
   (>2 minutes) or replayed ones are refused. Only correctly signed commands can use up a nonce.
4. **Fail closed.** Kill switch missing/unreadable = off. Router backup failed = change refused. Phone approval
   enabled but the notification couldn't be sent, no answer, or Home Assistant disconnected = refused.
5. **Outbound only.** No ports are opened on your router. The app connects out to your relay (and talks to Home
   Assistant inside the machine); nothing on the internet connects in. Hark needs no access to your Home Assistant.

## How messages travel

- **Through your relay (normal):** Hark leaves signed commands on your relay. The app keeps one outbound WebSocket
  open to the relay (the "doorbell", opened with a signed request); it carries only "something is waiting" notices,
  never commands, results or secrets. On a notice the app fetches the command over the normal signed request and
  checks it exactly as described above. Without a doorbell (older relays) the app's once-a-minute check delivers it.
- **Through Home Assistant (optional):** if you give Hark a Home Assistant token, Hark can also fire the event
  `hark_gateway_command`; the app applies the same checks. Results are then also written to Home Assistant, encrypted.

## Pairing

- The app posts a one-time Diffie-Hellman **public** key to your relay and prints a pairing code (the first 12
  characters, 48 bits, of that key's SHA-256 fingerprint) in its own Log. Hark answers only the request whose
  fingerprint matches the code you tell it, sealed (encrypted and authenticated) to that key. The relay only ever
  holds public keys and ciphertext; an answer is handed out once and requests expire after an hour (at most 10 wait
  at a time, 10 new requests an hour per address).
- Someone who can post to your relay can add pairing requests, but Hark never answers one that doesn't match your
  code, and nobody but the app that made the request can open the answer.
- After pairing the Log names the fingerprint of the key that answered, so you or Hark can confirm it was Hark.
- The optional Home Assistant path works the same way through `sensor.hark_gateway_pairing_request` /
  `sensor.hark_gateway_pairing`, with Hark checking the fingerprint against the app's Log.
- Pairing closes after it succeeds. Re-pairing needs the `reset_pairing` option and a restart.
- Approval public keys that are not valid Ed25519 keys (including the few "low-order" values with which one fixed
  signature would pass for every message) are refused at pairing, and such signatures are refused when checked.

## Optional second factor: approve on your phone

With `phone_approval` on, an approved change additionally needs a tap on **Approve** in the Home Assistant companion
app. A tap can only **co-sign or deny**: commands without Hark's signed approval are refused before your phone is
asked, so a tap can never start a change on its own. Each request uses a fresh 128-bit token, accepted once; set
`phone_approver_user_id` to accept taps only from your own Home Assistant user. Limit: Home Assistant admins (and any
token with admin rights) can watch service calls and fire events, so they could fake a tap; this factor protects
against a stolen approval key, not against someone who already controls Home Assistant.

## Router changes

- The router tool talks to exactly one host (your `router_host`, or the default gateway), checked to be on your home
  network and not the Home Assistant machine itself; the connection goes to the checked address.
- GET is read; everything else is a change. On OpenWrt, GET may only call a fixed list of read-only ubus methods.
- Before any change the settings are backed up (OPNsense config history point + `config.xml`; OpenWrt UCI; pfSense/
  UniFi the affected object). If that fails, nothing is changed unless the approved command explicitly allows it.
- Undo is itself a change: it needs approval and takes a fresh backup first.
- Optional certificate pin (`router_cert_sha256`): checked before any password is sent.
- Backups stay in the app's private `/data/router_backups` (0600); they contain router settings, including password
  hashes, and are included in Home Assistant backups of the app. Results returned to Hark never include them.

## What the gateway will never touch

- Network targets: only private home addresses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7). Never loopback,
  0.0.0.0, link-local/cloud metadata, multicast, Home Assistant's Supervisor/app networks or internal names. Tools
  that send data never target the Home Assistant machine itself. Names are resolved once (every address must pass)
  and the checked address is used (no DNS rebinding); redirects are not followed.
- Internet: only fixed endpoints (well-known DNS resolvers for DNS and health checks, one Cloudflare speed-test URL),
  plus hosts you list yourself in `checkup_cert_hosts` (TLS handshake only).
- Home Assistant: `hassio.*` never; the gateway's own kill switch and entities never; risky domains (restart, shell
  commands, scripts, automations, locks, alarms, notify, ...) only when the approved command says `dangerous_ok`.
  Config writes only to `configuration.yaml` and `packages/*.yaml`, with a SHA-256 of the exact approved content.
- Printers: receipt (ESC/POS) bytes are never sent to a page printer (hosts answering on IPP port 631 are skipped).
  Documents containing printer-control escape codes are refused. Daily page/job/receipt caps. Printing is not stopped
  by the kill switch; the daily caps protect your paper instead.

## Background monitors

Device inventory, internet health and the weekly check-up only look (ARP/DHCP reads, pings to fixed public
resolvers, connect-only port checks, TLS handshakes). They pause while the kill switch is off. New-device alerts and
check-up reports appear as Home Assistant notifications, sensors and events, visible to your Home Assistant users.

The closer look at a new device (2.0.5; `inventory_investigate`) is bounded and read-only: about 6 seconds at most,
20 devices an hour at most, only to that device's own address (checked with the same "home network only, never this
machine" rule as the tools), plus one reverse-DNS question to your normal DNS. It sends: TCP connects to about 24
common ports with no data (it reads the greeting an SSH server sends by itself), one mDNS question to its UDP 5353,
one NetBIOS name question to its UDP 137, one SSDP search to its UDP 1900, and one HTTP GET of the description file
the device itself points to (same address only, no redirects, 64 KB max). Raw printer ports (9100-9103, 515) are never
contacted. Names and text the device reports are shortened and stripped of formatting before they go into a
notification. The maker list is a file inside the app (public IEEE list); nothing is looked up online. Each look is
written to the audit log.

Known / Ignore only changes the app's own device list and dismisses its own notification; it can't hide a device from
the device list, change your router, or affect any other alert. Anyone who can fire Home Assistant events (admins,
automations) can mark a device; set `phone_approver_user_id` to accept phone taps only from that user.

## Privacy

- Results stored in Home Assistant are encrypted with a key derived from the gateway secret; they are deleted after
  reading (or 15 minutes). The relay deletes results and arguments after 7 days.
- Results redact passwords, tokens, cookies, API keys and GPS coordinates; session cookies and auth headers are
  dropped.
- The command itself (tool + arguments) passes over Home Assistant's event bus; exclude it from the recorder
  (Documentation tab, "Privacy of results").

## Your relay

You deploy your own relay from the template in this app's `relay` folder (guide:
https://github.com/kdttocs/HA/blob/main/hark_gateway/relay/DEPLOY.md). It has no public pages.

- **Its own secrets, claimed once.** A relay deployed with the button knows only Hark's approval *public* key. When
  Hark first claims it, it makes its own `GATEWAY_SECRET`, `DOC_TOKEN`, `PRINT_TOKEN` and `IP_SALT` (32 random bytes
  each) and keeps them in its Durable Object storage, inside your Cloudflare account. The claim must be signed with
  Hark's approval key over the relay's own address, a timestamp under 2 minutes old and a single-use nonce, so only
  Hark can claim it, and a claim made for one relay can't be used on another. The relay answers with
  `GATEWAY_SECRET` and `DOC_TOKEN` (the app gets `PRINT_TOKEN` later through the signed start-up call). Once Hark
  has used them, every further claim is refused without revealing anything. A valid claim that arrives before Hark
  first used the secrets gets the same values again, so a lost answer doesn't lock you out.
- **Fail closed.** No approval key = no claims and no approvals. No secrets yet = `/gw` and `/docs` refuse
  everything. 20 failed claims an hour from one address are blocked.
- **Secrets set by hand win.** A secret set with `wrangler secret put` or the dashboard always overrides the stored
  one, and a relay whose `GATEWAY_SECRET` or `DOC_TOKEN` was set by hand refuses claims (relays set up by hand before
  2.0.3 keep working unchanged). That is also the recovery path: set new values by hand, give them to Hark through its
  secure form, and re-pair.
- Anyone who can read your Cloudflare account (or its Durable Object storage) can read the relay's secrets, the same
  as secrets set by hand. Protect that account with 2FA.

- Every `/gw` request (including the doorbell connection) needs a fresh signed header; 60 failures an hour from one
  address are blocked.
- `/setup/pair` is the only route that takes anything without a signature: a one-time public key (limits above).
- Approvals are checked against `GW_APPROVAL_PUB`; with no key set, every approval is refused.
- Document queue: `DOC_TOKEN` (Hark uploads) and `PRINT_TOKEN` (the app fetches and prints; called `BRIDGE_TOKEN` in
  older relays). PDFs only, up to 25 MB.
- Command results and arguments are deleted after 7 days; command records after 30 days.

## Container permissions

- `host_network` (to see your network), `homeassistant_api`, `homeassistant_config` read/write (for approved
  config writes). Not requested: `hassio_api`, `docker_api`, `full_access`, `privileged`, devices, ports. AppArmor on.
- Stdlib Python on Home Assistant's pinned base image (Python 3.12, Alpine 3.20), plus the OpenSSH client from
  Alpine's signed package repository; nothing else is downloaded and run.

## Known limits

- Anyone with Home Assistant admin rights controls the house anyway: they can stop the app, change its options, read
  its log, or flip the kill switch.
- A leaked gateway secret alone allows the read tools; changes still need the approval key. Be aware that two read
  tools can still affect a device: `probe` may send a short message (up to 2,000 characters) to a device port
  (printer ports excepted), and `http` GET reaches device web pages, which a badly designed device may treat as a
  command. Switch off `tool_probe` (and `tool_http`) if you want those to be impossible. To rotate it, set a
  new `GATEWAY_SECRET` on the relay by hand, give it to Hark through its secure form, and re-pair (`reset_pairing`).
- Router TLS is not verified unless you pin the certificate (home routers are self-signed).
- Keep **Auto update** off for this app and use 2FA on any account that can push to this repository.

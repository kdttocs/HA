# Hark Home Assistant Gateway

This app lets Hark help with your home network, through Home Assistant:

1. **Network helper.** Hark can look around your network on its own (find devices, check what's running, test your
   internet, read your router's status). Anything that would **change** something (a router setting, a command on a
   computer, a Home Assistant service call, waking a computer) waits until you say yes to Hark.
2. **Your router.** OPNsense, pfSense (beta), OpenWrt (beta) and UniFi (beta) are supported. Every router change is **backed up first**,
   and can be **undone** (the undo is a change too, so it also waits for your yes).
3. **Watching for you.** New devices on your network raise an alert; internet sensors show if you're online, how fast
   it answers and a nightly speed test; once a week a **network check-up** lists open doors, waiting updates and
   certificates about to expire.
4. **Printing on request.** Documents Hark prints for you come out on your network page printer (laser/inkjet, over
   IPP), and short notes on a network ESC/POS receipt printer when Hark is asked to.

## How Hark reaches it

Through your **relay**: a small free Cloudflare Worker you deploy yourself (from this app's `relay` folder). Hark puts
a signed message on your relay; the app keeps a connection open *out* to the relay (the "doorbell"), so the relay can
tell it at once that something is waiting. The app then fetches the message, checks it, does the job and leaves the
answer on the relay for Hark. A message usually arrives within a second or two. Nothing is opened on your router and
there is no port forwarding: every connection goes out from your home. As a safety net the app also checks the relay
once a minute (a relay set up before app version 2.0.4 has no doorbell, so there messages take up to a minute;
update the relay to get the fast path). Your relay also holds the private queue of documents Hark wants printed.

Hark never needs access to your Home Assistant for this.

**Optional:** if your Home Assistant can be reached from the internet (for example with Home Assistant Cloud or your
own domain) and you give Hark a Home Assistant access token, Hark can also send messages *into Home Assistant*
directly (the event `hark_gateway_command`) and read the encrypted answer there. That is not needed; it only adds a
second way in.

## Install

1. Set up your relay (one time, about 3 minutes, free, no terminal): ask Hark for its approval public key, click
   the **Deploy to Cloudflare** button in the guide, paste the key, deploy, and give Hark the relay's address. Hark
   claims the relay by itself. Guide: https://github.com/kdttocs/HA/blob/main/hark_gateway/relay/DEPLOY.md
2. Home Assistant: **Settings > Apps > App store > ⋮ > Repositories**, add `https://github.com/kdttocs/HA`.
3. Find **Hark Home Assistant Gateway** and tap **Install**. In its **Configuration** tab, put your relay's address
   (the `https://...` address from step 1) into **Relay address** (`site`) and save. That address is not a secret.
4. Turn on **Start on boot** and tap **Start**. Open the **Log** tab: it shows a line like
   `pairing: pairing code 3f9a-41c2-77de`. Tell Hark that code within 30 minutes; Hark pairs with the app (see
   "Pairing").

(For Hark itself: the steps Hark follows are in this app's `hark/HARK.md`, with the small program it runs.)

Recommended: leave **Auto update** off for this app, so you see each new version before it installs.

## Pairing

Pairing gives the app three things from Hark: the secret that signs commands, your relay's address, and the public
half of Hark's **approval key**. You never copy a secret:

1. On start (not paired yet) the app makes a one-time key pair, posts only its **public** half to your relay, and
   prints a **pairing code** (the first 12 characters of that key's fingerprint) in its own Log.
2. You tell Hark the code. Hark finds the waiting request on your relay whose fingerprint matches your code (so a
   request posted by someone else is never answered), locks the pairing data to that key, and leaves the locked copy
   on the relay.
3. The app fetches it, unlocks it, checks it with the relay, and saves it privately in the app's `/data` folder. The
   Log says `pairing: done through relay; answered by key ...`; Hark can compare that with its own key.

With the optional Home Assistant access (see "How Hark reaches it"), Hark can pair without the code instead: the app
also puts its public key in Home Assistant (`sensor.hark_gateway_pairing_request`); Hark compares its fingerprint with
the app's Log and writes the locked answer to `sensor.hark_gateway_pairing`.

The pairing window **closes** after it succeeds, and 30 minutes after the app starts (restart the app to open it
again). To pair again later, switch on `reset_pairing`, save, restart the app, let Hark pair, then switch it off
again.

## Approval for changes

- **Looking** (read-only) runs on its own: finding devices, port checks, web page reads on your network, DNS lookups,
  SNMP reads, ping and speed tests, reading Home Assistant states, reading your router. Two honest limits: a web
  page "read" (GET) on a badly designed device can still trigger something on it, and `probe` may send a short
  message to a device port (see `tool_probe` below). Switch those tools off if that matters to you.
- **Changing** always asks first: router changes and undo, Wake-on-LAN, sending data to a device
  (POST/PUT/PATCH/DELETE), SSH commands, Home Assistant service calls, configuration and dashboard writes. Hark tells
  you exactly what it wants to do; only after your yes does it sign an approval for that one command.
- Approvals are signed with a **separate key that only Hark holds**. The app keeps only the public half, so even
  someone with a copy of the app's data (for example from a backup) could not approve changes.
- Some Home Assistant calls are never allowed (`hassio.*`, anything touching the app's own kill switch) and some need
  Hark to say "this one is risky" explicitly (restarting Home Assistant, shell commands, scripts, automations, locks,
  alarm panels, notifications and similar).

### Optional: also approve on your phone

Turn on `phone_approval` and set `phone_notify_service` to your phone's notify service (for example
`mobile_app_my_phone`; find it under **Developer tools > Actions**, search "notify.mobile_app"). Then every change
that Hark has approved **also** pops up on your phone with **Approve** and **Deny**:

- The change runs only after you tap **Approve** within `phone_approval_timeout_s` (default 5 minutes).
- **Deny**, no answer, a notification that could not be sent, or the app being disconnected from Home Assistant all
  mean: refused, nothing changed.
- A tap can only **co-sign or deny**. It can never approve anything on its own: commands without Hark's signed
  approval are refused before your phone is asked.
- Optional: set `phone_approver_user_id` (your Home Assistant user id, Settings > People > Users, shown with
  "Advanced mode" on) so only taps from your own account count.
- Honest limit: someone with Home Assistant admin rights can see the notification request and could fake a tap. If
  you gave Hark a Home Assistant token (optional), give that token its own user where possible.

## Your router

Pick your router in `router_type` and fill in its login. `router_host` is optional: if empty, the app uses your
network's default gateway (set it if your UniFi controller isn't your router). The router tool only ever talks to
that one host.

**Beta:** pfSense, OpenWrt and UniFi support is tested against simulated routers only, not yet on real hardware.
Try a harmless change and its undo first, and tell us what you see. OPNsense has been used on a real router.

| Router | What to create | Put it in |
| --- | --- | --- |
| **OPNsense** | System > Access > Users: a user with an API key + secret (download the key file) | `router_user` = key, `router_password` = secret (the old `opnsense_key` / `opnsense_secret` options still work) |
| **pfSense** (beta) | Install the **pfSense REST API** package (pfrest.org), then System > REST API > Keys: create a key | `router_password` = API key (or `router_user` + `router_password` of a local user) |
| **OpenWrt** (beta) | A router login that can use LuCI's ubus API (`luci-mod-rpc`/`rpcd`; `root` works) | `router_user`, `router_password`; `router_scheme: http` if your router has no HTTPS |
| **UniFi** (beta) | A **local** (not Ubiquiti cloud) user in UniFi Network; "View only" is enough unless you want changes | `router_user`, `router_password`, optional `router_site` (default `default`) |

- Home routers use self-signed certificates, so the app does not check them by default. To lock it to your router's
  exact certificate, put its SHA-256 fingerprint in `router_cert_sha256` (ask Hark to read it for you: it runs
  `firewall {"info": "cert"}`, which sends no password). With a fingerprint set, a different certificate is refused before any password is sent.
- **Backups:** before every router change the app saves a backup in its private `/data/router_backups/` (last 30):
  OPNsense - the router's own configuration history point plus a full copy of `config.xml`; OpenWrt - every UCI
  settings file; pfSense and UniFi - the settings of the exact item being changed. If the backup fails, the change is
  **refused** (unless the approved command itself says `no_backup_ok`).
- **Undo:** Hark can put a backup back (`firewall {"undo": "<backup id>", "method": "POST"}`). That is a change, so it
  needs your yes, and it backs up the current state first, so an undo can be undone too. OPNsense does not restart
  services after a revert (reboot or re-apply for a clean state). On pfSense, IDs of rules can shift after deletions;
  check the result. Steps that can't be reversed automatically are listed with where to restore them by hand.
- Backups contain your router's settings (including password hashes). They stay inside the app; Home Assistant
  backups of this app include them, so keep your HA backups private.

## Device alerts (inventory)

Every `inventory_every_min` minutes (default 15) the app lists the devices on your network: from your router's DHCP
and ARP tables when a router is set up, and from Home Assistant's own ARP table always. The first run only learns
what's there. After that a device never seen before:

- shows a notification **New device on your network** (switch off with `inventory_notify: false`),
- fires the event `hark_gateway_new_device` (use it in your own automations, for example to send it to your phone),
- appears in `sensor.hark_gateway_devices` (number of devices known, plus the latest new ones).

**What the alert tells you.** Before it alerts, the app takes a short look at the new device (about 6 seconds at most,
in the background, so nothing else waits) and writes what it found in plain words:

- **Made by:** the maker of its network chip, from an offline copy of the public IEEE maker list that ships with the
  app (nothing is looked up online), or the maker name your router already gives. Some makers build for many brands
  (for example Foxconn, also listed as Cloud Network Technology or Hon Hai) or make chips that go into many gadgets
  (for example Espressif); the alert explains that.
- **Hardware address:** whether it's the device's real factory address or a **private Wi-Fi address**. Phones,
  tablets and laptops use private addresses to hide their maker, so the maker can't be looked up for those.
- **Name:** any name it gives: the name it told your router, your router's DNS, its own announcement on the network
  (mDNS), its Windows network name (NetBIOS), or its UPnP description.
- **What it offers:** which of about 24 common services answer (for example a web page, printing, Chromecast, AirPlay,
  Windows file sharing) and which services it announces. Nothing is logged into and no data is sent to those
  services; the check only sees whether they answer. A printer's raw print ports (9100-9103, 515) are never touched.
- **Best guess:** what it probably is, and how sure (fairly sure, medium or low confidence).
- **Status:** when it joined (in Home Assistant's time zone). About 10 minutes later it is checked once more; if it
  has left, the same notification is updated ("left after about 12 minutes") and the event
  `hark_gateway_device_left` fires. If it's still there the notification is left alone.

Example (made-up addresses):

> An unnamed device joined your network at 6:21 PM.
>
> **Best guess:** a laptop, game console, smart TV or smart speaker (low confidence)
>
> - **Made by:** Cloud Network Technology Singapore (Foxconn), a contract maker that builds laptops, game consoles, smart speakers and TVs for many brands
> - **Name:** none. It didn't give your router a name and doesn't announce one
> - **Hardware address:** d8:80:83:00:53:01, its real factory address, not a private one
> - **What it offers:** nothing. No answer on 24 common services and it doesn't announce any. That's normal for phones, laptops and game consoles, and for sleeping devices
> - **Network address:** 192.0.2.142, seen in your router's address list (DHCP)
> - **Status:** online at 6:21 PM. I'll check again in 10 minutes

Switch the closer look off with `inventory_investigate: false`; the alert then uses only the maker and the name your
router gives. The look is limited to 20 new devices an hour (more than that get the short alert), pauses while the
kill switch is off, only talks to the new device itself (plus your router's DNS for the reverse name), and each look
is written to the audit log.

**Known or Ignore.** When you know what it is, mark it, and it stops alerting:

- **Tell Hark**, for example "the new device is the living room TV". Hark marks it for you.
- **In Home Assistant:** Developer tools > Events, event type `hark_gateway_device`, event data
  `{"mac": "00:00:5e:00:53:01", "action": "known", "name": "Living room TV"}`. Use `"action": "ignore"` for a device
  you don't want to hear about but don't want to name, and `"action": "new"` to undo. You can fire the same event from
  your own scripts or automations.
- **On your phone:** switch on `inventory_phone_notify` and set `phone_notify_service` (for example
  `mobile_app_my_phone`, needs the Home Assistant companion app). New-device alerts then also arrive on the phone with
  **Known** and **Ignore** buttons. If `phone_approver_user_id` is set, only taps from that Home Assistant user count.

Marking a device dismisses its notification, cancels the 10-minute update, saves the name, and keeps it out of the
"new" lists in `sensor.hark_gateway_devices`. You can mark a device before it ever joins; it then never alerts. A
phone or laptop that keeps changing its private address shows up as new each time it changes it; turning off the
private address for your own Wi-Fi on that device stops that.

## Internet health

Every `health_every_min` minutes (default 5):

| Entity | Meaning |
| --- | --- |
| `binary_sensor.hark_gateway_internet` | On = online (from your router's WAN status when set up, else public test addresses answer) |
| `sensor.hark_gateway_internet_latency` | Average round trip to the test addresses, ms |
| `sensor.hark_gateway_internet_packet_loss` | % of test pings lost |
| `sensor.hark_gateway_router_latency` | Round trip to your router, ms |
| `sensor.hark_gateway_download_speed` | Nightly speed test, Mbit/s (`speedtest_daily`, `speedtest_time`, `speedtest_mb`) |

Events `hark_gateway_internet_down` and `hark_gateway_internet_up` fire when the state changes. Test addresses are
fixed well-known public DNS resolvers (`health_targets` may pick from 1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9,
149.112.112.112); the speed test always uses one fixed Cloudflare endpoint.

## Weekly network check-up

Every week (`checkup_day`, `checkup_time`, default Sunday 09:00) the app checks, without changing anything:

- **Open doors:** devices with risky ports open (Telnet, FTP, Windows file sharing, Remote Desktop, VNC, Docker or
  databases without passwords/encryption).
- **Updates waiting:** Home Assistant's own update list (core, OS, apps, ESPHome...) and your router's firmware.
- **Certificates expiring** within 30 days on your devices' HTTPS pages, plus any `host` or `host:port` you list in
  `checkup_cert_hosts` (comma separated).

The result is a notification **Weekly network check-up**, `sensor.hark_gateway_checkup` ("ok" or "N to look at") and
the event `hark_gateway_checkup`. Hark can run it any time with the `checkup` tool.

## The off switch (kill switch)

The app creates a toggle **Hark Gateway enabled** (`input_boolean.hark_gateway_enabled`), switched on.

- **On:** Hark can use the network tools (changes still need your yes).
- **Off, missing, or unavailable:** every network command is refused, and the background device scans, internet
  checks and check-ups pause. Status questions are still answered.
- Printing documents Hark queued keeps working; daily print limits protect your paper instead. Receipt notes
  (`print_receipt`) are refused while it's off.
- Any Home Assistant user who can see the toggle can switch it. Hark cannot switch it on for itself.
- Harder off switch: set `enabled` to off in the Configuration tab and restart.

## What the app will and won't touch

- Only devices on your own network (private addresses). Never: this machine's loopback, Home Assistant's internal
  Supervisor/app networks, cloud metadata addresses, or internet addresses (except the fixed test endpoints above and
  hosts you list yourself in `checkup_cert_hosts`).
- Tools that send data (web requests, probes, SNMP, SSH, router) never target the Home Assistant machine itself.
- Names are looked up once and the checked address is used for the connection; web redirects are not followed.
- Every tool has rate limits (for example 2 network sweeps a minute, 30 port scans an hour, 6 speed tests a day).

## Printing

- **Documents:** Hark uploads a PDF to your relay's private document queue; the relay rings the app's doorbell and the
  app prints it on your
  network page printer over IPP (found through Home Assistant's IPP integration or a network search; set
  `doc_printer_ip` if it isn't found). If the printer won't take the PDF over IPP, the app sends it to the printer's
  port 9100 as a PDF job (`doc_raw_fallback`, on by default; switch it off if your printer prints pages of gibberish
  instead).
- **Receipts:** Hark's `print_receipt` tool prints a short note on a network ESC/POS receipt printer (found by
  itself, or `printer_ip`). Page printers are never sent receipt bytes: any device that answers on IPP (port 631) is
  skipped.
- Limits (defaults, change them in the options): 50 documents and 500 pages a day (`daily_doc_jobs`,
  `daily_doc_pages`), 100 pages per document (`max_pages_per_job`), 200 receipts a day (`daily_receipts`); documents
  up to 25 MB. Documents containing printer-control escape codes are refused.
- Printer status: `sensor.document_printer`. If the page printer isn't found, set `doc_printer_ip`;
  `doc_printer_model` (part of the printer's name) helps pick the right one when several are found.

## Privacy of results

- Answers go back to your relay. Only with the optional Home Assistant access, answers are also left in Home
  Assistant (`sensor.hark_gateway_result_…`), encrypted; Hark removes them after reading, and the app removes
  leftovers after 15 minutes.
- Reads redact passwords, tokens, cookies and GPS coordinates; web and router results drop session cookies and login
  headers.
- Your relay keeps command results for 7 days.
- Recommended (mainly with the optional Home Assistant access): keep these out of Home Assistant's history database
  by adding to `configuration.yaml`:

```yaml
recorder:
  exclude:
    entity_globs:
      - sensor.hark_gateway_result_*
      - sensor.hark_gateway_pairing*
    event_types:
      - hark_gateway_command
      - hark_gateway_result
```

## Seeing what Hark did

- **sensor.hark_gateway_last_action** and the **Logbook**: every command, with tool, target and result.
- **sensor.hark_gateway**: on/off, doorbell (`connected` = fast path to the relay), paired, pairing code while
  pairing, enabled tools, router type, phone approval, SSH key.
- The last 2,000 commands are kept inside the app (`/data/audit.jsonl`).
- Printer status: **sensor.document_printer** (see "Printing").

## SSH (optional)

The app makes its own SSH key. Add the `ssh_public_key` attribute of `sensor.hark_gateway` to
`~/.ssh/authorized_keys` on a machine you want Hark to reach. The first connection remembers the machine's host key;
a changed host key is refused. Every SSH command needs your yes.

## Home Assistant configuration and dashboards

Hark can read `configuration.yaml` and files in `packages/`, see a dashboard's outline, and run Home Assistant's
configuration check on its own. Writing those files or replacing a dashboard needs your yes every time; the approval
carries a fingerprint of the exact content. Old files are copied to `hark_backups/` in your config folder first.
`secrets.yaml`, `.storage` and every other file are off limits. Turn this off with `tool_ha_config: false`.

## Tools you can switch off

Every tool is on by default. Switching one off in the **Configuration** tab means Hark can't use it at all, even
with your approval. (Status, the audit trail, the SSH public key and document printing can't be switched off here;
use `enabled` or the kill switch.)

| Option | Hark's tools it switches | What they do | Needs your yes? |
| --- | --- | --- | --- |
| `tool_discovery` | `ping_sweep`, `mdns`, `ssdp` | Find devices on your network | No |
| `tool_port_scan` | `port_scan` | See which services a device offers | No |
| `tool_http` | `http` | Read web pages on your devices; send data to them | Reading no, sending yes |
| `tool_probe` | `probe`, `latency` | Talk to one port on a device: connect, optionally send a short message (up to 2,000 characters; never to printer ports) and read the answer; measure response time | No (switch it off if you don't want Hark sending messages to devices without asking) |
| `tool_dns` | `dns` | Name lookups (home or well-known public resolvers only) | No |
| `tool_snmp` | `snmp` | Read device information over SNMP (read only) | No |
| `tool_speedtest` | `speedtest` | On-demand internet speed test | No |
| `tool_ha_states` | `ha_states` | Read Home Assistant entity states (secrets and locations hidden) | No |
| `tool_router` | `firewall` (older name `opnsense`) | Read your router; change settings and undo | Reading no, changes yes |
| `tool_opnsense` | the same router tool | Older name of `tool_router`; either one switches it off | |
| `tool_wol` | `wol` | Wake a computer (Wake-on-LAN) | Yes |
| `tool_ssh` | `ssh` | Run a command on a computer you added the app's key to | Yes |
| `tool_ha_service` | `ha_service` | Call a Home Assistant action (service) | Yes |
| `tool_ha_config` | `ha_file_read`, `lovelace_get`, `ha_check_config`, `ha_file_write`, `lovelace_save`, `stage` | Read and write `configuration.yaml`/`packages/`, dashboards | Reading no, writing yes |
| `tool_inventory` | `devices` | List known devices and new ones; mark one Known or Ignore (also off with `inventory_enabled: false`) | No |
| `tool_health` | `internet` | Internet health readings (also off with `health_enabled: false`) | No |
| `tool_checkup` | `checkup` | Run the network check-up on demand | No |
| `tool_print` | `print_receipt` | Print a short note on the receipt printer | No (daily limit) |

## Options

| Option | What it does |
| --- | --- |
| `site` | **Relay address**: your relay's `https://...` address. Needed for pairing through the relay; not a secret. |
| `gateway_secret` | Leave empty: the app pairs with Hark by itself. |
| `enabled` | Hard on/off for the network tools (document printing is not affected). |
| `reset_pairing` | Switch on + restart to pair again once; switch off afterwards. |
| `router_type` | Your router: `opnsense`, `pfsense`, `openwrt` or `unifi` (see "Your router"). |
| `router_host` | Router address; empty = your network's default gateway. |
| `router_port`, `router_scheme` | Only if your router's web interface uses another port, or `http` instead of `https`. |
| `router_user`, `router_password` | Router login or API key (see the table in "Your router"). |
| `router_site` | UniFi only: site name (default `default`). |
| `router_cert_sha256` | Optional: lock the router connection to its exact certificate. |
| `tool_*` | Switch single tools off (see "Tools you can switch off"). |
| `inventory_enabled`, `inventory_every_min`, `inventory_notify` | Device alerts: on/off, how often (minutes), notification on/off. |
| `inventory_investigate`, `inventory_phone_notify` | Closer look at new devices on/off (default on); alerts with Known/Ignore buttons on your phone too (default off, needs `phone_notify_service`). |
| `health_enabled`, `health_every_min`, `health_targets` | Internet health: on/off, how often (minutes), which public test addresses (comma separated, from the list above). |
| `speedtest_daily`, `speedtest_time`, `speedtest_mb` | Nightly speed test: on/off, time (HH:MM), download size in MB. |
| `checkup_weekly`, `checkup_day`, `checkup_time`, `checkup_notify`, `checkup_cert_hosts` | Weekly check-up: on/off, day, time, notification, extra hosts for the certificate check. |
| `phone_approval`, `phone_notify_service`, `phone_approver_user_id`, `phone_approval_timeout_s` | Approve on your phone too (see "Optional: also approve on your phone"). |
| `doc_raw_fallback` | Send PDFs to port 9100 when IPP refuses them. |
| `daily_doc_jobs`, `daily_doc_pages`, `max_pages_per_job`, `daily_receipts` | Print limits. |
| `doc_printer_ip`, `doc_printer_model` | Page printer address / name, only if it isn't found by itself. |
| `printer_ip` | Receipt printer address, only if it isn't found by itself. |

**Older options (still work, normally leave empty):**

| Option | What it does |
| --- | --- |
| `opnsense_host`, `opnsense_key`, `opnsense_secret` | Pre-2.0 names for an OPNsense router (`router_host`, `router_user`, `router_password` win when set). |
| `tool_opnsense` | Pre-2.0 name of `tool_router`. |
| `print_token` | Your relay's `PRINT_TOKEN`. The app normally gets it from the relay by itself; troubleshooting only. |

## Troubleshooting

- **No pairing code in the Log:** check that **Relay address** (`site`) is filled in and that Hark has claimed the
  relay (`https://<relay>/healthz` shows `"claimed":true`). "older relay template" in the Log: update the relay
  (relay guide, "Updating later"). The code is valid for 30 minutes after the app starts; restart for a new one.
- **Commands take up to a minute:** the Log says "this relay has no doorbell": update the relay.
- **Nothing prints:** open the app's **Log**. "waiting for pairing" or "needs setup from Hark": tell Hark.
  "daily limit reached": raise the limit or wait until tomorrow.
- **Hark says the app isn't answering:** the Log should show "doorbell: connected to the relay" (and, only with the
  optional Home Assistant access, "ha events: subscribed to hark_gateway_command").
- **Network commands refused with "kill switch":** check that `input_boolean.hark_gateway_enabled` exists and is on.
- **Router tool missing:** `sensor.hark_gateway` shows `router.configured`; check `router_type` and the login.
- **Router change refused "could not back up":** the router login can't read the backup (OPNsense: the API user needs
  the "Diagnostics: Configuration History" privilege; OpenWrt: the user must be allowed `uci`).

# Hark HA Gateway

This app does two jobs on your home network for Hark:

1. **Printing.** Documents Hark prints for you come out on your network laser/inkjet printer (full pages), and
   receipts on a network ESC/POS receipt printer if you have one.
2. **Network helper.** Hark can look around your network (find devices, check what's running, test your internet
   speed, read your firewall's status) without asking. Anything that would **change** something (run a command,
   change a firewall setting, call a Home Assistant service, wake a computer) waits until you say yes to Hark.

## How Hark reaches it

Hark sends a signed message *into Home Assistant* (an event called `hark_gateway_command`). This app listens inside
Home Assistant, checks the message, does the job, and leaves an encrypted answer in Home Assistant for Hark to read.
Nothing is opened on your router and there is no port forwarding. The app also checks Hark's server briefly once a
minute as a safety net.

## Install

1. Home Assistant: **Settings > Apps > App store > ⋮ > Repositories**, add `https://github.com/kdttocs/HA`.
2. Find **Hark HA Gateway**, tap **Install**, turn on **Start on boot**, tap **Start**.
3. Tell Hark you started it. Hark pairs with the app by itself within the next 30 minutes (see "Pairing").

Recommended: leave **Auto update** off for this app, so you see each new version before it installs.

## Pairing

Pairing gives the app three things from Hark: the secret that signs commands, the address of Hark's server, and the
public half of Hark's **approval key**. Nothing to paste:

1. On first start the app puts a one-time **public** key in Home Assistant (`sensor.hark_gateway_pairing_request`) and
   prints its fingerprint in the app's own Log.
2. Hark compares that fingerprint with the app's Log (so a key swapped in by someone else is caught), locks the
   pairing data to the key, and writes the locked copy to `sensor.hark_gateway_pairing`.
3. The app unlocks it, checks it with Hark's server, saves it privately in the app's `/data` folder, and deletes both
   sensors.

The pairing window **closes** after it succeeds, and also 30 minutes after the app starts. To pair again (for example
after reinstalling Hark), switch on `reset_pairing`, save, restart the app, let Hark pair, then switch it off again.

## Approval for changes

- **Looking** (read-only) runs on its own: finding devices, port checks, web page reads on your network, DNS lookups,
  SNMP reads, ping and speed tests, reading Home Assistant states, reading firewall status.
- **Changing** always asks first: Wake-on-LAN, sending data to a device (POST/PUT/PATCH/DELETE), SSH commands,
  Home Assistant service calls, firewall changes. Hark tells you exactly what it wants to do; only after your yes does
  it sign an approval for that one command.
- Approvals are signed with a **separate key that only Hark holds**. The app keeps only the public half, so even
  someone who got a copy of the app's data (for example from a backup) could not approve changes.
- Some Home Assistant calls are never allowed (`hassio.*`, and anything that would change the app's own kill switch),
  and some need Hark to say "this one is risky" explicitly (restarting Home Assistant, shell commands, scripts,
  automations, locks, alarm panels, notifications and similar).

## The off switch (kill switch)

The app creates a toggle **Hark Gateway enabled** (`input_boolean.hark_gateway_enabled`), switched on.

- **On:** Hark can use the network tools (changes still need your yes).
- **Off, missing, or unavailable:** every network command is refused. Status questions are still answered.
- Printing keeps working either way; daily print limits (below) protect your paper instead.
- Any Home Assistant user who can see the toggle can switch it. Hark cannot switch it on for itself.
- Harder off switch: set `enabled` to off in the Configuration tab and restart.

## What the app will and won't touch

- Only devices on your own network (private addresses). Never: this machine's loopback, Home Assistant's internal
  Supervisor/app networks, cloud metadata addresses, or internet addresses.
- Tools that send data (web requests, probes, SNMP, SSH) also never target the Home Assistant machine itself.
- Names are looked up once and the checked address is used for the connection; web redirects are not followed.
- DNS lookups go to a device on your network or a well-known public resolver; the speed test always uses one fixed
  public test server.
- Every tool has rate limits (for example 2 network sweeps a minute, 30 port scans an hour).

## Print limits

Defaults: 50 documents and 500 pages a day, 100 pages per document, 200 receipts a day, documents up to 25 MB.
Documents that contain printer-control escape codes are refused. Change the limits in the Configuration tab.

## Privacy of results

- Answers left in Home Assistant (`sensor.hark_gateway_result_…`) are encrypted; Hark removes them after reading,
  and the app removes leftovers after 15 minutes.
- Home Assistant reads redact passwords, tokens, cookies and GPS coordinates; web results drop session cookies and
  login headers.
- Hark's server keeps command results for 7 days.
- Optional, recommended: keep these out of Home Assistant's history database by adding to `configuration.yaml`:

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
- **sensor.hark_gateway**: on/off, listening for Hark, paired/provisioned, enabled tools, the SSH public key.
- The last 2,000 commands are also kept inside the app (`/data/audit.jsonl`).
- Printer status: **sensor.document_printer** and **sensor.receipt_printer**.

## Firewall API (optional)

For an OPNsense-style firewall: create an API key and secret for a dedicated user (System > Access > Users > API keys)
and paste them into `opnsense_key` and `opnsense_secret`. `opnsense_host` is optional: if empty, the app uses your
network's default gateway. The tool only ever talks to that one host; reads run freely, changes need your yes.

## SSH (optional)

The app makes its own SSH key. Add the `ssh_public_key` attribute of `sensor.hark_gateway` to
`~/.ssh/authorized_keys` on a machine you want Hark to reach. The first connection remembers the machine's host key;
a changed host key is refused. Every SSH command needs your yes.

## Home Assistant configuration and dashboards (1.3.0)
Hark can read `configuration.yaml` and files in `packages/`, see a dashboard's outline, and run Home Assistant's
configuration check on its own. Writing `configuration.yaml` or `packages/<name>.yaml`, or replacing a dashboard,
needs your yes every time; the approval carries a fingerprint of the exact content. Old files are copied to
`hark_backups/` in your config folder first. `secrets.yaml`, `.storage` and every other file are off limits.
Turn this off with `tool_ha_config: false`.

## Options

| Option | What it does |
| --- | --- |
| `gateway_secret` | Leave empty: the app pairs with Hark by itself. |
| `enabled` | Hard on/off for the network tools (printing is not affected). |
| `reset_pairing` | Switch on + restart to pair again once; switch off afterwards. |
| `site` | Optional. Hark's server address normally arrives with pairing. |
| `opnsense_host`, `opnsense_key`, `opnsense_secret` | Firewall API (optional). |
| `tool_*` | Turn single tools on or off. |
| `daily_doc_jobs`, `daily_doc_pages`, `max_pages_per_job`, `daily_receipts` | Print limits. |
| `printer_ip`, `doc_printer_ip`, `doc_printer_model` | Only if a printer is not found by itself. |
| `print_token` | Troubleshooting only. |

## Troubleshooting

- **Nothing prints:** open the app's **Log**. "waiting for Hark to pair" or "needs setup from Hark": tell Hark.
  "daily limit reached": raise the limit or wait until tomorrow.
- **Hark says the app isn't answering:** the Log should show "ha events: subscribed to hark_gateway_command".
- **Network commands refused with "kill switch":** check that `input_boolean.hark_gateway_enabled` exists and is on.

# For Hark: setting up and using the Hark Home Assistant Gateway

These are instructions for Hark (or any assistant with a shell, Python 3.9+ and a secure vault) to do its side of
the setup for a user, end to end, and then use the gateway. The user's side is in the app's `DOCS.md` and
the relay guide (`hark_gateway/relay/DEPLOY.md`). You never need access to the user's Home Assistant.

## Get the client

Put these three files from this repository in one folder (standard library only, nothing to install):

- `hark_gateway/hark/hark_gw.py` (the client)
- `hark_gateway/ed25519.py` and `hark_gateway/pairing.py` (the exact code the app checks signatures with)

Raw links: `https://raw.githubusercontent.com/kdttocs/HA/main/hark_gateway/hark/hark_gw.py`, and the same with
`ed25519.py` and `pairing.py` (without `hark/`). Run `python3 hark_gw.py --help` to see every command.

The client keeps its state in `~/.hark-gateway` (or `--home DIR`, or env `HARK_GW_HOME`), files readable only by you.
Every command prints one JSON object. Exit codes: 0 ok, 1 error or refused, 2 timed out, 3 waiting for the user.

## Rules you must keep

- **Never show a secret** (approval seed, gateway secret, document token) in chat, logs or files the user sees. The
  only command that prints them is `export-secrets`, and its output goes straight into your secure vault.
- **Changes need the user's clear yes to that exact change.** When `run` exits with 3, describe the change in plain
  words (tool, target, what will happen) and wait. Only after a clear yes run `approve ID`; after a no, `deny ID`.
  Never approve on your own, never reuse a yes for a different command, never approve a batch on one vague yes.
- Use one approval key per user. Never put the same key on two people's relays.

## Setup, step by step

1. **Make your approval key** (once per user): `python3 hark_gw.py keygen`. It prints only the public key.
2. **Give the user the public key** (`approval_public_key`, 64 hex characters). It is safe to share. The user
   clicks **Deploy to Cloudflare** in `relay/DEPLOY.md` and pastes it into `GW_APPROVAL_PUB`.
3. **Claim the relay** when the user sends its address: `python3 hark_gw.py claim https://<relay address>`. The relay
   hands its own secrets over once, signed with your key; the client saves them and confirms. If it fails, the JSON
   has a `hint` (for example: the key on the relay is not yours, or the relay was already claimed).
4. **Store everything in your vault now:** `python3 hark_gw.py export-secrets` and save the whole JSON as one secret
   (for example "Hark Gateway keys for <user>"). On another machine, restore it with
   `python3 hark_gw.py import-secrets < saved.json`, or set the env variables listed in `--help`.
5. **The user installs the app**, puts the relay address into its **Relay address** option, starts it, and reads
   you the **pairing code** from the app's Log (`pairing: pairing code 3f9a-41c2-77de`).
6. **Pair:** `python3 hark_gw.py pair --code 3f9a-41c2-77de`. You only ever answer the request whose fingerprint
   matches the user's code. On success the app's Log says `pairing: done through relay; answered by key <answer_key>`;
   `answer_key` in your output should be the same.
7. **First look:** `python3 hark_gw.py run status`. It answers within a few seconds (`via: relay`).

The pairing window is open for 30 minutes after the app starts; if it closed, ask the user to restart the app for a
new code. To pair again later the user switches on `reset_pairing` and restarts the app.

## Using it

- Read tools run at once: `python3 hark_gw.py run TOOL '{"arg": "value"}'`, for example
  `run port_scan '{"host": "10.20.30.40"}'`, `run devices`, `run internet`, `run http '{"url": "http://10.20.30.1"}'`.
  The tool list and what each does is in the app's `DOCS.md` ("Tools you can switch off").
- Change tools (`wol`, `ssh`, `ha_service`, `ha_file_write`, `lovelace_save`, `http` with POST/PUT/PATCH/DELETE,
  `firewall` with any method but GET): `run` holds them and exits 3. Ask the user, then `approve ID` or `deny ID`.
- Home Assistant configuration: `push-file packages/NAME.yaml LOCAL.yaml` or `push-dashboard URL_PATH LOCAL.json`
  stage the content and hold the write for approval; the approval covers that exact content only.
- Printing: `python3 hark_gw.py print FILE.pdf [--copies 2] [--sides two-sided-long-edge] [--color monochrome]`.
- Health of the setup: `python3 hark_gw.py status` (when the app last checked in, version, pending approvals).
- Results: `result ID`, the last 30 commands: `list`.
- New-device alerts: when the user says what a new device is, mark it: `run devices '{"mark": "known", "mac":
  "00:00:5e:00:53:01", "name": "Living room TV"}'` (`"mark": "ignore"` to silence it without a name, `"new"` to undo).
  `run devices '{"new_only": true}'` lists unreviewed new devices with the app's best guess for each.

## Optional: through Home Assistant

Only if the user's Home Assistant is reachable from the internet and they give you a long-lived access token
(their profile page > Security). Then `echo TOKEN | python3 hark_gw.py ha https://<their HA address> --token-stdin`.
Commands are then also delivered as the Home Assistant event `hark_gateway_command`, and `pair` without `--code` pairs
through Home Assistant (it checks the app's Log through the Supervisor, which needs an admin token, or takes
`--fingerprint CODE`). This is a speed-up and a backup path, never required.

## Troubleshooting

- `claim` says 503: the relay has no `GW_APPROVAL_PUB` yet. 401: the key on the relay is not yours (check with
  `approval-pub`). 409: already claimed or set by hand; see "If something goes wrong" in the relay guide (`hark_gateway/relay/DEPLOY.md`).
- `pair --code` times out: the app has no Relay address set, the relay is older than 2.0.4, or the code expired.
- Commands time out: `status` shows `app_seen_sec_ago`; if it is large the app is stopped or offline.
- Refusals come back as `status: rejected` with the app's reason (for example the kill switch is off, or a tool
  is switched off in the app's options). Tell the user the reason in plain words.

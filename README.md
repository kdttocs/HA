# Hark Apps (Home Assistant app repository)

- **Hark HA Gateway** (`hark_gateway`): prints Hark's documents and receipts on your network printers, and lets Hark run
  network tools on your home network. Looking is automatic; any change waits for your approval, signed with a key only
  Hark holds. Hark reaches it through your Home Assistant; no port forwarding, nothing to paste.

Add this repository in Home Assistant: Settings > Apps > App store > ⋮ > Repositories:
`https://github.com/kdttocs/HA`

This repository holds no secrets, device addresses or server addresses. The app gets everything it needs from Hark
through Home Assistant when it pairs, and keeps it in the app's private `/data` folder.

Security notes: see `hark_gateway/DOCS.md` ("Approval for changes", "What the app will and won't touch").

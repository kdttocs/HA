# Hark Home Assistant Gateway

![Supports aarch64][aarch64] ![Supports amd64][amd64]

![Hark watching over a home network](https://raw.githubusercontent.com/kdttocs/HA/main/hark_gateway/images/hero-v2.jpg)

**Give Hark a seat inside your home network.**

> ### 🔒 Security first
>
> Letting an AI into your network should make you suspicious. Here's what protects you:
>
> - **Nothing changes without your yes.** Hark can look on its own, but every change (router settings, SSH, waking
>   or controlling devices) is refused unless you approve that exact command. Approvals are signed with a separate
>   key the app itself doesn't hold, so even a stolen copy of the app can't approve anything.
> - **No open doors.** No port forwarding and no inbound connections. The app only reaches out to a relay you run
>   yourself on your own free Cloudflare account.
> - **Home network only.** It can only reach private home addresses, never the wider internet (apart from a few fixed
>   DNS and speed-test servers) and never Home Assistant's own internals.
> - **Undo and off switch.** Router settings are backed up before every change and can be rolled back. A kill switch
>   in Home Assistant refuses every network command the moment you flip it, and Hark can't switch it back on. Every
>   command is written to an audit log.
> - **Optional phone tap.** Turn on phone approval and every change also needs a tap in the Home Assistant app.
> - **Open source.** Every line is in this folder for you to read. Full details:
>   https://github.com/kdttocs/HA/blob/main/hark_gateway/SECURITY.md

Your network is the most important system in your house, and the one nobody watches. Hark Home Assistant Gateway changes that.
It gives Hark, your AI, a secure foothold inside your network through Home Assistant, so it can see what you can't,
explain what it finds in plain language, and fix things the moment you say yes.

Ask it anything:

- *"Why is the internet slow tonight?"* Hark tests your connection, checks your router, and tells you whether it's
  your provider, your Wi-Fi, or one device hogging it.
- *"What's this device I don't recognize?"* Hark finds it, identifies it, and can block it, with your approval.
- *"Wake up my PC," "Print this," "Is the garage camera still online?"* Done, from anywhere.

And it works when you're not asking: you get an alert when a new device joins that says who made it and what it probably is (and you can mark it Known or Ignore), your internet health shows up as Home
Assistant sensors, there's a nightly speed test, and a weekly check-up reports anything that drifted.

## You stay in charge

- **Looks freely, changes nothing without you.** Reading is automatic. Every change needs your yes, signed with a
  separate approval key.
- **Every change can be undone.** Router settings are backed up before each change, and you can roll back in one step.
- **Nothing opens to the internet.** No port forwarding. The gateway reaches out to Hark; nothing reaches in.
- **One switch stops everything.** A kill switch in Home Assistant pauses it instantly, and a full audit log shows
  every action.

## What it can do

Find devices and see what's running on them · test internet speed, latency and packet loss · read and manage your
router (OPNsense; pfSense, OpenWrt and UniFi in beta) · Wake-on-LAN · SSH to computers you approve · DNS and SNMP
lookups · Home Assistant states and services · print documents and receipts on request.

## Get started

Setup is in the **Documentation** tab. A free Cloudflare Worker relay is all it needs: one **Deploy to Cloudflare**
button, one key from Hark to paste, about 3 minutes, no terminal. Then install the app, give it your relay's address,
and read Hark the pairing code from the app's Log. Hark doesn't need access to your Home Assistant.

- Relay setup (free Cloudflare Worker): https://github.com/kdttocs/HA/blob/main/hark_gateway/relay/DEPLOY.md
- How it's protected: https://github.com/kdttocs/HA/blob/main/hark_gateway/SECURITY.md

## License

MIT. See the LICENSE file in this folder.

[aarch64]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64]: https://img.shields.io/badge/amd64-yes-green.svg

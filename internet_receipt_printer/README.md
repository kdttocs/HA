# Internet Receipt Printer

![Supports aarch64][aarch64] ![Supports amd64][amd64]

Put a small web page on the internet where anyone with the link can type a short message, and it prints on a
receipt printer at your home.

- Messages wait in **your own relay**, a free Cloudflare Worker you deploy from this app's folder.
- Works with network receipt printers that speak ESC/POS on port 9100.
- Prints only when the printer's ready, with a daily paper limit and printer control codes stripped from messages.
- Never sends anything to page printers (laser or inkjet).
- Pairs with Hark automatically, or set the relay address and token yourself.

Setup is in the **Documentation** tab. More in this app's folder:

- Relay setup (free Cloudflare Worker): https://github.com/kdttocs/HA/blob/main/internet_receipt_printer/relay/DEPLOY.md
- How it's protected: https://github.com/kdttocs/HA/blob/main/internet_receipt_printer/SECURITY.md

## License

MIT. See the LICENSE file in this folder.

[aarch64]: https://img.shields.io/badge/aarch64-yes-green.svg
[amd64]: https://img.shields.io/badge/amd64-yes-green.svg

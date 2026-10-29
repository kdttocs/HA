#!/usr/bin/env python3
"""Rebuild oui.txt.gz, the offline "who made this network card" table used by the new-device alert.

Run this on a maintainer machine (never inside the app; the app does not download anything):

    python3 maintenance/oui_refresh.py                 # downloads the public IEEE MA-L list
    python3 maintenance/oui_refresh.py path/to/oui.txt # or uses a copy you already downloaded

Source: IEEE Registration Authority, MA-L (the large 24-bit blocks), https://standards-oui.ieee.org/oui/oui.txt
Output: hark_gateway/oui.txt.gz (one folder up). Format (gzip, UTF-8): one line per block, "AABBCC<TAB>Organization",
sorted by prefix. Names are tidied a little (spacing, ALL-CAPS turned into Title Case) and nothing else.
"""
import gzip, os, re, sys, urllib.request

URL = "https://standards-oui.ieee.org/oui/oui.txt"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "oui.txt.gz")   # hark_gateway/oui.txt.gz
LINE = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.*?)\s*$")
SMALL = {"of", "and", "the", "for", "de", "a"}
KEEP_UPPER = {"LG", "HP", "AVM", "ASUS", "TCL", "IBM", "NEC", "ZTE", "BSH", "SMC", "D-LINK", "GE", "AG", "SA",
              "SAS", "LLC", "GMBH", "PTE", "LTD", "INC", "CO", "BV", "AB", "AS", "OY", "SPA", "SRL", "KG", "USA", "UK", "II"}


def tidy(name):
    name = re.sub(r"\s+", " ", name).strip().strip(",")
    letters = [c for c in name if c.isalpha()]
    if letters and sum(c.isupper() for c in letters) / len(letters) > 0.9 and len(name) > 4:
        words = []
        for i, w in enumerate(name.split(" ")):
            core = w.strip(".,()")
            if core.upper() in KEEP_UPPER and core.upper() not in ("GMBH", "PTE", "LTD", "INC", "CO", "LLC"):
                words.append(w)
            elif i and core.lower() in SMALL:
                words.append(w.lower())
            else:
                words.append("-".join(p[:1].upper() + p[1:].lower() for p in w.split("-")))
        name = " ".join(words)
    return name[:80]


def build(text):
    rows = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if m and m.group(2):
            rows[m.group(1)] = tidy(m.group(2))
    if len(rows) < 20000:
        raise SystemExit(f"only {len(rows)} entries found; is that the IEEE oui.txt file?")
    body = "".join(f"{k}\t{v}\n" for k, v in sorted(rows.items())).encode()
    with gzip.GzipFile(OUT, "wb", compresslevel=9, mtime=0) as f:
        f.write(body)
    return len(rows)


def main():
    if len(sys.argv) > 1:
        text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    else:
        req = urllib.request.Request(URL, headers={"User-Agent": "Wget/1.21 (hark-gateway oui refresh)"})
        text = urllib.request.urlopen(req, timeout=120).read().decode("utf-8", errors="replace")
    n = build(text)
    print(f"wrote {OUT}: {n} makers, {os.path.getsize(OUT) // 1024} KB")


if __name__ == "__main__":
    main()

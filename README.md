<div align="center">

# 🔐 Hacking Vault

**My personal pentesting and offensive-security arsenal**

OSINT · Recon · Web · Scan · Crypto · Forensics · Shells — with a terminal menu and a web console

</div>

---

## ⚠️ Authorized use only

> Everything here is for **educational purposes** and for systems where you have
> **explicit permission** (labs, HTB/TryHackMe, CTFs, contracted engagements).
> Misuse is illegal. The author takes no responsibility for improper use.

---

## 📁 Layout

Tools only. Everything is **Python stdlib** (no `pip`), one file per tool and
self-documented (`-h`).

```
hacking-vault/
│
├── 🚀 hvault.py      Unified launcher: terminal menu + web console + report
├── 🧩 hvault/        Launcher core (declarative registry, menu, web, runner, report)
├── 🐍 scripts/       Tools by category
│   ├── osint/        Passive OSINT: crt.sh, username hunt, DNS/WHOIS, Wayback
│   ├── recon/        Active recon: ports without nmap, DNS/AXFR, web, HTTP probe
│   ├── web/          Web app testing: content discovery, CORS misconfig
│   ├── crypto/       Crypto/CTF: magic-decode, encode, classic ciphers, hashid, JWT
│   ├── forensics/    Forensics/CTF: file inspection, strings, carving, entropy
│   └── shells/       Reverse shells + listener
└── 🧰 tools/
    └── vulnscan/     All-in-one auditor that chains your tools
```

---

## 🚀 Unified launcher

A single front door to every tool, from a terminal menu or a local web console.
No dependencies.

```bash
python3 hvault.py              # interactive terminal menu (default)
python3 hvault.py web          # local web console, opens in the browser
python3 hvault.py list         # list every tool and its id
python3 hvault.py run osint.crtsh example.com --live   # run one directly
python3 hvault.py report example.com                   # chain passive tools into one report
```

The web console listens on **loopback only** and guards every request with a
random key carried in the URL, so nothing off your machine can reach it. Each
tool stays usable on its own (`python3 scripts/osint/crtsh.py ...`); the launcher
is a convenience layer on top. Details: [`hvault/README.md`](hvault/README.md).

---

## 🧾 One target, one report

`report` is the global mode: point it at a domain or host and it sweeps every
applicable tool - chosen from the registry, so a new OSINT script joins the sweep
by itself - and writes a single Markdown report under `reports/` (git-ignored).
OSINT runs by default; `--active` adds Recon and Web. Use `--only <category>` to
gather one whole area at once (all of OSINT, all of Recon...). Individually you
reach for one tool; globally you get the whole picture with one command.

```bash
python3 hvault.py report example.com            # passive profile (safe by default)
python3 hvault.py report example.com --only osint   # run all of OSINT at once
python3 hvault.py report 10.10.10.10 --active   # add light active recon (ports, web)
```

---

## ⭐ Flagship: `vulnscan`

An **all-in-one console security auditor** that chains your tools (nmap, httpx,
nuclei, ffuf, sqlmap, subfinder, SMB, hydra...) into a single flow.

```bash
python3 tools/vulnscan/vulnscan.py <target> --full
```

| | |
|---|---|
| 🌐 **Network** | ports and services with nmap |
| 🕸️ **Web** | fingerprint, headers, TLS, XSS/SQLi, fuzzing |
| 🪟 **SMB/AD** | null sessions, shares, users |
| 🔎 **DNS** | records and zone transfer |
| 📄 **Report** | findings by severity + attack vectors |

➡️ Full guide: [`tools/vulnscan/README.md`](tools/vulnscan/README.md)

---

## 🧰 Included tools

| Tool | Category | What it does |
|------|----------|--------------|
| `scripts/osint/crtsh.py` | OSINT | Passive subdomains from Certificate Transparency (crt.sh) |
| `scripts/osint/username-hunt.py` | OSINT | Where a username is registered across ~30 public sites |
| `scripts/osint/footprint.py` | OSINT | Passive footprint: DNS (over HTTPS) + WHOIS |
| `scripts/osint/wayback.py` | OSINT | Archived URLs for a domain from the Wayback Machine (CDX) |
| `scripts/recon/dnsrecon.py` | Recon | DNS records, AXFR attempt and subdomain brute force |
| `scripts/recon/portscan.py` | Recon | Threaded TCP scanner for boxes without nmap |
| `scripts/recon/webenum.py` | Recon | Fast web recon (headers, cookies, methods, paths) |
| `scripts/recon/httpprobe.py` | Recon | Probe a host list for live HTTP(S): status, title, server |
| `scripts/web/dirscan.py` | Web | Wordlist content discovery (dirs/files), threaded |
| `scripts/web/cors-check.py` | Web | Detect permissive / misconfigured CORS |
| `scripts/crypto/magic-decode.py` | Crypto/CTF | Peel layered encodings until text or a flag drops out |
| `scripts/crypto/encode.py` | Crypto/CTF | The inverse: encode into base64/32/hex/url/rot13/binary (`all`) |
| `scripts/crypto/classic-cipher.py` | Crypto/CTF | Caesar/XOR/Vigenere/Atbash/railfence/frequency with scoring (`all`) |
| `scripts/crypto/jwt-tool.py` | Crypto/Web | Decode a JWT, flag `alg:none`, verify or dictionary-crack HS256 |
| `scripts/crypto/hashid.py` | Credentials | Identify a hash and print the `hashcat`/`john` command |
| `scripts/forensics/fileinspect.py` | Forensics | Magic bytes, strings, entropy and embedded-file carving |
| `scripts/shells/revshell.py` | Exploitation | Reverse shells across interpreters + listener |
| `tools/vulnscan/vulnscan.py` | Scan | All-in-one auditor (network, web, SMB/AD, nuclei, fuzzing, report) |

➡️ Per-category detail: [`scripts/README.md`](scripts/README.md) ·
[`osint/`](scripts/osint/README.md) · [`recon/`](scripts/recon/README.md) ·
[`web/`](scripts/web/README.md) · [`crypto/`](scripts/crypto/README.md) ·
[`forensics/`](scripts/forensics/README.md) · [`shells/`](scripts/shells/README.md)

---

## 🎯 What each category covers

| Category | What lives here |
|----------|-----------------|
| 🕵️ **OSINT** | passive recon: subdomains, usernames, DNS/WHOIS, archived URLs |
| 🔍 **Recon** | port scanning, DNS/AXFR, active web recon, HTTP probing |
| 🕸️ **Web** | content discovery, CORS and web-app misconfig checks |
| 🛡️ **Scan** | chained auditing with `vulnscan` |
| 🧩 **Crypto/CTF** | decoding/encoding, classic ciphers, hash and JWT work |
| 🔬 **Forensics** | file typing, strings, entropy, embedded-file carving |
| 🐚 **Shells** | reverse shells and listeners |

---

## 🧩 Tools that run every function at once

The multi-function tools take an `all` mode (also the default when you name no
sub-function), so you can throw input at them and let scoring surface the answer:

```bash
python3 scripts/crypto/classic-cipher.py "iodj{...}"   # tries every cipher, ranks hits
python3 scripts/crypto/encode.py "secret"              # shows every encoding at once
python3 scripts/crypto/magic-decode.py <blob>          # peels every layer automatically
```

---

## 🚀 Quick start

```bash
# Clone
git clone <repo> hacking-vault && cd hacking-vault

# (pwnix) activate the Python environment if you use it for the third-party tools
wsvenva

# Menu for everything, a tool directly, or one report for a target
python3 hvault.py
python3 hvault.py report <target>
python3 tools/vulnscan/vulnscan.py <target> --full
```

> 💡 Scan results and reports are written to local folders that `.gitignore`
> **excludes automatically** from the repository.

---

## 🔗 Useful resources

- 📚 [HackTricks](https://book.hacktricks.xyz/)
- 🐧 [GTFOBins](https://gtfobins.github.io/)
- 🎒 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- 🛡️ [OWASP](https://owasp.org/)

---

<div align="center">

📜 MIT License · for educational purposes

**Hack ethically, always with permission.** 🎯

</div>

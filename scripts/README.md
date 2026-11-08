# scripts

Standalone helpers for OSINT, recon, CTF crypto and getting a shell. All are pure
**Python standard library** (no `pip install`), single-file, and self-documented
(`-h` on any of them). Each category folder has a short README explaining its tools.

Everything here is also wired into the unified launcher at the repo root - run
`python3 hvault.py` for a terminal menu or `python3 hvault.py web` for a local web
console over the same tools.

> ⚠️ Authorized / educational use only: labs, HTB/TryHackMe, CTFs, or engagements
> with written permission.

| Script | Category | Uses | What it does |
|--------|----------|------|--------------|
| [`osint/crtsh.py`](osint/crtsh.py) | OSINT | Python 3 | Passive subdomain enumeration from Certificate Transparency logs (crt.sh). |
| [`osint/username-hunt.py`](osint/username-hunt.py) | OSINT | Python 3 | Finds where a username is registered across ~30 public sites. |
| [`osint/footprint.py`](osint/footprint.py) | OSINT | Python 3 | Passive DNS (over HTTPS) + WHOIS registration footprint of a domain. |
| [`recon/dnsrecon.py`](recon/dnsrecon.py) | Recon | Python 3 | DNS records, zone-transfer (AXFR) attempt and subdomain brute force. |
| [`recon/portscan.py`](recon/portscan.py) | Recon | Python 3 | Threaded TCP connect scanner for boxes without nmap. |
| [`recon/webenum.py`](recon/webenum.py) | Recon | Python 3 | Quick single-host web recon: headers, cookies, methods, paths (detection only). |
| [`crypto/magic-decode.py`](crypto/magic-decode.py) | CTF crypto | Python 3 | Recursively peels layered encodings until it reaches text or a flag. |
| [`crypto/classic-cipher.py`](crypto/classic-cipher.py) | CTF crypto | Python 3 | Caesar/XOR/Vigenere/Atbash/railfence/frequency, with scoring. |
| [`crypto/hashid.py`](crypto/hashid.py) | Credentials | Python 3 → `hashcat`/`john` | Identifies a hash and prints the matching crack command. |
| [`shells/revshell.py`](shells/revshell.py) | Exploitation | Python 3 → `nc`/`socat` | Reverse-shell one-liners across interpreters, plus the listener. |

> **Uses** = what the script runs on. All need only **Python 3** (standard library,
> no `pip`); `→` marks the external tool the script hands off to - you run that one
> yourself, it is not required for the script to work.

Per-category detail: [`osint/`](osint/README.md) · [`recon/`](recon/README.md) ·
[`crypto/`](crypto/README.md) · [`shells/`](shells/README.md).

## Examples

```bash
# OSINT: passive subdomains, then who/where
python3 scripts/osint/crtsh.py example.com --live
python3 scripts/osint/footprint.py example.com
python3 scripts/osint/username-hunt.py johndoe --found-only

# Recon without nmap, DNS + zone transfer, then a web service
python3 scripts/recon/portscan.py 10.10.10.10 -p 1-1024 --banner
python3 scripts/recon/dnsrecon.py example.com --axfr --brute
python3 scripts/recon/webenum.py http://10.10.10.10

# CTF crypto and credentials
python3 scripts/crypto/magic-decode.py "NzM2NTYzNzI2NTc0"
python3 scripts/crypto/hashid.py 5f4dcc3b5aa765d61d8327deb882cf99

# A reverse shell for your listener
python3 scripts/shells/revshell.py 10.10.14.5 4444 -t bash --base64
```

Every script prints full help with `-h`.

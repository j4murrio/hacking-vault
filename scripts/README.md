# scripts

Standalone helpers for recon, CTF crypto and getting a shell. All are pure
**Python standard library** (no `pip install`), single-file, and self-documented
(`-h` on any of them). They complement — never duplicate — the archpwm shell
functions (`revshell`, `serve`, `listen`, `nmap-extract`…) and `tools/vulnscan`.

> ⚠️ Authorized / educational use only: labs, HTB/TryHackMe, CTFs, or engagements
> with written permission.

| Script | Category | Uses | What it does |
|--------|----------|------|--------------|
| [`crypto/magic-decode.py`](crypto/magic-decode.py) | CTF crypto | Python 3 | Recursively peels layered encodings (base64/32/85, hex, URL, ROT13, binary, decimal, morse, gzip/zlib/bz2) until it reaches text or a flag. |
| [`crypto/classic-cipher.py`](crypto/classic-cipher.py) | CTF crypto | Python 3 | Caesar/ROT brute, single-byte & repeating-key XOR, Vigenère, Atbash, rail fence, frequency analysis — with scoring so the plaintext floats up. |
| [`crypto/hashid.py`](crypto/hashid.py) | Credentials | Python 3 → `hashcat` / `john` | Identifies a hash and prints the matching `hashcat -m` / `john --format` command. |
| [`recon/portscan.py`](recon/portscan.py) | Recon | Python 3 | Threaded TCP connect scanner for boxes without nmap (restricted shells, containers). |
| [`recon/webenum.py`](recon/webenum.py) | Web | Python 3 | Quick single-host web recon: headers, cookies, methods, robots, interesting paths (detection only). |
| [`shells/revshell.py`](shells/revshell.py) | Exploitation | Python 3 → `nc` / `socat` | Portable reverse-shell one-liners (9 interpreters) + listener, with URL/base64 variants. |

> **Uses** = what the script runs on. All six need only **Python 3** (standard
> library, no `pip`); `→` marks the external tool the script hands off to — you run
> that one yourself, it is not required for the script to work.

## Examples

```bash
# CTF: auto-decode a layered blob, or brute a single-byte XOR
python3 scripts/crypto/magic-decode.py "NzM2NTYzNzI2NTc0"
python3 scripts/crypto/classic-cipher.py xor --brute --hex "$(cat cipher.hex)"

# Identify a hash and get the crack command
python3 scripts/crypto/hashid.py 5f4dcc3b5aa765d61d8327deb882cf99

# Recon without nmap, then look at a web service
python3 scripts/recon/portscan.py 10.10.10.10 -p 1-1024 --banner
python3 scripts/recon/webenum.py http://10.10.10.10

# Generate a reverse shell for your listener
python3 scripts/shells/revshell.py 10.10.14.5 4444 -t bash --base64
```

Every script prints full help with `-h`.

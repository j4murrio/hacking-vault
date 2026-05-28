# vulnscan

Console-based security auditor: **network · web · SMB/AD · DNS**.

Part of [hacking-vault](https://github.com/j4murrio/hacking-vault) —
built to run on the [archpwm](https://github.com/j4murrio/archpwm) hacking
environment, but fully usable on any Linux system with the tools installed.

---

## ⚠️ Legal notice

Use **only** against systems you are explicitly authorized to test: your own
labs, HTB / TryHackMe machines, CTFs, or engagements with written permission.
Unauthorized use is illegal. The brute-force phase is especially noisy — only
enable it when appropriate.

---

## What it does

```
  Target: IP · CIDR · domain · URL
       │
       ├─ DNS       dig        DNS records + zone transfer (AXFR)    [domains]
       ├─ SUBDOM    subfinder  subdomain enum + live probe            [domains]
       ├─ NETWORK   nmap       ports + services (-sV -sC)
       │
       ├─ per host / service:
       │   ├─ SMB   netexec / enum4linux / smbclient
       │   └─ WEB   httpx · Python checks · sqlmap · ffuf · nuclei
       │
       └─ reports/<host>_<timestamp>/
              REPORT.md   findings by severity + attack vectors
```

Every phase is **fault-tolerant**: if a tool is missing it warns and skips
instead of crashing. Run `--check-tools` to see what's installed.

---

## Tools used

| Layer       | Tools                                        | Required |
|-------------|----------------------------------------------|:--------:|
| DNS         | `dig` (bind-tools)                           | No       |
| Subdomains  | `subfinder`, `httpx`                         | No       |
| Network     | `nmap`                                       | **Yes**  |
| SMB / AD    | `netexec` / `nxc`, `enum4linux`, `smbclient` | No       |
| Web         | `httpx`, `ffuf`, `nuclei`, `sqlmap`          | No       |
| Web (built-in) | `requests` + `beautifulsoup4` (Python)    | Recommended |
| Brute-force | `hydra`                                      | No       |

---

## Setup

The script needs two things: **system tools** (nmap, ffuf, nuclei…) and two
**Python libraries** (`requests`, `beautifulsoup4`). How you get them depends
on whether you are running archpwm or a generic Linux system.

### archpwm environment

> [archpwm](https://github.com/j4murrio/archpwm) is a ready-made Arch Linux
> hacking environment. It ships with BlackArch repos, all tools pre-listed,
> and a persistent Python venv with all hacking libraries already installed.

```bash
# 1. Install system tools (BlackArch / pacman)
sudo pacman -S nmap bind-tools subfinder httpx ffuf nuclei sqlmap \
               netexec enum4linux smbclient hydra seclists

# 2. Activate the shared workspace venv (requests, bs4, etc. already inside)
wsvenva

# 3. First run: update nuclei templates
nuclei -update-templates

# 4. Verify all tools are found
python3 vulnscan.py --check-tools
```

**archpwm-specific commands used in this script:**

| Command | What it does | Defined in |
|---------|-------------|------------|
| `wsvenva` | Activates the shared venv at `~/Workarea/.python-hacking-venv` | `~/.zshrc` |
| `wsvenvr` | Deletes and recreates the workspace venv with all libraries | `~/.zshrc` |
| `venvc`   | Creates a local `./venv` in the current directory | `~/.zshrc` |
| `venva`   | Activates the local `./venv` | `~/.zshrc` |
| `venvr`   | Removes the local venv | `~/.zshrc` |
| `wsinit`  | Initialises the full `~/Workarea/` folder structure | `~/.zshrc` |

These are shell aliases defined by archpwm. They do **not** exist on a
generic system — see the equivalent commands below.

---

### Generic Linux (Debian/Ubuntu/Kali/any distro)

```bash
# 1. Install system tools — adjust to your distro
# Debian / Kali
sudo apt install nmap dnsutils ffuf sqlmap hydra smbclient enum4linux -y

# nuclei (Go binary — no package on most distros)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# netexec (pip or pipx)
pipx install netexec

# 2. Create a Python venv for the script
python3 -m venv .venv
source .venv/bin/activate          # Linux / macOS
# .venv\Scripts\activate           # Windows

# 3. Install Python libraries
pip install requests beautifulsoup4

# 4. First run: update nuclei templates
nuclei -update-templates

# 5. Verify all tools are found
python3 vulnscan.py --check-tools
```

---

### archpwm vs generic — side-by-side reference

Every command or path in the table below is **archpwm-specific** on the left
and its **generic equivalent** on the right.

| Action | archpwm | Generic Linux |
|--------|---------|---------------|
| Activate shared Python venv | `wsvenva` | `source .venv/bin/activate` |
| Recreate venv from scratch | `wsvenvr` | `rm -rf .venv && python3 -m venv .venv && source .venv/bin/activate && pip install requests beautifulsoup4` |
| Create local project venv | `venvc` | `python3 -m venv .venv` |
| Activate local venv | `venva` | `source .venv/bin/activate` |
| Remove local venv | `venvr` | `rm -rf .venv` |
| Install tools | `sudo pacman -S <tool>` | `sudo apt install <tool>` / `go install …` / `pipx install …` |
| Default wordlist path | `/usr/share/seclists/Discovery/Web-Content/common.txt` | `/usr/share/seclists/…` (if installed) or pass `--wordlist <path>` |
| Install SecLists | `sudo pacman -S seclists` | `sudo apt install seclists` or `git clone https://github.com/danielmiessler/SecLists` |

> **Note:** The script detects missing tools at runtime — it never hard-codes
> archpwm paths except for the default wordlist, which you can always override
> with `--wordlist /your/custom/list.txt`.

---

## Quick start

```bash
# Check which tools are installed
python3 vulnscan.py --check-tools

# Default audit of an IP (nmap + web + SMB auto + nuclei)
python3 vulnscan.py 10.10.10.10

# Everything reasonable in one go
python3 vulnscan.py 10.10.10.10 --full

# Web app — spider, SQLi, directory fuzzing
python3 vulnscan.py http://target.com --spider --sqli --fuzz

# Domain — DNS records + subdomain enumeration
python3 vulnscan.py target.com --dns --subdomains

# Whole subnet, all 65535 ports
python3 vulnscan.py 10.10.10.0/24 --ports-full

# Authenticated web scan
python3 vulnscan.py http://target.com --cookie "session=abc123" -H "X-Api-Key: xyz"

# Brute-force SSH/FTP (NOISY — labs only)
python3 vulnscan.py 10.10.10.10 --bruteforce \
    --userlist users.txt --passlist /usr/share/wordlists/rockyou.txt
```

---

## All options

| Option | Description |
|--------|-------------|
| `target` | IP, CIDR range, domain or URL |
| `--check-tools` | Show installed / missing tools and install commands |
| `-o, --output` | Output folder (default: `reports/<host>_<timestamp>`) |
| `--full` | All reasonable phases (excludes brute-force and vuln-scripts) |
| `--ports-full` | Scan all 65535 ports |
| `--vuln-scripts` | `nmap --script vuln` — known CVEs, slower |
| `--dns` | DNS recon with dig (automatic for domains) |
| `--subdomains` | Subdomain enumeration with subfinder |
| `--spider` | Crawl the site to discover parameters and forms |
| `--sqli` | Automated SQL injection with sqlmap |
| `--fuzz` | Directory fuzzing with ffuf |
| `--smb` / `--no-smb` | Force / disable SMB enumeration |
| `--bruteforce` | SSH/FTP brute-force with hydra (opt-in, noisy) |
| `--no-nuclei` | Skip nuclei scan |
| `--wordlist` | Wordlist for fuzzing (default: SecLists `common.txt`) |
| `--userlist` / `--passlist` | Lists for hydra (small built-in defaults if omitted) |
| `--severity` | Filter nuclei by severity (e.g. `critical,high`) |
| `--cookie` | Session cookie for authenticated scanning |
| `-H, --header` | Extra HTTP header `Name: value` (repeatable) |

---

## Output structure

Results are saved to `reports/<host>_<timestamp>/`:

```
reports/10.10.10.10_20260528_101500/
├── dns.txt                DNS records and AXFR output
├── subdomains.txt         subfinder results
├── subdomains_live.txt    live subdomains (httpx probe)
├── nmap_discovery.*       fast port discovery
├── nmap_detailed.*        version + default scripts
├── nmap_vuln.txt          --script vuln output (if used)
├── netexec_<ip>.txt       SMB enumeration
├── enum4linux_<ip>.txt    SMB/Samba full enum
├── smbclient_<ip>.txt     share listing
├── httpx.txt              web fingerprint
├── ffuf_*.json            directory fuzzing results
├── nuclei.txt             vulnerability findings
├── sqlmap/                sqlmap output directory
├── hydra_*.txt            brute-force results
└── REPORT.md              findings by severity + attack vectors
```

The `reports/` folder is excluded from git by the project's `.gitignore`.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `'requests' not found` | **archpwm:** `wsvenva` · **Generic:** `source .venv/bin/activate` |
| nuclei finds nothing | `nuclei -update-templates` |
| Default wordlist missing | `sudo pacman -S seclists` (archpwm) · `sudo apt install seclists` (Debian) · or `--wordlist <path>` |
| nmap scan is slow / incomplete | Run with `sudo` (raw socket scans need root) |
| `--sqli` or `--fuzz` take too long | Normal for deep scans — interrupt with `Ctrl+C` and check partial results |
| SMB enum auto-triggered | Add `--no-smb` to skip it |

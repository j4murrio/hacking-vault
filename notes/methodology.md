# Methodology — box / engagement checklist

A repeatable order of operations for a single target (HTB/THM/lab/engagement).
Work top-down; take notes and screenshots as you go, not at the end.

> ⚠️ Authorized / educational use only.

## 1. Recon
- [ ] Confirm scope and connectivity (`ping`, VPN up, `myip`).
- [ ] Full TCP ports, then service/version on the open ones
      (`vulnscan <ip> --full`, or `nmap -p- --min-rate 2000` → `nmap -sVC -p<ports>`).
- [ ] UDP top ports if TCP is thin (`nmap -sU --top-ports 50`).
- [ ] Note every service, version and banner in the target notes.

## 2. Enumeration (per service)
- [ ] **Web** — `webenum`, directories (`ffuf`), vhosts, `nuclei`, source/JS, default creds.
- [ ] **SMB** — null session shares/users (`netexec`, `enum4linux`, `smbclient`).
- [ ] **DNS** — records + zone transfer for domains (`dig`, `subfinder`).
- [ ] **Other** — FTP anon, SNMP, NFS exports, databases, mail.
- [ ] Search versions for known CVEs and public exploits.

## 3. Foothold
- [ ] Pick the most promising vector (default/weak creds, known CVE, upload, injection).
- [ ] Get code exec → reverse shell (`revshell`) → **stabilize the TTY**.
- [ ] Grab the user flag; snapshot the shell context (`id`, hostname, ip).

## 4. Privilege escalation
- [ ] Enumerate (`linpeas`/winPEAS, `sudo -l`/`whoami /priv`) — see the privesc cheatsheets.
- [ ] Confirm the vector before firing; escalate; grab the root/SYSTEM flag.

## 5. Post-exploitation
- [ ] Loot creds, hashes, config, keys; note persistence paths (do not deploy unless in scope).
- [ ] Map lateral movement / pivots if the engagement covers more hosts.

## 6. Report
- [ ] For each finding: severity, evidence (command + output/screenshot), impact, remediation.
- [ ] `vulnscan` already writes `REPORT.md` per target — fold its findings in.

---

## Per-target note template

```
# <target> (<ip>)
Date:        <date>
Scope/creds: <in-scope, provided creds>

## Ports & services
<port/proto  service  version>

## Enumeration notes
-

## Foothold
- vector:
- shell as:  <user>   (user flag: )

## Privilege escalation
- vector:
- shell as:  root/SYSTEM   (root flag: )

## Loot
- creds/hashes/keys:

## Findings (for the report)
- [SEV] title — evidence — impact — fix
```

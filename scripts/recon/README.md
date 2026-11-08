# Recon

Active reconnaissance: these talk **directly to the target** (its ports, its name
servers), so run them only against hosts you are authorized to test. They are portable
fallbacks for when the usual tool (nmap, dnsrecon, dnspython) is not on the box. Pure
Python standard library, single file each.

> ⚠️ Authorized / educational use only.

---

## `portscan.py` - TCP port scanner (no nmap)

**What it does:** finds open TCP ports on a host when nmap is not available (restricted
shells, minimal containers, a freshly landed foothold).

**How it works:** a threaded TCP *connect* scan - it simply tries to open a socket to each
port and records the ones that accept. No raw sockets, so it needs no root. With `--banner`
it reads the first bytes a service sends to guess what it is.

```bash
python3 portscan.py 10.10.10.10                   # common ports
python3 portscan.py 10.10.10.10 -p 1-1024 --banner
```

---

## `dnsrecon.py` - DNS records, zone transfer, subdomain brute

**What it does:** enumerates a domain's DNS: standard records, a zone-transfer (AXFR)
attempt against each name server, and a subdomain brute force.

**How it works:** it speaks the DNS wire protocol itself (builds and parses the packets,
including name compression), so it needs no `dnspython`. Records go out as UDP queries to a
recursive resolver; AXFR opens a TCP connection to each authoritative name server and reads
the whole zone if the server is misconfigured to allow it; `--brute` resolves a built-in (or
your own) list of names in parallel.

```bash
python3 dnsrecon.py example.com                   # records
python3 dnsrecon.py example.com --axfr --brute    # transfer attempt + brute force
```

---

## `webenum.py` - quick web recon

**What it does:** a fast first look at a single web service - what it runs, how it is
configured, and which interesting paths exist.

**How it works:** fetches the target and inspects the response: server/framework banners,
missing security headers, insecure cookie flags, allowed HTTP methods (`OPTIONS`), and
`robots`/`sitemap`. Then it probes a short list of interesting paths (`.git`, `.env`,
`admin`, backups...) with `HEAD` and reports the status codes. Detection only - it never
downloads or exploits anything.

```bash
python3 webenum.py http://10.10.10.10
python3 webenum.py https://target.com -k --paths admin,backup,api/v1
```

---

## `httpprobe.py` - find the live web hosts in a list

**What it does:** takes a pile of hosts (from subdomain enumeration, a scope file or
stdin) and tells you which ones actually serve HTTP/HTTPS, with their status code, page
title and server header - so you know where to point the rest of your tools.

**How it works:** for each host it tries the chosen ports (default `80,443`) over both
schemes in parallel, follows one redirect, and reports what answered. Hosts come from the
command line, `--file`, or a pipe (`crtsh.py ... | httpprobe.py`). `--title` fetches a few
KB to pull the `<title>`; otherwise it only reads headers.

```bash
python3 httpprobe.py example.com www.example.com --title
python3 httpprobe.py --file subs.txt --ports 80,443,8080,8443
python3 osint/crtsh.py example.com | python3 recon/httpprobe.py --title
```

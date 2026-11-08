# OSINT

Passive reconnaissance: everything here gathers information from **public, third-party
sources** and never touches the target's own servers, so it is safe to run before you
have scope to probe directly. Pure Python standard library, single file each.

> ⚠️ Authorized / educational use only.

---

## `crtsh.py` - subdomains from Certificate Transparency

**What it does:** finds subdomains of a domain by reading the public TLS certificate
logs at [crt.sh](https://crt.sh). Every certificate ever issued lists the hostnames it
covers, so the logs are a rich, passive source of subdomains.

**How it works:** queries crt.sh's JSON API for `%.<domain>`, extracts and de-duplicates
every `name_value` / `common_name`, strips wildcards, and keeps only names under the
target domain. With `--live` it then sends a `HEAD` request to each over HTTPS/HTTP (in
parallel) and reports the ones that answer, with their status code.

```bash
python3 crtsh.py example.com                 # list all known subdomains
python3 crtsh.py example.com --live -o subs.txt   # keep only live ones, save them
```

---

## `username-hunt.py` - where a username exists

**What it does:** checks a single handle against ~30 social, developer and gaming sites
and reports where a profile with that name exists.

**How it works:** each site has a URL template plus an explicit detection rule (which HTTP
status means "present", and an optional marker string that cancels soft-404 pages that
answer `200` for everything). It requests each profile URL concurrently and classifies the
result as found / absent / unreachable, so false positives stay low.

```bash
python3 username-hunt.py johndoe                 # check every site
python3 username-hunt.py johndoe --found-only -o hits.txt
```

---

## `footprint.py` - DNS + WHOIS footprint

**What it does:** draws the public picture of a domain: its DNS records and its WHOIS
registration (registrar, creation/expiry dates, name servers).

**How it works:** resolves A/AAAA/MX/NS/TXT/SOA/CNAME through a public **DNS-over-HTTPS**
resolver (Google or Cloudflare) instead of your local resolver, then pulls WHOIS by
connecting to port 43 and following the IANA referral chain down to the registrar's own
server, parsing the fields that matter. Fully passive.

```bash
python3 footprint.py example.com                 # DNS + WHOIS
python3 footprint.py example.com --dns-only --resolver cloudflare
```

---

## `wayback.py` - archived URLs from the Wayback Machine

**What it does:** lists the URLs the Internet Archive has ever captured for a domain -
old endpoints, parameters, forgotten files and paths that no longer appear on the live
site but still exist on the server.

**How it works:** queries the Wayback Machine's **CDX** API for the domain and
de-duplicates the snapshots. `--subdomains` widens it to `*.domain`, `--ext` keeps only
chosen extensions (e.g. `php,bak,sql,env`), `--params` keeps only URLs that carry a query
string (good hunting for IDOR/SQLi), and `--live` sends a `HEAD` to each and keeps the
ones that still answer. Fully passive against the target - all traffic goes to the archive.

```bash
python3 wayback.py example.com                          # every archived URL
python3 wayback.py example.com --ext php,bak,sql,env    # juicy files only
python3 wayback.py example.com --params --live          # live URLs with parameters
```

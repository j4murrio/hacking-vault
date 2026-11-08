# Web application

Active tests against a web application you are authorized to assess - content discovery
and CORS misconfiguration. They talk directly to the target, so keep them inside scope.
Pure Python standard library, single file each.

> ⚠️ Authorized / educational use only.

---

## `dirscan.py` - directory and file discovery

**What it does:** finds hidden paths on a web server - admin panels, backups, config
files, API routes - by requesting a wordlist of names against a base URL and reporting
what exists.

**How it works:** a threaded scanner that requests `base/<word>` for every entry in a
built-in list (or your own `--wordlist`), optionally appending extensions (`--ext
php,txt,bak`). It reports the paths whose status is in `--status` (default covers 200/301/
302/401/403), so you see both open and protected-but-present resources. Detection only -
it never downloads or modifies anything.

```bash
python3 dirscan.py http://target/                      # built-in list
python3 dirscan.py http://target/ -x php,bak,old       # with extensions
python3 dirscan.py https://target/ --wordlist words.txt --status 200,403
```

---

## `cors-check.py` - CORS misconfiguration

**What it does:** checks whether a web endpoint trusts the wrong origins, which can let
an attacker's page read authenticated responses from the target.

**How it works:** it sends requests carrying hostile `Origin` headers (an arbitrary
attacker origin, `null`, a subdomain, a prefix match) and inspects the
`Access-Control-Allow-Origin` / `-Allow-Credentials` reply. It flags **CRITICAL** when an
attacker origin is reflected *with* credentials allowed, and **HIGH** for a reflected or
`null` origin, or a wildcard combined with credentials.

```bash
python3 cors-check.py https://api.target/me            # default checks
python3 cors-check.py https://api.target/me --origin https://evil.example
```

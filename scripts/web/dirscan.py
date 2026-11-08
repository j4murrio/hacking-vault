#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dirscan.py - Threaded web content discovery (directories and files).

A no-dependency stand-in for ffuf/gobuster: request every word in a list against
a base URL and report the paths that exist. Ships with a small built-in list so
it works with no wordlist, and takes a real one (SecLists, etc.) for serious runs.

Talks directly to the target: authorized / educational use only.

Examples:
    python3 dirscan.py http://target/
    python3 dirscan.py http://target/ -w /usr/share/seclists/Discovery/Web-Content/common.txt
    python3 dirscan.py http://target/ -x php,txt,bak --status 200,204,301,302,403
"""

import argparse
import sys
import urllib.error
import urllib.parse
import urllib.request
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "hacking-vault/dirscan (authorized testing)"

# Enough to find the obvious things when no wordlist is supplied.
BUILTIN = """
admin administrator login logout dashboard panel api api/v1 v1 v2
.git .git/config .env .htaccess .htpasswd backup backups old bak
config config.php wp-admin wp-login.php wp-config.php robots.txt sitemap.xml
uploads upload files images img assets static css js test tests dev debug
server-status phpinfo.php info.php db database sql dump.sql user users
console shell cmd private secret secrets tmp temp cache logs log
""".split()


def build_targets(base, words, exts):
    base = base if base.endswith("/") else base + "/"
    paths = []
    for w in words:
        w = w.strip().lstrip("/")
        if not w or w.startswith("#"):
            continue
        paths.append(w)
        for e in exts:
            paths.append(f"{w}.{e.lstrip('.')}")
    # De-duplicate while keeping order.
    seen, out = set(), []
    for pth in paths:
        if pth not in seen:
            seen.add(pth)
            out.append(urllib.parse.urljoin(base, pth))
    return out


def request(url, timeout, insecure):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read()
            return url, resp.status, len(body)
    except urllib.error.HTTPError as e:
        try:
            length = len(e.read())
        except Exception:
            length = 0
        return url, e.code, length
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, ConnectionError, OSError):
        return None


def load_words(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [ln.rstrip("\r\n") for ln in f]


def main():
    p = argparse.ArgumentParser(
        description="Threaded web directory/file discovery.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url", help="base URL, e.g. http://target/")
    p.add_argument("-w", "--wordlist", help="wordlist path (default: built-in)")
    p.add_argument("-x", "--ext", default="",
                   help="extensions to append, comma-separated (e.g. php,txt,bak)")
    p.add_argument("--status", default="200,204,301,302,307,401,403",
                   help="status codes to report (comma-separated)")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--threads", type=int, default=30, help="threads (default 30)")
    p.add_argument("--timeout", type=int, default=8, help="timeout s (default 8)")
    args = p.parse_args()

    if not args.url.lower().startswith(("http://", "https://")):
        args.url = "http://" + args.url
    words = load_words(args.wordlist) if args.wordlist else BUILTIN
    exts = [e for e in args.ext.split(",") if e.strip()]
    try:
        keep = {int(c) for c in args.status.split(",") if c.strip()}
    except ValueError:
        sys.exit("[-] --status must be comma-separated numbers.")

    targets = build_targets(args.url, words, exts)
    hits = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(request, u, args.timeout, args.insecure)
                   for u in targets]
        for fut in as_completed(futures):
            res = fut.result()
            if res and res[1] in keep:
                hits.append(res)

    for url, status, length in sorted(hits, key=lambda x: x[0]):
        print(f"[{status}] {url}  ({length} bytes)")
    print(f"\n[+] {len(hits)} hit(s) out of {len(targets)} request(s).",
          file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except FileNotFoundError as e:
        sys.exit(f"[-] {e}")

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
wayback.py - Pull a domain's archived URLs from the Wayback Machine (CDX API).

Passive recon: the data comes from web.archive.org, never from the target, so it
surfaces old endpoints, parameters and files without touching the host. Useful
for finding forgotten admin panels, API routes and leaked paths.

Authorized / educational use only.

Examples:
    python3 wayback.py example.com
    python3 wayback.py example.com --subdomains
    python3 wayback.py example.com --ext php,bak,sql,env --params
    python3 wayback.py example.com --live   # keep only still-reachable URLs
"""

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

CDX = "http://web.archive.org/cdx/search/cdx"
UA = "hacking-vault/wayback (authorized testing)"


def fetch(domain, subdomains, timeout):
    """Query the CDX API and return the list of unique original URLs."""
    host = f"*.{domain}/*" if subdomains else f"{domain}/*"
    query = {
        "url": host,
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": "50000",
    }
    url = f"{CDX}?{urllib.parse.urlencode(query)}"
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        rows = json.loads(resp.read().decode("utf-8", "replace"))
    # First row is the header (["original"]); skip it.
    return [r[0] for r in rows[1:]] if rows else []


def by_extension(urls, exts):
    exts = tuple("." + e.lower().lstrip(".") for e in exts)
    out = []
    for u in urls:
        path = urllib.parse.urlparse(u).path.lower()
        if path.endswith(exts):
            out.append(u)
    return out


def is_live(url, timeout):
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return url, r.status
    except urllib.error.HTTPError as e:
        return (url, e.code) if e.code < 400 else None
    except Exception:
        return None


def main():
    p = argparse.ArgumentParser(
        description="Archived URLs for a domain from the Wayback Machine.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("domain", help="apex domain, e.g. example.com")
    p.add_argument("--subdomains", action="store_true",
                   help="include *.domain subdomains")
    p.add_argument("--ext", help="keep only these extensions (comma-separated)")
    p.add_argument("--params", action="store_true",
                   help="keep only URLs that carry a query string")
    p.add_argument("--live", action="store_true",
                   help="probe each URL and keep the reachable ones")
    p.add_argument("--threads", type=int, default=20, help="probe threads (default 20)")
    p.add_argument("--timeout", type=int, default=30, help="request timeout s (default 30)")
    args = p.parse_args()

    try:
        urls = fetch(args.domain, args.subdomains, args.timeout)
    except (urllib.error.URLError, ValueError, TimeoutError) as e:
        sys.exit(f"[-] CDX query failed: {e}")

    if args.ext:
        urls = by_extension(urls, args.ext.split(","))
    if args.params:
        urls = [u for u in urls if "?" in u]

    urls = sorted(set(urls))
    if not urls:
        print("[-] No archived URLs matched.")
        return

    if args.live:
        alive = []
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(is_live, u, args.timeout) for u in urls]
            for fut in as_completed(futures):
                hit = fut.result()
                if hit:
                    alive.append(hit)
        for url, status in sorted(alive):
            print(f"[{status}] {url}")
        print(f"\n[+] {len(alive)}/{len(urls)} still reachable.", file=sys.stderr)
    else:
        for u in urls:
            print(u)
        print(f"\n[+] {len(urls)} archived URLs.", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

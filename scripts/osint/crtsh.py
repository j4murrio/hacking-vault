#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
crtsh.py - Passive subdomain enumeration via Certificate Transparency (crt.sh).

Pulls every name that has ever appeared in a public TLS certificate for a domain
from the crt.sh logs. Entirely passive - it never touches the target's own
infrastructure - so it is safe to run before you have scope to probe directly.
Feed the results to httpx / subfinder / dnsrecon for live checks.

Authorized / educational use only.

Examples:
    python3 crtsh.py example.com
    python3 crtsh.py example.com --live -o subs.txt
    python3 crtsh.py example.com --wildcards --timeout 40
"""

import argparse
import json
import socket
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = {"User-Agent": "Mozilla/5.0 (crtsh-osint; authorized recon)"}


def fetch_crtsh(domain, timeout=30, retries=2):
    """Return the raw list of certificate rows crt.sh has for a domain."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    last = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", "replace").strip()
            if not body:
                return []
            # crt.sh sometimes returns concatenated objects instead of an array.
            if body[0] != "[":
                body = "[" + body.replace("}\n{", "},{") + "]"
            return json.loads(body)
        except (urllib.error.URLError, socket.timeout, json.JSONDecodeError) as e:
            last = e
    raise RuntimeError(f"crt.sh query failed: {last}")


def parse_subdomains(rows, domain, keep_wildcards=False):
    """Extract a clean, de-duplicated subdomain set from crt.sh rows."""
    suffix = "." + domain.lower()
    found = set()
    for row in rows:
        names = []
        names += str(row.get("name_value", "")).splitlines()
        names.append(str(row.get("common_name", "")))
        for name in names:
            name = name.strip().lower().rstrip(".")
            if not name:
                continue
            if name.startswith("*.") and not keep_wildcards:
                name = name[2:]
            if name == domain.lower() or name.endswith(suffix):
                found.add(name)
    return found


def probe(host, timeout=4):
    """Return (host, status) if the host answers over HTTPS or HTTP, else None."""
    for scheme, ctx in (("https", ssl._create_unverified_context()), ("http", None)):
        try:
            req = urllib.request.Request(f"{scheme}://{host}/", method="HEAD",
                                         headers=UA)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return host, f"{scheme} {r.getcode()}"
        except urllib.error.HTTPError as e:
            return host, f"{scheme} {e.code}"
        except Exception:
            continue
    return None


def main():
    p = argparse.ArgumentParser(
        description="Passive subdomain enumeration via crt.sh.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("domain", help="apex domain, e.g. example.com")
    p.add_argument("--live", action="store_true",
                   help="probe each subdomain over HTTP/HTTPS and keep the ones that answer")
    p.add_argument("--wildcards", action="store_true",
                   help="keep wildcard entries (*.sub) instead of stripping the star")
    p.add_argument("-o", "--output", help="write the subdomain list to a file")
    p.add_argument("--timeout", type=float, default=30, help="crt.sh timeout s (default 30)")
    p.add_argument("-t", "--threads", type=int, default=40,
                   help="concurrent probes for --live (default 40)")
    args = p.parse_args()

    print(f"[*] Querying crt.sh for *.{args.domain} ...", file=sys.stderr)
    try:
        rows = fetch_crtsh(args.domain, timeout=args.timeout)
    except RuntimeError as e:
        sys.exit(f"[-] {e}")
    subs = sorted(parse_subdomains(rows, args.domain, args.wildcards))
    if not subs:
        sys.exit("[-] No subdomains found in Certificate Transparency logs.")
    print(f"[+] {len(subs)} unique name(s) from {len(rows)} certificate(s)",
          file=sys.stderr)

    results = subs
    if args.live:
        print("[*] Probing which resolve and answer ...", file=sys.stderr)
        live = []
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(probe, h) for h in subs]
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    live.append(res)
        for host, status in sorted(live):
            print(f"  {status:<10} {host}")
        results = [h for h, _ in sorted(live)]
        print(f"[+] {len(results)} live of {len(subs)}", file=sys.stderr)
    else:
        print("\n".join(subs))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write("\n".join(results) + "\n")
        print(f"[+] Wrote {len(results)} host(s) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

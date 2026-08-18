#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webenum.py - Quick single-host web recon with the Python standard library.

Fingerprint headers, security headers, cookie flags, HTTP methods, robots /
sitemap, and probe a short list of interesting paths (detection only - it reports
status codes, it does not download or exploit anything). No third-party deps, so
it runs anywhere Python does. For a deeper audit use vulnscan.

Authorized / educational use only.

Examples:
    python3 webenum.py http://10.10.10.10
    python3 webenum.py https://target.com -k
    python3 webenum.py http://target.com --paths admin,backup,api/v1
"""

import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urlparse

UA = {"User-Agent": "Mozilla/5.0 (webenum; authorized pentest)"}
SECURITY_HEADERS = [
    "Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]
INTERESTING = [
    "robots.txt", "sitemap.xml", ".git/HEAD", ".env", ".htaccess",
    ".svn/entries", "server-status", "admin", "login", "backup",
    "config.php.bak", "phpinfo.php", ".DS_Store", "api", "wp-login.php",
]


def fetch(url, method="GET", timeout=10, ctx=None):
    """Return (status, headers, body, final_url); status is None on transport error."""
    req = urllib.request.Request(url, method=method, headers=UA)
    try:
        r = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return r.getcode(), r.headers, r.read(65536), r.geturl()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, b"", url
    except Exception:
        return None, None, b"", url


def main():
    p = argparse.ArgumentParser(
        description="Quick single-host web recon (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url", help="target URL, e.g. http://host[:port]/")
    p.add_argument("-k", "--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--timeout", type=float, default=10, help="request timeout s")
    p.add_argument("--paths", help="extra comma-separated paths to probe")
    args = p.parse_args()

    url = args.url if "://" in args.url else "http://" + args.url
    ctx = ssl._create_unverified_context() if args.insecure else None

    status, headers, body, final = fetch(url, timeout=args.timeout, ctx=ctx)
    if status is None:
        sys.exit(f"[-] Could not connect to {url}")
    print(f"[*] {url}  ->  {status}  ({final})")

    title = re.search(rb"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if title:
        print(f"[+] Title: {title.group(1).strip().decode('utf-8', 'replace')[:80]}")
    for h in ("Server", "X-Powered-By", "X-AspNet-Version", "Via"):
        if headers.get(h):
            print(f"[+] {h}: {headers.get(h)}")

    missing = [h for h in SECURITY_HEADERS if not headers.get(h)]
    if missing:
        print(f"[!] Missing security headers: {', '.join(missing)}")
    for cookie in headers.get_all("Set-Cookie", []):
        flags = []
        if "secure" not in cookie.lower():
            flags.append("no Secure")
        if "httponly" not in cookie.lower():
            flags.append("no HttpOnly")
        if flags:
            print(f"[!] Cookie {cookie.split('=', 1)[0]}: {', '.join(flags)}")

    _, opt_headers, _, _ = fetch(url, method="OPTIONS", timeout=args.timeout, ctx=ctx)
    allow = opt_headers.get("Allow") if opt_headers else None
    if allow:
        print(f"[+] Allowed methods: {allow}")

    print("[*] Probing interesting paths...")
    base = "{0.scheme}://{0.netloc}".format(urlparse(final or url))
    paths = list(INTERESTING)
    if args.paths:
        paths += [x.strip() for x in args.paths.split(",") if x.strip()]
    for path in paths:
        st, _, _, _ = fetch(f"{base}/{path}", method="HEAD",
                            timeout=args.timeout, ctx=ctx)
        if st and st < 400 or st in (401, 403):
            print(f"    {st}  /{path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

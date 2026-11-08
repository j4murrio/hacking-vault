#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
httpprobe.py - Find the live web servers in a list of hosts.

Feed it hosts (args, a file, or stdin from crtsh/dnsrecon) and it reports which
answer over HTTP/HTTPS, with status, final URL after redirects, page title and
Server header. The fast first pass between enumeration and manual testing.

Talks directly to the targets: authorized / educational use only.

Examples:
    python3 httpprobe.py example.com api.example.com
    python3 crtsh.py example.com | python3 httpprobe.py
    python3 httpprobe.py -f hosts.txt --ports 80,443,8080,8443 --title
"""

import argparse
import re
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

UA = "hacking-vault/httpprobe (authorized testing)"
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def schemes_for(ports):
    """Map each port to the scheme(s) to try. Returns (scheme, port) pairs."""
    default = {80: ["http"], 443: ["https"], 8080: ["http"],
               8443: ["https"], 8000: ["http"], 8888: ["http"]}
    pairs = []
    for port in ports:
        for scheme in default.get(port, ["http", "https"]):
            pairs.append((scheme, port))
    return pairs


def probe(host, scheme, port, timeout, want_title, insecure):
    """Request one host:port. Returns a result dict, or None if it did not answer."""
    netloc = host if ((scheme == "http" and port == 80) or
                      (scheme == "https" and port == 443)) else f"{host}:{port}"
    url = f"{scheme}://{netloc}/"
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = resp.status
            final = resp.geturl()
            server = resp.headers.get("Server", "")
            body = resp.read(4096) if want_title else b""
    except urllib.error.HTTPError as e:
        status, final, server, body = e.code, url, e.headers.get("Server", ""), b""
    except (urllib.error.URLError, ssl.SSLError, TimeoutError, ConnectionError, OSError):
        return None
    title = ""
    if want_title:
        m = TITLE_RE.search(body)
        if m:
            title = m.group(1).decode("utf-8", "replace").strip()
            title = re.sub(r"\s+", " ", title)[:80]
    return {"url": url, "status": status, "final": final,
            "server": server, "title": title}


def read_hosts(args):
    hosts = list(args.hosts)
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            hosts += [ln.strip() for ln in f]
    if not hosts and not sys.stdin.isatty():
        hosts += [ln.strip() for ln in sys.stdin]
    # Strip any scheme/path the input carried; keep the bare host.
    clean = []
    for h in hosts:
        h = h.strip()
        if not h:
            continue
        h = re.sub(r"^\w+://", "", h).split("/")[0]
        clean.append(h)
    return sorted(set(clean))


def main():
    p = argparse.ArgumentParser(
        description="Probe a host list for live HTTP/HTTPS servers.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("hosts", nargs="*", help="hosts (or pipe them / use -f)")
    p.add_argument("-f", "--file", help="file with one host per line")
    p.add_argument("--ports", default="80,443",
                   help="comma-separated ports (default 80,443)")
    p.add_argument("--title", action="store_true", help="fetch and show page title")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--threads", type=int, default=40, help="threads (default 40)")
    p.add_argument("--timeout", type=int, default=8, help="timeout s (default 8)")
    args = p.parse_args()

    hosts = read_hosts(args)
    if not hosts:
        sys.exit("[-] No hosts given. Pass them as args, with -f, or on stdin.")
    try:
        ports = [int(x) for x in args.ports.split(",") if x.strip()]
    except ValueError:
        sys.exit("[-] --ports must be a comma-separated list of numbers.")

    jobs = [(h, s, pt) for h in hosts for s, pt in schemes_for(ports)]
    live = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {pool.submit(probe, h, s, pt, args.timeout, args.title,
                               args.insecure): (h, s, pt) for h, s, pt in jobs}
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                live.append(res)

    for r in sorted(live, key=lambda x: x["url"]):
        extra = f'  "{r["title"]}"' if r["title"] else ""
        srv = f'  [{r["server"]}]' if r["server"] else ""
        redir = f'  -> {r["final"]}' if r["final"].rstrip("/") != r["url"].rstrip("/") else ""
        print(f'[{r["status"]}] {r["url"]}{srv}{redir}{extra}')
    print(f"\n[+] {len(live)} live endpoint(s) across {len(hosts)} host(s).",
          file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

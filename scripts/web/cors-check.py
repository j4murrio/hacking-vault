#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cors-check.py - Spot permissive and broken CORS configurations.

Sends an Origin header the server should refuse and reads back the
Access-Control-Allow-Origin / -Credentials headers. It flags the classic wins:
a reflected arbitrary Origin, a wildcard, Origin + credentials, null accepted,
and weak suffix/prefix matching an attacker domain can satisfy.

Authorized / educational use only.

Examples:
    python3 cors-check.py https://api.target.com/
    python3 cors-check.py https://api.target.com/ --origin https://evil.example
"""

import argparse
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "hacking-vault/cors-check (authorized testing)"


def request(url, origin, timeout, insecure):
    """Send one request with the given Origin; return the relevant ACAO/ACAC headers."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Origin": origin})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = resp.headers
            status = resp.status
    except urllib.error.HTTPError as e:
        headers, status = e.headers, e.code
    return {
        "status": status,
        "acao": headers.get("Access-Control-Allow-Origin"),
        "acac": headers.get("Access-Control-Allow-Credentials"),
    }


def analyze(url, probe_origin):
    host = urllib.parse.urlparse(url).netloc
    evil = probe_origin or "https://evil.example"
    checks = [
        ("arbitrary origin reflected", evil),
        ("null origin", "null"),
        ("subdomain of attacker", f"https://{host}.evil.example"),
        ("attacker domain with target as prefix", f"https://{host}evil.example"),
    ]
    return host, checks


def main():
    p = argparse.ArgumentParser(
        description="Detect permissive / misconfigured CORS.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("url", help="endpoint URL, e.g. https://api.target/")
    p.add_argument("--origin", help="attacker origin to test (default https://evil.example)")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--timeout", type=int, default=10, help="timeout s (default 10)")
    args = p.parse_args()

    if not args.url.lower().startswith(("http://", "https://")):
        sys.exit("[-] URL must start with http:// or https://")

    host, checks = analyze(args.url, args.origin)
    findings = []
    print(f"[*] CORS probe of {args.url}\n")
    for label, origin in checks:
        try:
            res = request(args.url, origin, args.timeout, args.insecure)
        except (urllib.error.URLError, ssl.SSLError, TimeoutError, OSError) as e:
            print(f"  {label:<40} request failed: {e}")
            continue
        acao, acac = res["acao"], res["acac"]
        creds = (acac or "").lower() == "true"
        reflected = acao == origin
        wildcard = acao == "*"
        line = f"  {label:<40} ACAO={acao!r} ACAC={acac!r}"
        if reflected and creds:
            findings.append(f"CRITICAL: Origin {origin} reflected WITH credentials "
                            f"-> full cross-origin read.")
            line += "   <-- CRITICAL"
        elif reflected:
            findings.append(f"HIGH: arbitrary Origin {origin} reflected.")
            line += "   <-- reflected"
        elif wildcard and creds:
            findings.append("HIGH: wildcard ACAO together with credentials (browsers "
                            "block it, but the config is wrong).")
            line += "   <-- wildcard+creds"
        elif acao == "null":
            findings.append("HIGH: 'null' origin accepted -> reachable from a "
                            "sandboxed iframe.")
            line += "   <-- null accepted"
        print(line)

    print()
    if findings:
        print("[!] Findings:")
        for f in findings:
            print(f"  - {f}")
    else:
        print("[+] No obvious CORS misconfiguration on this endpoint.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

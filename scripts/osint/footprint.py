#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
footprint.py - Passive DNS + WHOIS footprint of a domain.

Resolves the common record types through public DNS-over-HTTPS resolvers and
pulls the WHOIS registration (registrar, key dates, name servers) by following
the IANA referral chain. Nothing is sent to the target's own servers, so this is
safe to run from the earliest, no-scope stage of an engagement.

Authorized / educational use only.

Examples:
    python3 footprint.py example.com
    python3 footprint.py example.com --dns-only
    python3 footprint.py example.com --resolver cloudflare
"""

import argparse
import json
import re
import socket
import sys
import urllib.parse
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (footprint-osint; authorized recon)"}
RESOLVERS = {
    "google": "https://dns.google/resolve",
    "cloudflare": "https://cloudflare-dns.com/dns-query",
}
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
WHOIS_FIELDS = [
    ("Registrar", r"Registrar:\s*(.+)"),
    ("Created", r"Cre(?:ation Date|ated)(?: On)?:\s*(.+)"),
    ("Updated", r"Updated Date:\s*(.+)"),
    ("Expires", r"(?:Registry Expiry Date|Expir\w+ Date):\s*(.+)"),
    ("Status", r"(?:Domain Status|Status):\s*(.+)"),
    ("Name Server", r"Name Server:\s*(.+)"),
    ("DNSSEC", r"DNSSEC:\s*(.+)"),
]


def doh(name, rtype, resolver="google", timeout=10):
    """Resolve one record type via DNS-over-HTTPS. Returns a list of strings."""
    base = RESOLVERS[resolver]
    url = f"{base}?name={urllib.parse.quote(name)}&type={rtype}"
    req = urllib.request.Request(url, headers={**UA, "Accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = json.loads(r.read().decode("utf-8", "replace"))
    out = []
    for ans in data.get("Answer", []):
        val = ans.get("data", "").strip()
        if val:
            out.append(val.rstrip("."))
    return out


def whois_query(server, query, timeout=15):
    """Send a WHOIS query to a server on port 43 and return the raw response."""
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def whois_lookup(domain, timeout=15):
    """Follow the IANA referral chain to the authoritative WHOIS and return it."""
    text = whois_query("whois.iana.org", domain, timeout)
    for _ in range(3):
        m = re.search(r"(?:refer|whois):\s*(\S+)", text, re.I)
        if not m:
            break
        referral = m.group(1).strip()
        try:
            deeper = whois_query(referral, domain, timeout)
        except OSError:
            break
        if "Registrar WHOIS Server" in deeper or "Registrar:" in deeper:
            # one more hop to the registrar's own server, if advertised
            rm = re.search(r"Registrar WHOIS Server:\s*(\S+)", deeper, re.I)
            text = deeper
            if rm:
                try:
                    text = whois_query(rm.group(1).strip(), domain, timeout)
                except OSError:
                    pass
            break
        text = deeper
    return text


def parse_whois(text):
    """Pull the fields that matter into an ordered {label: [values]} dict."""
    out = {}
    for label, pat in WHOIS_FIELDS:
        vals = []
        for m in re.finditer(pat, text, re.I):
            v = m.group(1).strip()
            if v and v not in vals:
                vals.append(v)
        if vals:
            out[label] = vals
    return out


def main():
    p = argparse.ArgumentParser(
        description="Passive DNS + WHOIS footprint of a domain.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("domain", help="domain to profile, e.g. example.com")
    p.add_argument("--dns-only", action="store_true", help="skip the WHOIS lookup")
    p.add_argument("--whois-only", action="store_true", help="skip the DNS records")
    p.add_argument("--resolver", choices=list(RESOLVERS), default="google",
                   help="DoH resolver (default google)")
    p.add_argument("--timeout", type=float, default=10, help="per-query timeout s")
    args = p.parse_args()

    if not args.whois_only:
        print(f"[*] DNS records for {args.domain} (via {args.resolver} DoH)")
        a_records = []
        for rtype in RECORD_TYPES:
            try:
                vals = doh(args.domain, rtype, args.resolver, args.timeout)
            except Exception as e:
                print(f"    {rtype:<6} [error: {type(e).__name__}]")
                continue
            if rtype in ("A", "AAAA"):
                a_records += vals
            for v in vals:
                print(f"    {rtype:<6} {v}")
        for ip in a_records:
            try:
                host = socket.gethostbyaddr(ip)[0]
                print(f"    PTR    {ip} -> {host}")
            except OSError:
                pass

    if not args.dns_only:
        print(f"\n[*] WHOIS for {args.domain}")
        try:
            raw = whois_lookup(args.domain, args.timeout)
        except OSError as e:
            sys.exit(f"[-] WHOIS failed: {e}")
        fields = parse_whois(raw)
        if not fields:
            print("    [-] No structured fields parsed (TLD may use a thin/opaque WHOIS).")
        for label, vals in fields.items():
            for v in vals:
                print(f"    {label:<13} {v}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

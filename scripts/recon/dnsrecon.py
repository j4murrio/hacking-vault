#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnsrecon.py - Active DNS reconnaissance with a self-contained DNS client.

Resolves the common record types, attempts a zone transfer (AXFR) against each
authoritative name server, and brute-forces subdomains from a built-in list.
Implements just enough of the DNS wire format to need no third-party module
(no dnspython). Unlike the passive osint/footprint.py it talks to the zone's own
name servers, so run it only against domains you are authorized to test.

Authorized / educational use only.

Examples:
    python3 dnsrecon.py example.com
    python3 dnsrecon.py example.com --axfr
    python3 dnsrecon.py example.com --brute -w subs.txt --resolver 1.1.1.1
"""

import argparse
import random
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15,
          "TXT": 16, "AAAA": 28, "AXFR": 252}
QTYPE_NAME = {v: k for k, v in QTYPES.items()}

BUILTIN_SUBS = (
    "www mail ftp localhost webmail smtp pop pop3 imap ns1 ns2 ns3 dns dns1 dns2 "
    "mx mx1 vpn remote server admin portal api dev staging stage test testing qa "
    "uat prod beta demo app apps mobile m web web1 web2 cpanel whm autodiscover "
    "autoconfig cloud git gitlab jenkins ci build docker registry proxy gw gateway "
    "router firewall fw db sql mysql postgres oracle mssql backup bak old new intranet "
    "extranet internal external secure ssl login auth sso ldap ad dc exchange owa "
    "lync sip voip pbx monitor nagios zabbix grafana kibana elastic jira confluence "
    "wiki support help status blog shop store cdn static assets img images media files "
    "download upload share drive nextcloud owncloud s3 ns dev-api stg"
).split()


def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        if label:
            out += bytes([len(label)]) + label.encode("idna" if any(ord(c) > 127 for c in label) else "ascii")
    return out + b"\x00"


def build_query(qname, qtype, qid=None, recursion=True):
    qid = qid if qid is not None else random.randint(0, 0xFFFF)
    flags = 0x0100 if recursion else 0x0000
    header = struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0)
    question = encode_name(qname) + struct.pack(">HH", qtype, 1)
    return qid, header + question


def read_name(data, offset):
    """Decode a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels = []
    jumped_to = None
    pos = offset
    while True:
        length = data[pos]
        if length & 0xC0 == 0xC0:  # pointer
            pointer = struct.unpack(">H", data[pos:pos + 2])[0] & 0x3FFF
            if jumped_to is None:
                jumped_to = pos + 2
            pos = pointer
            continue
        pos += 1
        if length == 0:
            break
        labels.append(data[pos:pos + length].decode("ascii", "replace"))
        pos += length
    return ".".join(labels), (jumped_to if jumped_to is not None else pos)


def parse_rdata(rtype, data, offset, rdlength):
    end = offset + rdlength
    if rtype == 1:
        return socket.inet_ntoa(data[offset:end])
    if rtype == 28:
        return socket.inet_ntop(socket.AF_INET6, data[offset:end])
    if rtype in (2, 5, 12):  # NS, CNAME, PTR
        return read_name(data, offset)[0]
    if rtype == 15:  # MX
        pref = struct.unpack(">H", data[offset:offset + 2])[0]
        return f"{pref} {read_name(data, offset + 2)[0]}"
    if rtype == 16:  # TXT
        out, pos = [], offset
        while pos < end:
            n = data[pos]
            out.append(data[pos + 1:pos + 1 + n].decode("utf-8", "replace"))
            pos += 1 + n
        return '"' + "".join(out) + '"'
    if rtype == 6:  # SOA
        mname, pos = read_name(data, offset)
        rname, pos = read_name(data, pos)
        serial = struct.unpack(">I", data[pos:pos + 4])[0]
        return f"{mname} {rname} {serial}"
    return data[offset:end].hex()


def parse_records(data):
    """Parse all answer/authority records from one DNS message."""
    qid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    pos = 12
    for _ in range(qd):
        _, pos = read_name(data, pos)
        pos += 4
    records = []
    for _ in range(an + ns + ar):
        name, pos = read_name(data, pos)
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        value = parse_rdata(rtype, data, pos, rdlength)
        records.append((name, QTYPE_NAME.get(rtype, str(rtype)), value))
        pos += rdlength
    return records


def query_udp(server, qname, qtype, timeout=5):
    qid, packet = build_query(qname, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, 53))
        resp, _ = s.recvfrom(4096)
    if (resp[2] & 0x02):  # truncated -> retry over TCP
        return query_tcp(server, qname, qtype, timeout)
    return parse_records(resp)


def query_tcp(server, qname, qtype, timeout=5):
    qid, packet = build_query(qname, qtype, recursion=(qtype != QTYPES["AXFR"]))
    with socket.create_connection((server, 53), timeout=timeout) as s:
        s.sendall(struct.pack(">H", len(packet)) + packet)
        messages = _read_tcp_messages(s, single=(qtype != QTYPES["AXFR"]))
    records = []
    for msg in messages:
        records += parse_records(msg)
    return records


def _read_tcp_messages(sock, single=False):
    """Read one or more length-prefixed DNS messages from a TCP stream."""
    buf = b""
    messages = []
    while True:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while len(buf) >= 2:
            mlen = struct.unpack(">H", buf[:2])[0]
            if len(buf) < 2 + mlen:
                break
            messages.append(buf[2:2 + mlen])
            buf = buf[2 + mlen:]
        if single and messages:
            break
    return messages


def axfr(server, zone, timeout=10):
    """Attempt a full zone transfer. Returns the record list, or [] if refused."""
    try:
        return query_tcp(server, zone, QTYPES["AXFR"], timeout)
    except OSError:
        return []


def resolve_ns_ips(domain, resolver, timeout):
    ips = []
    for _, _, ns in query_udp(resolver, domain, QTYPES["NS"], timeout):
        try:
            ips.append((ns, socket.gethostbyname(ns)))
        except OSError:
            pass
    return ips


def main():
    p = argparse.ArgumentParser(
        description="Active DNS reconnaissance (self-contained DNS client).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("domain", help="target domain, e.g. example.com")
    p.add_argument("--resolver", default="8.8.8.8", help="recursive resolver (default 8.8.8.8)")
    p.add_argument("--axfr", action="store_true", help="attempt AXFR against each name server")
    p.add_argument("--brute", action="store_true", help="brute-force subdomains")
    p.add_argument("-w", "--wordlist", help="subdomain wordlist (one per line) for --brute")
    p.add_argument("-t", "--threads", type=int, default=50, help="brute concurrency (default 50)")
    p.add_argument("--timeout", type=float, default=5, help="per-query timeout s")
    args = p.parse_args()

    print(f"[*] DNS records for {args.domain} (resolver {args.resolver})")
    for rt in ("A", "AAAA", "NS", "MX", "TXT", "SOA", "CNAME"):
        try:
            for name, rtype, value in query_udp(args.resolver, args.domain, QTYPES[rt], args.timeout):
                print(f"    {rtype:<6} {value}")
        except OSError as e:
            print(f"    {rt:<6} [error: {e}]")

    if args.axfr:
        print(f"\n[*] Attempting zone transfer (AXFR)")
        ns_ips = resolve_ns_ips(args.domain, args.resolver, args.timeout)
        if not ns_ips:
            print("    [-] No name servers resolved.")
        for ns, ip in ns_ips:
            records = axfr(ip, args.domain, max(args.timeout, 10))
            if records:
                print(f"    [+] AXFR ALLOWED by {ns} ({ip}) - {len(records)} records:")
                for name, rtype, value in records:
                    print(f"        {name:<30} {rtype:<6} {value}")
            else:
                print(f"    [-] {ns} ({ip}) refused the transfer")

    if args.brute:
        subs = BUILTIN_SUBS
        if args.wordlist:
            with open(args.wordlist, encoding="utf-8", errors="replace") as f:
                subs = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        print(f"\n[*] Brute-forcing {len(subs)} subdomains")
        hits = 0

        def resolve(sub):
            host = f"{sub}.{args.domain}"
            recs = []
            try:
                recs = [v for _, rt, v in query_udp(args.resolver, host, QTYPES["A"], args.timeout)
                        if rt == "A"]
            except OSError:
                pass
            return host, recs

        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = [pool.submit(resolve, s) for s in subs]
            for fut in as_completed(futures):
                host, recs = fut.result()
                if recs:
                    hits += 1
                    print(f"    [+] {host:<34} {', '.join(recs)}")
        print(f"[+] {hits} subdomain(s) resolved")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

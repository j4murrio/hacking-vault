#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
portscan.py - Threaded TCP connect scanner (stdlib only, no root needed).

A portable fallback for when nmap is not on the box (restricted shells, minimal
containers, CTF foothold). For a full audit use nmap / vulnscan instead.

Authorized / educational use only: scan hosts you own or are permitted to test.

Examples:
    python3 portscan.py 10.10.10.10                 # common ports
    python3 portscan.py 10.10.10.10 -p 1-1024 --banner
    python3 portscan.py target.com -p 22,80,443,8080 -t 400
    python3 portscan.py 10.10.10.10 -p -             # all 65535 (slow)
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# A compact "most common services" set for the default scan.
TOP_PORTS = sorted({
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 389, 443, 445, 465,
    587, 631, 636, 993, 995, 1025, 1433, 1521, 1723, 2049, 2121, 3128, 3306,
    3389, 5000, 5432, 5601, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8443,
    8888, 9000, 9200, 9443, 10000, 11211, 27017,
})


def parse_ports(spec):
    if spec in ("-", "all"):
        return range(1, 65536)
    if not spec or spec == "top":
        return TOP_PORTS
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def clean_host(target):
    """Pull a bare hostname/IP out of something pasted as a URL or host:port."""
    host = target.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.count(":") == 1:  # host:port, but leave IPv6 literals alone
        name, port = host.split(":")
        if port.isdigit():
            host = name
    return host


def service(port):
    try:
        return socket.getservbyport(port)
    except OSError:
        return "?"


def scan_port(host, port, timeout, grab):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            return None
        banner = ""
        if grab:
            try:
                s.settimeout(min(timeout, 1.5))
                banner = s.recv(128).decode("latin-1", "replace").strip()
            except OSError:
                pass
    return port, banner


def main():
    p = argparse.ArgumentParser(
        description="Threaded TCP connect scanner (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("target", help="hostname or IP")
    p.add_argument("-p", "--ports", help="e.g. 1-1024, 22,80,443, 'top', '-' (all)")
    p.add_argument("-t", "--threads", type=int, default=200, help="threads (default 200)")
    p.add_argument("--timeout", type=float, default=0.5, help="connect timeout s (default 0.5)")
    p.add_argument("--banner", action="store_true", help="grab a short service banner")
    args = p.parse_args()

    host = clean_host(args.target)
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        sys.exit(f"[-] Cannot resolve {host}")
    ports = list(parse_ports(args.ports))
    print(f"[*] Scanning {host} ({ip}) - {len(ports)} ports, "
          f"{args.threads} threads")

    open_ports = []
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(scan_port, ip, port, args.timeout, args.banner)
                   for port in ports]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)

    if not open_ports:
        print("[-] No open ports found.")
        return
    print(f"\n[+] {len(open_ports)} open port(s):")
    for port, banner in sorted(open_ports):
        tail = f"  {banner[:60]}" if banner else ""
        print(f"    {port:>5}/tcp  {service(port):<12}{tail}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

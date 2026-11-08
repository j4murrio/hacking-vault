#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fileinspect.py - First-look triage for a file in a forensics/CTF challenge.

Identifies the type from magic bytes, pulls printable strings (with flag
highlighting), measures Shannon entropy to tell plaintext from
compressed/encrypted data, and scans for embedded file signatures (a ZIP, PNG or
PDF hiding past the end of the host file - the usual stego trick).

Authorized / educational use only.

Examples:
    python3 fileinspect.py challenge.jpg
    python3 fileinspect.py blob.bin --strings --min 6
    python3 fileinspect.py suspicious.png --flag 'CTF\\{.*?\\}'
"""

import argparse
import math
import re
import sys
from collections import Counter

# Leading magic bytes -> human label. Checked longest-first.
MAGIC = [
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "DOS/PE executable"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"BM", "BMP image"),
    (b"%PDF", "PDF document"),
    (b"PK\x03\x04", "ZIP archive (or docx/jar/apk)"),
    (b"PK\x05\x06", "ZIP archive (empty)"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b", "gzip stream"),
    (b"BZh", "bzip2 stream"),
    (b"\xfd7zXZ\x00", "xz stream"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"OggS", "Ogg media"),
    (b"ID3", "MP3 (ID3)"),
    (b"\x25\x21PS", "PostScript"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\xca\xfe\xba\xbe", "Java class / Mach-O fat"),
]

# Signatures worth finding *inside* a file (embedded / appended data).
EMBEDDED = [
    (b"PK\x03\x04", "ZIP archive"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"%PDF", "PDF document"),
    (b"GIF89a", "GIF image"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\x1f\x8b\x08", "gzip stream"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
]


def identify(head):
    for sig, label in MAGIC:
        if head.startswith(sig):
            return label
    return "unknown / raw data"


def entropy(data):
    """Shannon entropy in bits per byte (0 = uniform, ~8 = random/compressed)."""
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def extract_strings(data, minlen):
    """Yield runs of printable ASCII at least minlen long, with their offset."""
    cur, start = bytearray(), 0
    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not cur:
                start = i
            cur.append(b)
        else:
            if len(cur) >= minlen:
                yield start, cur.decode("ascii")
            cur = bytearray()
    if len(cur) >= minlen:
        yield start, cur.decode("ascii")


def find_embedded(data):
    """Report signatures that appear after offset 0 (appended/hidden content)."""
    hits = []
    for sig, label in EMBEDDED:
        start = data.find(sig, 1)
        while start != -1:
            hits.append((start, label))
            start = data.find(sig, start + 1)
    return sorted(hits)


def main():
    p = argparse.ArgumentParser(
        description="Triage a file: type, strings, entropy, embedded data.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("file", help="file to inspect")
    p.add_argument("--strings", action="store_true", help="dump printable strings")
    p.add_argument("--min", type=int, default=4, help="min string length (default 4)")
    p.add_argument("--flag", default=r"[A-Za-z0-9_]+\{[^}]{1,100}\}",
                   help="regex to highlight flag-like strings")
    args = p.parse_args()

    try:
        with open(args.file, "rb") as f:
            data = f.read()
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        sys.exit(f"[-] {e}")

    flag_re = re.compile(args.flag)

    print(f"[*] {args.file}")
    print(f"    size     {len(data)} bytes")
    print(f"    type     {identify(data[:32])}")
    ent = entropy(data)
    note = ("high - likely compressed/encrypted" if ent > 7.3
            else "low - likely text/structured" if ent < 5.0 else "mixed")
    print(f"    entropy  {ent:.2f} bits/byte ({note})")

    embedded = find_embedded(data)
    if embedded:
        print("\n[!] Embedded/appended signatures (possible hidden data):")
        for off, label in embedded:
            print(f"    @ 0x{off:08x} ({off})  {label}")

    all_strings = list(extract_strings(data, args.min))
    flags = [(off, s) for off, s in all_strings if flag_re.search(s)]
    if flags:
        print("\n[+] Flag-like strings:")
        for off, s in flags:
            for m in flag_re.findall(s):
                print(f"    @ 0x{off:08x}  {m}")

    if args.strings:
        print(f"\n[*] Strings (min {args.min}):")
        for off, s in all_strings:
            print(f"    @ 0x{off:08x}  {s}")
    elif not flags and not embedded:
        print(f"\n    ({len(all_strings)} strings >= {args.min} chars; "
              f"use --strings to list them)")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

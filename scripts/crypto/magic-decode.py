#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
magic-decode.py - Recursive multi-encoding decoder for CTF blobs.

Peels layered encodings (base64/32/85, hex, URL, ROT13, binary, decimal, morse,
gzip/zlib/bz2) until it reaches readable text or a flag. Inspired by CyberChef's
"Magic".

Authorized / educational use only.

Examples:
    python3 magic-decode.py "NzM2NTYzNzI2NTc0"        # auto (magic mode)
    echo "<blob>" | python3 magic-decode.py -          # from stdin
    python3 magic-decode.py -f data.txt --all          # one layer, every codec
    python3 magic-decode.py "<blob>" --flag 'HTB\\{.*\\}'
"""

import argparse
import base64
import binascii
import bz2
import codecs
import gzip
import re
import sys
import zlib
from collections import deque
from urllib.parse import unquote_to_bytes

PRINTABLE = set(range(32, 127)) | {9, 10, 13}
DEFAULT_FLAG = r"[A-Za-z0-9_]{2,}\{[^{}]{1,120}\}"


def printable_ratio(data):
    if not data:
        return 0.0
    return sum(1 for b in data if b in PRINTABLE) / len(data)


def preview(data, limit=120):
    text = data.decode("utf-8", "backslashreplace")
    text = text.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return text[:limit] + ("…" if len(text) > limit else "")


# ============================================================================
# Single-layer decoders — each returns bytes, or None if it does not apply
# ============================================================================
def _b64(d):
    s = re.sub(rb"\s", b"", d.strip())
    if len(s) < 4 or re.fullmatch(rb"[A-Za-z0-9+/=]+", s) is None:
        return None
    try:
        return base64.b64decode(s + b"=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def _b64url(d):
    s = re.sub(rb"\s", b"", d.strip())
    if len(s) < 4 or re.fullmatch(rb"[A-Za-z0-9\-_=]+", s) is None:
        return None
    if b"-" not in s and b"_" not in s:
        return None  # identical to standard base64 otherwise
    try:
        return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))
    except (binascii.Error, ValueError):
        return None


def _b32(d):
    s = re.sub(rb"\s", b"", d.strip()).upper()
    if len(s) < 8 or re.fullmatch(rb"[A-Z2-7=]+", s) is None:
        return None
    try:
        return base64.b32decode(s + b"=" * (-len(s) % 8))
    except (binascii.Error, ValueError):
        return None


def _b85(d):
    try:
        return base64.b85decode(re.sub(rb"\s", b"", d.strip()))
    except ValueError:
        return None


def _a85(d):
    try:
        return base64.a85decode(d.strip())
    except ValueError:
        return None


def _hex(d):
    s = re.sub(rb"[\s:]", b"", d.strip())
    if not s or len(s) % 2 or re.fullmatch(rb"[0-9A-Fa-f]+", s) is None:
        return None
    try:
        return bytes.fromhex(s.decode("ascii"))
    except ValueError:
        return None


def _url(d):
    if b"%" not in d:
        return None
    out = unquote_to_bytes(d)
    return out if out != d else None


def _rot13(d):
    try:
        return codecs.encode(d.decode("ascii"), "rot13").encode("ascii")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None


def _rot47(d):
    return bytes(33 + (b - 33 + 47) % 94 if 33 <= b <= 126 else b for b in d)


def _binary(d):
    s = re.sub(rb"\s", b"", d.strip())
    if not s or len(s) % 8 or re.fullmatch(rb"[01]+", s) is None:
        return None
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def _decimal(d):
    toks = d.split()
    if len(toks) < 2 or not all(re.fullmatch(rb"\d{1,3}", t) for t in toks):
        return None
    vals = [int(t) for t in toks]
    return bytes(vals) if all(v <= 255 for v in vals) else None


def _gzip(d):
    if not d.startswith(b"\x1f\x8b"):
        return None
    try:
        return gzip.decompress(d)
    except (OSError, EOFError, zlib.error):
        return None


def _zlib(d):
    if d[:1] != b"\x78":
        return None
    try:
        return zlib.decompress(d)
    except zlib.error:
        return None


def _bz2(d):
    if not d.startswith(b"BZh"):
        return None
    try:
        return bz2.decompress(d)
    except (OSError, ValueError):
        return None


MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9",
}


def _morse(d):
    s = d.decode("ascii", "ignore").strip()
    if not s or set(s) - set(".-/ \n\t"):
        return None
    words = re.split(r"\s*/\s*|\s{3,}", s)
    out = []
    for word in words:
        letters = [MORSE.get(sym, "?") for sym in word.split() if sym]
        if letters:
            out.append("".join(letters))
    text = " ".join(out)
    return text.encode() if text and "?" not in text else None


def _reverse(d):
    return d[::-1]


# Codecs used while auto-peeling. Order matters only for tie-breaking output.
MAGIC_DECODERS = [
    ("base64", _b64), ("base64url", _b64url), ("base32", _b32),
    ("base85", _b85), ("ascii85", _a85), ("hex", _hex), ("url", _url),
    ("rot13", _rot13), ("binary", _binary), ("decimal", _decimal),
    ("gzip", _gzip), ("zlib", _zlib), ("bz2", _bz2), ("morse", _morse),
]
# Extra transforms too noisy to auto-chain, offered only in --all mode.
ALL_DECODERS = MAGIC_DECODERS + [("rot47", _rot47), ("reverse", _reverse)]

COMPRESSED = {"gzip", "zlib", "bz2"}


def magic(data, flag_re, max_depth=8, max_nodes=800):
    """Breadth-first peel; stop on a flag match, else return the most readable."""
    seen = {data}
    queue = deque([(data, [], 0)])
    best = None  # (printable_ratio, bytes, chain)
    nodes = 0
    while queue and nodes < max_nodes:
        cur, chain, depth = queue.popleft()
        if depth >= max_depth:
            continue
        for name, fn in MAGIC_DECODERS:
            try:
                res = fn(cur)
            except Exception:
                res = None
            if not res or res == cur or res in seen:
                continue
            nodes += 1
            seen.add(res)
            new_chain = chain + [name]
            if flag_re.search(res):
                return new_chain, res, True
            pr = printable_ratio(res)
            if best is None or pr > best[0]:
                best = (pr, res, new_chain)
            if pr >= 0.85 or name in COMPRESSED:
                queue.append((res, new_chain, depth + 1))
            if nodes >= max_nodes:
                break
    if best and best[0] >= 0.85:
        return best[2], best[1], False
    return None, None, False


def run_all(data, flag_re):
    """Apply every codec once and print whichever produce plausible output."""
    hits = 0
    for name, fn in ALL_DECODERS:
        try:
            res = fn(data)
        except Exception:
            res = None
        if not res or res == data:
            continue
        flag = " [FLAG]" if flag_re.search(res) else ""
        print(f"[+] {name:<10} ({printable_ratio(res):.0%} printable){flag}")
        print(f"      {preview(res)}")
        hits += 1
    if not hits:
        print("[-] No decoder produced different output. Is the input raw text?")


def read_input(args):
    if args.file:
        with open(args.file, "rb") as f:
            return f.read()
    if args.data in (None, "-"):
        return sys.stdin.buffer.read()
    return args.data.encode()


def main():
    p = argparse.ArgumentParser(
        description="Recursive multi-encoding decoder for CTF blobs.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[1] if "Examples:" in __doc__ else None,
    )
    p.add_argument("data", nargs="?", help="data to decode ('-' or omit for stdin)")
    p.add_argument("-f", "--file", help="read data from a file (binary safe)")
    p.add_argument("--all", action="store_true",
                   help="apply every codec once (single layer) instead of peeling")
    p.add_argument("--flag", default=DEFAULT_FLAG,
                   help="regex marking a successful decode (default: name{...})")
    p.add_argument("--max-depth", type=int, default=8,
                   help="maximum layers to peel in magic mode (default: 8)")
    args = p.parse_args()

    raw = read_input(args)
    if not raw.strip():
        p.error("empty input")
    flag_re = re.compile(args.flag.encode(), re.IGNORECASE)

    if args.all:
        run_all(raw.strip(), flag_re)
        return

    chain, result, is_flag = magic(raw.strip(), flag_re, max_depth=args.max_depth)
    if result is None:
        print("[-] Could not peel to readable text. Try --all to inspect layers.")
        sys.exit(1)
    arrow = " -> ".join(chain) if chain else "(none)"
    tag = "FLAG" if is_flag else "readable"
    print(f"[+] {tag} via: {arrow}")
    print(result.decode("utf-8", "backslashreplace"))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

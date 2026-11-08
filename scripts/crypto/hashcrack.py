#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashcrack.py - Dictionary attack against raw hashes (stdlib only).

The companion to hashid: once a hash is identified, throw a wordlist at it.
Covers the common unsalted schemes hashlib can compute - MD5, SHA1/224/256/384/
512, SHA3-256/512 and, where the platform's OpenSSL still exposes MD4, NTLM and
MD4. With no --algo it tries every scheme whose digest length matches, so you can
paste a bare hash and let it work the shape out.

A portable fallback for when hashcat/john are not on the box (restricted shells,
CTF foothold). For large wordlists or salted/slow hashes use hashcat or john.

Authorized / educational use only: crack hashes you own or are permitted to test.

Examples:
    python3 hashcrack.py <hash> -w /usr/share/wordlists/rockyou.txt
    python3 hashcrack.py <hash> -a md5 -w words.txt
    python3 hashcrack.py -f hashes.txt -w rockyou.txt
    python3 hashcrack.py --list
"""

import argparse
import hashlib
import sys


def _utf8(name):
    return lambda pw: hashlib.new(name, pw.encode()).hexdigest()


def _ntlm(pw):
    return hashlib.new("md4", pw.encode("utf-16-le")).hexdigest()


# name -> function(password_str) -> lowercase hex digest.
HASHERS = {
    "md5":      _utf8("md5"),
    "sha1":     _utf8("sha1"),
    "sha224":   _utf8("sha224"),
    "sha256":   _utf8("sha256"),
    "sha384":   _utf8("sha384"),
    "sha512":   _utf8("sha512"),
    "sha3_256": _utf8("sha3_256"),
    "sha3_512": _utf8("sha3_512"),
}
# MD4 backs both raw MD4 and NTLM, but OpenSSL 3 often drops it. Only offer them
# when the platform can actually compute them, so a run never half-works.
try:
    hashlib.new("md4", b"")
    HASHERS["md4"] = _utf8("md4")
    HASHERS["ntlm"] = _ntlm
except (ValueError, TypeError):
    pass

HEXLEN = {32, 40, 56, 64, 96, 128}


def candidates(target):
    """Which hashers could have produced this digest, by hex length."""
    n = len(target)
    return [name for name, fn in HASHERS.items() if len(fn("x")) == n]


def crack(target, words, algos):
    """Return (password, algo) for the first word that hashes to target, else (None, None)."""
    target = target.strip().lower()
    for w in words:
        for a in algos:
            if HASHERS[a](w) == target:
                return w, a
    return None, None


def load_words(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return [ln.rstrip("\r\n") for ln in f]


def main():
    p = argparse.ArgumentParser(
        description="Dictionary attack against raw hashes (stdlib only).",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("hash", nargs="?", help="the hash ('-'/omit reads stdin)")
    p.add_argument("-f", "--file", help="file with one hash per line")
    p.add_argument("-w", "--wordlist",
                   default="/usr/share/wordlists/rockyou.txt",
                   help="wordlist path (default: rockyou.txt)")
    p.add_argument("-a", "--algo", help="force one scheme (see --list)")
    p.add_argument("--list", action="store_true",
                   help="list the schemes this build can crack and exit")
    args = p.parse_args()

    if args.list:
        for name in HASHERS:
            print(f"  {name}")
        return
    if args.algo and args.algo not in HASHERS:
        p.error(f"unknown scheme '{args.algo}'. See --list.")

    if args.file:
        hashes = [ln.strip() for ln in load_words(args.file) if ln.strip()]
    elif args.hash in (None, "-"):
        hashes = [ln.strip() for ln in sys.stdin if ln.strip()]
    else:
        hashes = [args.hash]

    try:
        words = load_words(args.wordlist)
    except FileNotFoundError:
        sys.exit(f"[-] Wordlist not found: {args.wordlist}. Pass one with -w.")

    cracked = 0
    for h in hashes:
        if len(h) not in HEXLEN and not args.algo:
            print(f"[-] {h[:40]} - no scheme matches this length.")
            continue
        algos = [args.algo] if args.algo else candidates(h)
        pw, algo = crack(h, words, algos)
        if pw is not None:
            cracked += 1
            print(f"[+] {h[:40]}  ->  {pw!r}  ({algo})")
        else:
            print(f"[-] {h[:40]}  not found in {len(words)} word(s)")

    print(f"\n[*] {cracked}/{len(hashes)} cracked.", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except FileNotFoundError as e:
        sys.exit(f"[-] {e}")

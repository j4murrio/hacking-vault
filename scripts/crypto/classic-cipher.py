#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
classic-cipher.py - Toolkit for the ciphers that show up in CTF crypto/misc.

Caesar/ROT brute force, single-byte and repeating-key XOR, Vigenere, Atbash,
rail fence, and letter-frequency analysis. English scoring ranks brute-force
candidates so the plaintext usually floats to the top.

Authorized / educational use only.

Examples:
    python3 classic-cipher.py caesar  "iodj{urw13}"
    python3 classic-cipher.py xor     --brute --hex 1f1f1f...
    python3 classic-cipher.py xor     --key SECRET --hex $(cat cipher.hex)
    python3 classic-cipher.py vigenere -k LEMON "rijvs..."
    python3 classic-cipher.py railfence --brute "Wenhgtstructure..."
    python3 classic-cipher.py freq -f cipher.txt
"""

import argparse
import string
import sys
from collections import Counter

PRINTABLE = set(range(32, 127)) | {9, 10, 13}


# Substrings that strongly signal real plaintext (flag markers, English words).
CRIBS = ("flag", "ctf", "htb", "key", "the", "and", "that", "with",
         "you", "are", "for", "pass", "root", "http", "user")


def plaintext_score(data):
    """Heuristic score (higher = better) tuned for CTF plaintext and flags.

    A per-character base rewards lowercase/space and flag characters and punishes
    binary; crib bonuses add the order-sensitive signal that lets a real flag beat
    a random letter-soup of the same length.
    """
    score = 0
    for b in data:
        ch = chr(b)
        if ch in string.ascii_lowercase or ch == " ":
            score += 3
        elif ch in "_{}-" or ch in string.digits:
            score += 2
        elif ch in string.ascii_uppercase or ch in ".,!?'\"":
            score += 1
        elif b not in PRINTABLE:
            score -= 5
    text = data.decode("latin-1").lower()
    bonus = 3 if ("{" in text and "}" in text) else 0
    bonus += 4 * sum(1 for crib in CRIBS if crib in text)
    return score / max(len(data), 1) + bonus


# Common English n-grams; used to rank transposition output, whose character
# multiset never changes (so a per-character score cannot tell rails apart).
COMMON_NGRAMS = (
    "the", "and", "ing", "ion", "ent", "tio", "for", "her", "ere", "ver",
    "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es",
    "or", "te", "of", "ed", "is", "it", "al", "ar", "st", "to",
)


def transposition_score(data):
    """Order-sensitive score (higher = better) for transposition ciphers."""
    text = data.decode("latin-1").lower()
    return sum(text.count(g) for g in COMMON_NGRAMS)


def show(data, limit=200):
    text = data.decode("utf-8", "backslashreplace")
    return text[:limit].replace("\n", "\\n")


def get_data(args):
    """Resolve input bytes from --hex, a positional string, -f file, or stdin."""
    if getattr(args, "file", None):
        with open(args.file, "rb") as f:
            raw = f.read()
    elif getattr(args, "text", None) not in (None, "-"):
        raw = args.text.encode()
    else:
        raw = sys.stdin.buffer.read()
    if getattr(args, "hex", False):
        raw = bytes.fromhex("".join(raw.decode("ascii", "ignore").split()))
    return raw.strip() if not getattr(args, "hex", False) else raw


# ============================================================================
# Ciphers
# ============================================================================
def caesar_shift(text, k):
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + k) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + k) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def cmd_caesar(args):
    text = get_data(args).decode("utf-8", "backslashreplace")
    if args.shift is not None:
        print(caesar_shift(text, args.shift))
        return
    ranked = sorted(range(26),
                    key=lambda k: plaintext_score(caesar_shift(text, k).encode()),
                    reverse=True)
    top = ranked if args.all else ranked[:5]
    for k in top:
        print(f"[{k:>2}] {caesar_shift(text, k)}")


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def cmd_xor(args):
    data = get_data(args)
    if args.brute:
        ranked = sorted(range(256),
                        key=lambda k: plaintext_score(xor_bytes(data, bytes([k]))),
                        reverse=True)
        for k in ranked[:8]:
            print(f"[key 0x{k:02x} {k:>3}] {show(xor_bytes(data, bytes([k])))}")
        return
    if not args.key:
        sys.exit("xor: provide --brute or --key")
    key = bytes.fromhex(args.key) if args.key_hex else args.key.encode()
    out = xor_bytes(data, key)
    sys.stdout.buffer.write(out + b"\n")


def cmd_vigenere(args):
    text = get_data(args).decode("utf-8", "backslashreplace")
    key = [ord(c.lower()) - 97 for c in args.key if c.isalpha()]
    if not key:
        sys.exit("vigenere: key must contain letters")
    sign = 1 if args.encrypt else -1
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - base + sign * key[ki % len(key)]) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    print("".join(out))


def cmd_atbash(args):
    text = get_data(args).decode("utf-8", "backslashreplace")
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr(219 - ord(ch)))   # 219 = ord('a') + ord('z')
        elif "A" <= ch <= "Z":
            out.append(chr(155 - ord(ch)))   # 155 = ord('A') + ord('Z')
        else:
            out.append(ch)
    print("".join(out))


def railfence_decrypt(text, rails):
    if rails < 2:
        return text
    # Mark the zig-zag pattern, then place characters back along the rails.
    pattern, r, step = [], 0, 1
    for _ in text:
        pattern.append(r)
        if r == 0:
            step = 1
        elif r == rails - 1:
            step = -1
        r += step
    order = sorted(range(len(text)), key=lambda i: pattern[i])
    placed = [""] * len(text)
    for idx, pos in zip(order, range(len(text))):
        placed[idx] = text[pos]
    return "".join(placed)


def cmd_railfence(args):
    text = get_data(args).decode("utf-8", "backslashreplace")
    if args.brute:
        ranked = sorted(range(2, 11),
                        key=lambda r: transposition_score(railfence_decrypt(text, r).encode()),
                        reverse=True)
        for r in ranked[:5]:
            print(f"[rails {r}] {railfence_decrypt(text, r)}")
        return
    print(railfence_decrypt(text, args.rails))


def cmd_freq(args):
    data = get_data(args)
    letters = [chr(b).lower() for b in data if chr(b).isalpha()]
    if not letters:
        sys.exit("freq: no letters in input")
    total = len(letters)
    for ch, n in Counter(letters).most_common():
        bar = "#" * int(50 * n / total)
        print(f"  {ch}  {n:>5} {100*n/total:5.1f}%  {bar}")


def main():
    p = argparse.ArgumentParser(
        description="Classic-cipher toolkit for CTF crypto.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_input(sp):
        sp.add_argument("text", nargs="?", help="input text ('-'/omit for stdin)")
        sp.add_argument("-f", "--file", help="read input from a file")

    c = sub.add_parser("caesar", help="Caesar/ROT brute force or fixed shift")
    add_input(c)
    c.add_argument("-s", "--shift", type=int, help="use a fixed shift instead of brute")
    c.add_argument("--all", action="store_true", help="show all 26 shifts")
    c.set_defaults(func=cmd_caesar)

    x = sub.add_parser("xor", help="single-byte brute or repeating-key XOR")
    add_input(x)
    x.add_argument("--hex", action="store_true", help="input is a hex string")
    x.add_argument("--brute", action="store_true", help="brute single-byte key")
    x.add_argument("--key", help="repeating key (string, or hex with --key-hex)")
    x.add_argument("--key-hex", action="store_true", help="treat --key as hex")
    x.set_defaults(func=cmd_xor)

    v = sub.add_parser("vigenere", help="Vigenere decrypt (or --encrypt)")
    add_input(v)
    v.add_argument("-k", "--key", required=True, help="alphabetic key")
    v.add_argument("--encrypt", action="store_true", help="encrypt instead of decrypt")
    v.set_defaults(func=cmd_vigenere)

    a = sub.add_parser("atbash", help="Atbash substitution")
    add_input(a)
    a.set_defaults(func=cmd_atbash)

    rf = sub.add_parser("railfence", help="rail-fence decrypt or brute rails")
    add_input(rf)
    rf.add_argument("--rails", type=int, default=3, help="number of rails (default 3)")
    rf.add_argument("--brute", action="store_true", help="try 2..10 rails")
    rf.set_defaults(func=cmd_railfence)

    fq = sub.add_parser("freq", help="letter-frequency analysis")
    add_input(fq)
    fq.set_defaults(func=cmd_freq)

    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

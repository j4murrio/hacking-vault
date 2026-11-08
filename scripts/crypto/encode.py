#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
encode.py - Encode text into the formats that show up in CTF and web work.

The inverse of magic-decode: give it a string and it produces base64/base32/hex/
url/rot13/binary/decimal/html/reversed/gzip+base64. Pick one codec, or run `all`
(also the default) to see every encoding side by side.

Authorized / educational use only.

Examples:
    python3 encode.py "secret"              # all codecs at once
    python3 encode.py base64 "secret"
    python3 encode.py rot 13 "attack"
    python3 encode.py all -f payload.bin
    echo -n hi | python3 encode.py hex
"""

import argparse
import base64
import binascii
import gzip
import html
import sys
import urllib.parse


def _rot(data, n):
    out = []
    for b in data:
        ch = chr(b)
        if "a" <= ch <= "z":
            out.append(chr((b - 97 + n) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((b - 65 + n) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


# Each codec maps raw bytes to a printable string. Keyed by the subcommand name.
CODECS = {
    "base64":  lambda d: base64.b64encode(d).decode(),
    "base64url": lambda d: base64.urlsafe_b64encode(d).decode(),
    "base32":  lambda d: base64.b32encode(d).decode(),
    "hex":     lambda d: d.hex(),
    "url":     lambda d: urllib.parse.quote(d, safe=""),
    "rot13":   lambda d: _rot(d, 13),
    "binary":  lambda d: " ".join(f"{b:08b}" for b in d),
    "decimal": lambda d: " ".join(str(b) for b in d),
    "html":    lambda d: html.escape(d.decode("utf-8", "replace")),
    "reverse": lambda d: d.decode("utf-8", "backslashreplace")[::-1],
    "gzip64":  lambda d: base64.b64encode(gzip.compress(d)).decode(),
}

# Codecs that read cleanly in an "all" overview (rot handled separately).
ALL_ORDER = ["base64", "base64url", "base32", "hex", "url", "rot13",
             "binary", "decimal", "html", "reverse", "gzip64"]


def get_data(args):
    """Resolve input bytes from a file, a positional string, or stdin."""
    if getattr(args, "file", None):
        with open(args.file, "rb") as f:
            return f.read()
    if getattr(args, "text", None) not in (None, "-"):
        return args.text.encode()
    return sys.stdin.buffer.read()


def cmd_one(name, args):
    data = get_data(args)
    print(CODECS[name](data))


def cmd_rot(args):
    data = get_data(args)
    print(_rot(data, args.n % 26))


def cmd_all(args):
    data = get_data(args)
    width = max(len(n) for n in ALL_ORDER)
    for name in ALL_ORDER:
        try:
            value = CODECS[name](data)
        except (UnicodeError, binascii.Error) as e:
            value = f"[-] {e}"
        print(f"  {name:<{width}}  {value}")


def main():
    p = argparse.ArgumentParser(
        description="Encode text into common CTF/web formats.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd")

    def add_input(sp):
        sp.add_argument("text", nargs="?", help="input text ('-'/omit for stdin)")
        sp.add_argument("-f", "--file", help="read raw input from a file")

    for name in CODECS:
        sp = sub.add_parser(name, help=f"encode to {name}")
        add_input(sp)
        sp.set_defaults(func=lambda a, n=name: cmd_one(n, a))

    r = sub.add_parser("rot", help="Caesar/ROT by N (e.g. rot 13)")
    r.add_argument("n", type=int, help="shift amount")
    add_input(r)
    r.set_defaults(func=cmd_rot)

    a = sub.add_parser("all", help="show every encoding at once (default)")
    add_input(a)
    a.set_defaults(func=cmd_all)

    # No subcommand, or a first token that is not a subcommand, means "all":
    # `encode.py "secret"` and `encode.py` (stdin) both run every codec.
    argv = sys.argv[1:]
    subcommands = set(CODECS) | {"rot", "all"}
    if argv and argv[0] in ("-h", "--help"):
        pass
    elif not argv or argv[0] not in subcommands:
        argv = ["all"] + argv

    args = p.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except (FileNotFoundError, IsADirectoryError, PermissionError) as e:
        sys.exit(f"[-] {e}")

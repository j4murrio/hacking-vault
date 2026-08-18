#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hashid.py - Identify a hash and print the hashcat / john command to crack it.

Offline, regex + length based. Where a shape is ambiguous (e.g. 32 hex could be
MD5 or NTLM) it lists every candidate with its hashcat -m mode and john format,
plus a ready-to-run command template.

Authorized / educational use only.

Examples:
    python3 hashid.py 5f4dcc3b5aa765d61d8327deb882cf99
    python3 hashid.py '$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW'
    python3 hashid.py -f hashes.txt -w /usr/share/wordlists/rockyou.txt
"""

import argparse
import re
import sys

# Schemes recognised by their prefix. (regex, name, hashcat_mode, john_format)
PREFIXED = [
    (r"^\$1\$",            "md5crypt",           "500",   "md5crypt"),
    (r"^\$2[aby]?\$\d\d\$", "bcrypt",             "3200",  "bcrypt"),
    (r"^\$5\$",            "sha256crypt",        "7400",  "sha256crypt"),
    (r"^\$6\$",            "sha512crypt",        "1800",  "sha512crypt"),
    (r"^\$apr1\$",         "Apache apr1-md5",    "1600",  "md5crypt"),
    (r"^\$y\$",            "yescrypt",           "-",     "yescrypt"),
    (r"^\$(P|H)\$",        "phpass (WP/phpBB)",  "400",   "phpass"),
    (r"^\{SSHA\}",         "LDAP SSHA",          "111",   "ssha"),
    (r"^\{SHA\}",          "LDAP SHA",           "101",   "raw-sha1"),
    (r"^sha1\$",           "Django SHA1",        "124",   "django"),
    (r"^md5\$",            "Django MD5",         "-",     "django"),
    (r"^\$krb5tgs\$",      "Kerberos TGS-REP",   "13100", "krb5tgs"),
    (r"^\$krb5asrep\$",    "Kerberos AS-REP",    "18200", "krb5asrep"),
    (r"^\$DCC2\$|^\$dcc2\$", "Domain Cached Creds 2", "2100", "mscash2"),
]

# Hashes distinguished only by hex length. length -> [(name, mode, john), ...]
HEX_LEN = {
    16:  [("MySQL323", "200", "mysql")],
    32:  [("MD5", "0", "raw-md5"), ("NTLM", "1000", "nt"),
          ("MD4", "900", "raw-md4"), ("LM", "3000", "lm")],
    40:  [("SHA1", "100", "raw-sha1"), ("RIPEMD-160", "6000", "ripemd-160")],
    56:  [("SHA224", "1300", "raw-sha224")],
    64:  [("SHA256", "1400", "raw-sha256"), ("SHA3-256", "17400", "raw-sha3")],
    96:  [("SHA384", "10800", "raw-sha384")],
    128: [("SHA512", "1700", "raw-sha512"), ("SHA3-512", "17600", "-")],
}


def detect(h):
    h = h.strip()
    for pat, name, mode, john in PREFIXED:
        if re.search(pat, h):
            return [(name, mode, john)]
    # pwdump line: user:rid:LM:NT:::  -> the NT part is what you crack
    m = re.search(r":([0-9a-fA-F]{32}):([0-9a-fA-F]{32}):", h)
    if m:
        return [("NTLM (from pwdump, NT hash)", "1000", "nt")]
    # MySQL 4.1+ : '*' + 40 uppercase hex
    if re.fullmatch(r"\*[0-9A-F]{40}", h):
        return [("MySQL4.1+", "300", "mysql-sha1")]
    if re.fullmatch(r"[0-9a-fA-F]+", h) and len(h) in HEX_LEN:
        return list(HEX_LEN[len(h)])
    return []


def main():
    p = argparse.ArgumentParser(
        description="Identify a hash and print the crack command.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("hash", nargs="?", help="the hash ('-'/omit reads stdin)")
    p.add_argument("-f", "--file", help="file with one hash per line")
    p.add_argument("-w", "--wordlist",
                   default="/usr/share/wordlists/rockyou.txt",
                   help="wordlist for the command templates")
    args = p.parse_args()

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            hashes = [ln.strip() for ln in f if ln.strip()]
    elif args.hash in (None, "-"):
        hashes = [ln.strip() for ln in sys.stdin if ln.strip()]
    else:
        hashes = [args.hash]

    for h in hashes:
        cands = detect(h)
        print(f"\n[*] {h[:70]}{'…' if len(h) > 70 else ''}")
        if not cands:
            print("    [-] Unrecognised shape.")
            continue
        for name, mode, john in cands:
            print(f"    [+] {name}")
            if mode != "-":
                print(f"        hashcat -m {mode} -a 0 '{h}' {args.wordlist}")
            if john != "-":
                print(f"        john --format={john} --wordlist={args.wordlist} <file>")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

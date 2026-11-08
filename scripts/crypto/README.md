# Crypto / CTF

Helpers for the encoding, cipher and hash puzzles that show up in CTF crypto/misc and in
credential work. All offline, pure Python standard library, single file each.

> ⚠️ Authorized / educational use only.

---

## `magic-decode.py` - recursive multi-encoding decoder

**What it does:** takes a scrambled blob and peels away layered encodings until it reaches
readable text or a flag. The console equivalent of CyberChef's "Magic".

**How it works:** it tries every decoder (base64/32/85, hex, URL, ROT13, binary, decimal,
morse, gzip/zlib/bz2) breadth-first. After each successful decode it scores how readable the
result is and keeps peeling the promising branches, stopping as soon as a flag regex matches.
`--all` instead applies every codec once and shows each result, for manual inspection.

```bash
python3 magic-decode.py "NzM2NTYzNzI2NTc0"        # auto-peel
echo "<blob>" | python3 magic-decode.py - --all   # one layer, every codec
```

---

## `classic-cipher.py` - classic cipher toolkit

**What it does:** decrypts or brute-forces the classic ciphers: Caesar/ROT, XOR
(single-byte and repeating-key), Vigenere, Atbash, rail fence, plus letter-frequency
analysis.

**How it works:** for brute-force modes it tries every key and **scores** each candidate
with an English/flag heuristic (common letters, `flag{...}` markers, frequent n-grams for
transposition), so the real plaintext floats to the top of the list instead of leaving you
to eyeball 256 outputs.

```bash
python3 classic-cipher.py caesar "iodj{khoor}"        # brute, ranked
python3 classic-cipher.py xor --brute --hex "$(cat c.hex)"
python3 classic-cipher.py vigenere -k LEMON "rijvs..."
```

---

## `hashid.py` - identify a hash and get the crack command

**What it does:** tells you what kind of hash you are holding and prints the exact
`hashcat` / `john` command to crack it.

**How it works:** matches the hash against known prefixes (`$2b$`, `$6$`, `$krb5tgs$`...)
and, for bare hex, against its length (32 = MD5/NTLM/..., 64 = SHA256/...). Ambiguous shapes
list every candidate with its hashcat `-m` mode and john format, each as a ready-to-run
command template.

```bash
python3 hashid.py 5f4dcc3b5aa765d61d8327deb882cf99
python3 hashid.py -f hashes.txt -w /usr/share/wordlists/rockyou.txt
```

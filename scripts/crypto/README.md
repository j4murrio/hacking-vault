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

## `encode.py` - the encoder (inverse of magic-decode)

**What it does:** the forward direction - turns text into base64/base64url/base32/hex,
URL-encoding, ROT13, binary, decimal, HTML entities, reversed or gzip+base64. Handy for
building a payload or an expected value to match.

**How it works:** one codec per subcommand; running it with **no subcommand** (or `all`)
applies every codec at once and prints each result, so you can eyeball which form a
challenge wants. `rot` takes an explicit shift (`rot -n 5`).

```bash
python3 encode.py base64 "flag{hello}"      # one codec
python3 encode.py "flag{hello}"             # all codecs at once (default)
python3 encode.py rot -n 13 "uryyb"         # ROT with an explicit shift
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

With **no subcommand** (or `all`) it throws every keyless attack at the input - 26 Caesar
shifts, Atbash, all 256 single-byte XOR keys and rail fence 2..10 - and prints the
best-scoring candidates first. Reach for a named subcommand only when you need a key
(Vigenere, repeating-key XOR) or raw frequency counts.

```bash
python3 classic-cipher.py "iodj{khoor}"               # all keyless attacks, ranked
python3 classic-cipher.py caesar "iodj{khoor}"        # brute, ranked
python3 classic-cipher.py xor --brute --hex "$(cat c.hex)"
python3 classic-cipher.py vigenere -k LEMON "rijvs..."
```

---

## `jwt-tool.py` - inspect, verify and attack JSON Web Tokens

**What it does:** decodes a JWT's header and payload, flags the classic weaknesses
(`alg:none`, a symmetric HS* secret you can brute), checks the `exp`/`nbf`/`iat` times,
and either verifies a known secret or dictionary-cracks an HS256 one.

**How it works:** it splits the three base64url parts and pretty-prints them. `--secret`
recomputes the HMAC and compares it in constant time (`hmac.compare_digest`). `--wordlist`
tries each line as the HS secret until the signature matches - the standard attack on a
weak-key HS256 token. `--forge-none` rebuilds the token with `"alg":"none"` and an empty
signature, to test whether a server wrongly accepts it.

```bash
python3 jwt-tool.py eyJhbGci...                         # decode + warnings
python3 jwt-tool.py eyJhbGci... --wordlist rockyou.txt  # crack the HS256 secret
python3 jwt-tool.py eyJhbGci... --forge-none            # build an alg:none token
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

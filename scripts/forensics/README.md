# Forensics / stego

Offline inspection of a single file - the first look at a CTF forensics or stego artifact.
Nothing here touches a network. Pure Python standard library, single file.

> ⚠️ Authorized / educational use only.

---

## `fileinspect.py` - magic bytes, strings, entropy and carving

**What it does:** tells you what a mystery file really is and what it is hiding: its true
type from the magic bytes (not the extension), the printable strings inside it, how random
each region is, and whether another file is buried in it.

**How it works:** it matches the header against a table of file signatures, extracts ASCII
and UTF-16 strings above a minimum length (`--min`), and computes **Shannon entropy** - a
high, flat value points at encryption or compression, a spike flags an embedded blob. It
then scans the whole file for the signatures of common formats (PNG, ZIP, PDF, JPEG...) to
**carve** files appended after the real end - the classic "extra ZIP glued onto a PNG"
stego trick. `--flag` highlights strings matching your flag regex.

```bash
python3 fileinspect.py suspicious.png                  # type, entropy, embedded files
python3 fileinspect.py suspicious.png --strings --min 6
python3 fileinspect.py dump.bin --flag 'flag\{[^}]+\}'
```

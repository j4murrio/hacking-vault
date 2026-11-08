# Shells

Getting an interactive shell back from a target you are testing. Pure Python standard
library, single file.

> ⚠️ For systems you are authorized to test (labs, CTFs, engagements with written
> permission). Authorized / educational use only.

---

## `revshell.py` - reverse-shell generator

**What it does:** prints ready-to-paste reverse-shell one-liners for your listener
(LHOST/LPORT) across many interpreters - bash, nc, python, php, perl, ruby, powershell,
socat and more - plus the matching listener command to catch the connection.

**How it works:** it is a templating tool, nothing more: it substitutes your IP and port
into each payload. `--type` picks one interpreter (default: print them all), `--platform`
filters linux/windows, `--base64` wraps a *nix payload so odd quoting survives copy/paste,
`--url-encode` makes it safe for a web injection point, and `--listener` prints the
`nc`/`socat`/`pwncat` command to listen with. It only builds strings - it never connects to
anything.

```bash
python3 revshell.py 10.10.14.5 4444                    # every interpreter
python3 revshell.py 10.10.14.5 4444 -t bash --base64 --listener nc
python3 revshell.py 10.10.14.5 4444 -t powershell --url-encode
python3 revshell.py --list                             # see the interpreter names
```

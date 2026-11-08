"""Declarative tool catalog: the single source the CLI, menu and web all read.

Each tool is an external standalone script (so the scripts stay usable on their
own) described here by its parameters. The runner turns a {param: value} mapping
into an argv the script already understands; the menu and web build their forms
by walking the same Param list. Adding a tool is one ToolSpec entry.
"""

from dataclasses import dataclass, field


@dataclass
class Param:
    name: str                 # "domain" (positional) or "--live" (option)
    label: str
    required: bool = False
    default: object = None
    kind: str = "str"         # str | int | flag | choice | text
    choices: tuple = ()
    help: str = ""

    @property
    def positional(self):
        return not self.name.startswith("-")

    @property
    def key(self):
        return self.name.lstrip("-").replace("-", "_")


@dataclass
class ToolSpec:
    id: str
    category: str
    name: str
    summary: str
    script: str               # path relative to the repo root
    params: list = field(default_factory=list)
    needs_root: bool = False
    note: str = ""

    def argv(self, values):
        """Build the script argv from a {param.key: value} mapping."""
        pos, opts = [], []
        for p in self.params:
            v = values.get(p.key, p.default)
            if p.positional:
                if v not in (None, ""):
                    pos.append(str(v))
            elif p.kind == "flag":
                if v:
                    opts.append(p.name)
            elif v not in (None, "", False):
                opts += [p.name, str(v)]
        return pos + opts


def build_registry():
    """Return the ordered list of ToolSpec for the whole toolkit."""
    s = "scripts"
    return [
        # ---- OSINT (passive) ------------------------------------------------
        ToolSpec(
            "osint.crtsh", "OSINT", "crt.sh subdomains",
            "Passive subdomain enumeration via Certificate Transparency logs.",
            f"{s}/osint/crtsh.py",
            [Param("domain", "Domain", required=True, help="apex domain, e.g. example.com"),
             Param("--live", "Probe live hosts", kind="flag"),
             Param("--wildcards", "Keep wildcards", kind="flag"),
             Param("--timeout", "Timeout (s)", default=30, kind="int")]),
        ToolSpec(
            "osint.username", "OSINT", "Username hunt",
            "Find where a username is registered across ~30 public sites.",
            f"{s}/osint/username-hunt.py",
            [Param("username", "Username", required=True),
             Param("--found-only", "Only hits", kind="flag"),
             Param("--timeout", "Timeout (s)", default=8, kind="int")]),
        ToolSpec(
            "osint.footprint", "OSINT", "DNS + WHOIS footprint",
            "Passive DNS (over HTTPS) and WHOIS registration footprint.",
            f"{s}/osint/footprint.py",
            [Param("domain", "Domain", required=True),
             Param("--dns-only", "DNS only", kind="flag"),
             Param("--whois-only", "WHOIS only", kind="flag"),
             Param("--resolver", "DoH resolver", default="google",
                   kind="choice", choices=("google", "cloudflare"))]),
        ToolSpec(
            "osint.wayback", "OSINT", "Wayback URLs",
            "Archived URLs for a domain from the Wayback Machine (passive).",
            f"{s}/osint/wayback.py",
            [Param("domain", "Domain", required=True, help="apex domain, e.g. example.com"),
             Param("--subdomains", "Include subdomains", kind="flag"),
             Param("--ext", "Extensions", help="comma-separated, e.g. php,bak,sql"),
             Param("--params", "Only URLs with params", kind="flag"),
             Param("--live", "Keep reachable only", kind="flag"),
             Param("--timeout", "Timeout (s)", default=30, kind="int")]),
        # ---- Recon (active) -------------------------------------------------
        ToolSpec(
            "recon.dnsrecon", "Recon", "DNS recon + AXFR",
            "Active DNS records, zone-transfer attempt and subdomain brute force.",
            f"{s}/recon/dnsrecon.py",
            [Param("domain", "Domain", required=True),
             Param("--resolver", "Resolver IP", default="8.8.8.8"),
             Param("--axfr", "Try zone transfer", kind="flag"),
             Param("--brute", "Brute subdomains", kind="flag"),
             Param("--wordlist", "Wordlist path")]),
        ToolSpec(
            "recon.portscan", "Recon", "Port scan (no nmap)",
            "Threaded TCP connect scanner for boxes without nmap.",
            f"{s}/recon/portscan.py",
            [Param("target", "Target", required=True, help="host or IP"),
             Param("--ports", "Ports", default="top",
                   help="e.g. 1-1024, 22,80,443, top, - (all)"),
             Param("--banner", "Grab banners", kind="flag"),
             Param("--threads", "Threads", default=200, kind="int")]),
        ToolSpec(
            "recon.webenum", "Recon", "Web recon",
            "Headers, cookies, methods, robots and interesting paths (detection only).",
            f"{s}/recon/webenum.py",
            [Param("url", "URL", required=True, help="http(s)://host[:port]/"),
             Param("--insecure", "Skip TLS verify", kind="flag"),
             Param("--paths", "Extra paths", help="comma-separated")]),
        ToolSpec(
            "recon.httpprobe", "Recon", "HTTP probe",
            "Probe a host list for live HTTP/HTTPS: status, title, server.",
            f"{s}/recon/httpprobe.py",
            [Param("hosts", "Hosts", help="space-separated (or use --file)"),
             Param("--file", "Host file", help="one host per line"),
             Param("--ports", "Ports", default="80,443"),
             Param("--title", "Fetch title", kind="flag"),
             Param("--insecure", "Skip TLS verify", kind="flag"),
             Param("--timeout", "Timeout (s)", default=8, kind="int")]),
        # ---- Web application ------------------------------------------------
        ToolSpec(
            "web.dirscan", "Web", "Content discovery",
            "Threaded directory/file discovery against a base URL (built-in or wordlist).",
            f"{s}/web/dirscan.py",
            [Param("url", "Base URL", required=True, help="http(s)://host[:port]/"),
             Param("--wordlist", "Wordlist", help="path (default: built-in list)"),
             Param("--ext", "Extensions", help="comma-separated, e.g. php,txt,bak"),
             Param("--status", "Status codes", default="200,204,301,302,307,401,403"),
             Param("--insecure", "Skip TLS verify", kind="flag"),
             Param("--timeout", "Timeout (s)", default=8, kind="int")]),
        ToolSpec(
            "web.cors", "Web", "CORS check",
            "Detect permissive / misconfigured CORS (reflected origin, null, credentials).",
            f"{s}/web/cors-check.py",
            [Param("url", "URL", required=True, help="endpoint, e.g. https://api.host/"),
             Param("--origin", "Attacker origin", help="default https://evil.example"),
             Param("--insecure", "Skip TLS verify", kind="flag"),
             Param("--timeout", "Timeout (s)", default=10, kind="int")]),
        # ---- Vulnerability scan (flagship) ----------------------------------
        ToolSpec(
            "scan.vulnscan", "Scan", "vulnscan (all-in-one)",
            "Chained auditor: nmap, web, SMB/AD, nuclei, fuzzing, hydra, report.",
            "tools/vulnscan/vulnscan.py",
            [Param("target", "Target", required=True, help="IP, host, URL or domain"),
             Param("--full", "Full scan", kind="flag"),
             Param("--dns", "DNS recon", kind="flag"),
             Param("--subdomains", "Subdomains", kind="flag"),
             Param("--smb", "Force SMB enum", kind="flag"),
             Param("--fuzz", "Dir fuzzing", kind="flag"),
             Param("--sqli", "SQLi tests", kind="flag"),
             Param("--bruteforce", "Brute login", kind="flag")],
            note="Needs external tools installed (nmap, nuclei...). Long-running: "
                 "prefer the CLI for big scans."),
        # ---- Crypto / CTF ---------------------------------------------------
        ToolSpec(
            "crypto.magic", "Crypto", "Magic decoder",
            "Recursively peel layered encodings (base64/hex/url/rot/gzip...) to text.",
            f"{s}/crypto/magic-decode.py",
            [Param("data", "Data / blob", required=True, kind="text"),
             Param("--all", "All codecs (1 layer)", kind="flag"),
             Param("--flag", "Flag regex")]),
        ToolSpec(
            "crypto.encode", "Crypto", "Encoder",
            "Encode text into base64/32/hex/url/rot13/binary; 'all' shows every one.",
            f"{s}/crypto/encode.py",
            [Param("cmd", "Codec", default="all", kind="choice",
                   choices=("all", "base64", "base64url", "base32", "hex", "url",
                            "rot13", "binary", "decimal", "html", "reverse", "gzip64")),
             Param("text", "Text", kind="text")]),
        ToolSpec(
            "crypto.cipher", "Crypto", "Classic ciphers",
            "Caesar/XOR/Vigenere/Atbash/railfence/frequency with scoring; 'all' runs them all.",
            f"{s}/crypto/classic-cipher.py",
            [Param("cmd", "Cipher", default="all", kind="choice",
                   choices=("all", "caesar", "xor", "vigenere", "atbash",
                            "railfence", "freq")),
             Param("text", "Text", kind="text"),
             Param("--brute", "Brute force", kind="flag"),
             Param("--hex", "Input is hex", kind="flag"),
             Param("--key", "Key")]),
        ToolSpec(
            "crypto.hashid", "Crypto", "Hash identifier",
            "Identify a hash and print the hashcat / john crack command.",
            f"{s}/crypto/hashid.py",
            [Param("hash", "Hash", required=True),
             Param("--wordlist", "Wordlist", default="/usr/share/wordlists/rockyou.txt")]),
        ToolSpec(
            "crypto.jwt", "Crypto", "JWT tool",
            "Decode a JWT, flag alg:none, verify or dictionary-crack the HS256 secret.",
            f"{s}/crypto/jwt-tool.py",
            [Param("token", "Token", required=True, kind="text"),
             Param("--secret", "Verify secret", help="verify an HS* signature"),
             Param("--wordlist", "Crack wordlist", help="dictionary-crack the secret"),
             Param("--forge-none", "Forge alg:none", kind="flag")]),
        # ---- Forensics / CTF ------------------------------------------------
        ToolSpec(
            "forensics.fileinspect", "Forensics", "File inspector",
            "Magic bytes, strings, entropy and embedded-file carving for a file.",
            f"{s}/forensics/fileinspect.py",
            [Param("file", "File path", required=True),
             Param("--strings", "Dump strings", kind="flag"),
             Param("--min", "Min string len", default=4, kind="int"),
             Param("--flag", "Flag regex")]),
        # ---- Exploitation ---------------------------------------------------
        ToolSpec(
            "shells.revshell", "Shells", "Reverse shell generator",
            "Reverse-shell one-liners across interpreters, plus the listener.",
            f"{s}/shells/revshell.py",
            [Param("ip", "LHOST", required=True, help="your listener IP"),
             Param("port", "LPORT", required=True, kind="int"),
             Param("--type", "Shell type", help="bash, python3, powershell... (blank = all)"),
             Param("--platform", "Platform", kind="choice", choices=("", "linux", "windows")),
             Param("--base64", "Base64 wrap", kind="flag"),
             Param("--url-encode", "URL-encode", kind="flag"),
             Param("--listener", "Listener", kind="choice",
                   choices=("", "nc", "ncat", "socat", "socat-tty", "pwncat"))]),
    ]

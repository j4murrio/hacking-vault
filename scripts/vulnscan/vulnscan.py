#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vulnscan.py - Security auditor: network + web + SMB/AD + DNS.

Orchestrates the tools already installed in your archpwm environment to run a
complete target audit: discovery, enumeration, vulnerability detection and
suggested attack vectors, all saved in a final Markdown report.

Tools used (all available in archpwm; each phase is skipped automatically if
its tool is missing):

    dig        -> DNS records + zone transfer (AXFR)               [domains]
    subfinder  -> subdomain enumeration                            [domains]
    nmap       -> ports, services and (optional) vuln scripts
    httpx      -> web fingerprint (technology, title, server)
    ffuf       -> directory fuzzing
    nuclei     -> web vulnerability scanner (template-based)
    sqlmap     -> automated SQL injection
    enum4linux / smbclient / netexec -> SMB / Windows enumeration
    hydra      -> SSH/FTP brute-force login                         [opt-in]
    (Python)   -> headers, cookies, TLS, robots, methods, spider, XSS/SQLi

Generates a REPORT.md with findings sorted by severity and a section of
suggested attack vectors.

LEGAL: use only against systems you are authorized to test (labs, HTB/THM,
CTFs, engagements with written permission). Unauthorized use is illegal.

Examples:
    python3 vulnscan.py 10.10.10.10
    python3 vulnscan.py 10.10.10.10 --full
    python3 vulnscan.py http://target.com --spider --sqli --fuzz
    python3 vulnscan.py target.com --subdomains --dns
    python3 vulnscan.py 10.10.10.0/24 --ports-full
"""

import argparse
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


# ============================================================================
# Colors and output helpers
# ============================================================================
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; MAGENTA = "\033[95m"; GRAY = "\033[90m"


def info(m): print(f"{C.CYAN}[*]{C.RESET} {m}")
def ok(m):   print(f"{C.GREEN}[+]{C.RESET} {m}")
def warn(m): print(f"{C.YELLOW}[!]{C.RESET} {m}")
def err(m):  print(f"{C.RED}[-]{C.RESET} {m}")
def vuln(m): print(f"{C.RED}{C.BOLD}[VULN]{C.RESET} {m}")


def phase(title):
    print(f"\n{C.BOLD}{C.BLUE}{'=' * 66}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}  {title}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'=' * 66}{C.RESET}")


BANNER = rf"""{C.CYAN}
 __     ___   _ _    _   _ ____   ____    _    _   _
 \ \   / / | | | |  | \ | / ___| / ___|  / \  | \ | |
  \ \ / /| | | | |  |  \| \___ \| |     / _ \ |  \| |
   \ V / | |_| | |__| |\  |___) | |___ / ___ \| |\  |
    \_/   \___/|____|_| \_|____/ \____/_/   \_\_| \_|
{C.RESET}{C.GRAY}   security auditor: network · web · smb · dns  ·  hacking-vault{C.RESET}
"""


# ============================================================================
# Findings and attack-vector suggestions
# ============================================================================
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {
    "critical": C.MAGENTA, "high": C.RED, "medium": C.YELLOW,
    "low": C.CYAN, "info": C.GRAY,
}
FINDINGS    = []   # {"sev", "title", "detail", "host"}
SUGGESTIONS = []   # suggested attack vectors (plain text)


def add_finding(sev, title, detail="", host=""):
    sev = sev if sev in SEVERITIES else "info"
    FINDINGS.append({"sev": sev, "title": title, "detail": detail, "host": host})
    tag  = sev.upper().ljust(8)
    line = f"{SEV_COLOR[sev]}[{tag}]{C.RESET} {title}"
    if detail:
        line += f"  {C.GRAY}{detail}{C.RESET}"
    print("    " + line)


def add_suggestion(text):
    if text not in SUGGESTIONS:
        SUGGESTIONS.append(text)


# ============================================================================
# Execution helpers
# ============================================================================
def tool_exists(name):
    return shutil.which(name) is not None


def first_tool(*names):
    """Return the first available binary from a list (e.g. netexec/nxc)."""
    for n in names:
        if tool_exists(n):
            return n
    return None


def run(cmd, logfile=None, timeout=None):
    """Run an external command, stream its output live, and optionally save it."""
    print(f"{C.GRAY}    $ {' '.join(cmd)}{C.RESET}")
    lines = []
    proc  = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            sys.stdout.write(f"{C.GRAY}    {line}{C.RESET}")
            lines.append(line)
        proc.wait(timeout=timeout)
    except FileNotFoundError:
        err(f"Binary not found: {cmd[0]}")
        return 127, ""
    except subprocess.TimeoutExpired:
        proc.kill()
        warn(f"Timed out: {cmd[0]}")
    output = "".join(lines)
    if logfile:
        with open(logfile, "w", encoding="utf-8", errors="replace") as f:
            f.write(output)
    return (proc.returncode if proc else 1), output


# ============================================================================
# Target classification
# ============================================================================
def classify_target(raw):
    """
    Returns (kind, host, url) where:
      kind = 'cidr' | 'ip' | 'domain' | 'url'
      host = IP or hostname for nmap
      url  = base URL for web phases, or None
    """
    raw = raw.strip()
    if re.match(r"^https?://", raw):
        host = urlparse(raw).netloc.split(":")[0]
        return "url", host, raw.rstrip("/")
    try:
        ipaddress.ip_network(raw, strict=False)
        return ("cidr" if "/" in raw else "ip"), raw, None
    except ValueError:
        return "domain", raw, None


def make_session(headers=None, cookie=None):
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": "Mozilla/5.0 (vulnscan; authorized pentest)"})
    if headers:
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                s.headers[k.strip()] = v.strip()
    if cookie:
        s.headers["Cookie"] = cookie
    return s


# ============================================================================
# PHASE: DNS (dig) — domains only
# ============================================================================
def dns_recon(domain, outdir):
    """DNS records and zone transfer check (AXFR)."""
    phase("DNS - records and zone transfer (dig)")
    if not tool_exists("dig"):
        warn("dig not found (install bind-tools); skipping DNS recon.")
        return
    log = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        code, out = run(["dig", "+short", rtype, domain])
        if out.strip():
            log.append(f"== {rtype} ==\n{out.strip()}")
            add_finding("info", f"DNS {rtype}", out.strip().replace("\n", " "))
    _, ns_out = run(["dig", "+short", "NS", domain])
    for ns in [n.strip(".") for n in ns_out.split() if n.strip()]:
        code, axfr = run(["dig", "AXFR", f"@{ns}", domain])
        log.append(f"== AXFR @{ns} ==\n{axfr}")
        if "Transfer failed" not in axfr and re.search(r"\bIN\b.*\b(A|CNAME|MX)\b", axfr):
            vuln(f"Zone transfer allowed on {ns}!")
            add_finding("high", "DNS zone transfer (AXFR) allowed", ns)
            add_suggestion(
                f"AXFR open on {ns}: dump all records with "
                f"'dig AXFR @{ns} {domain}'."
            )
    with open(os.path.join(outdir, "dns.txt"), "w", encoding="utf-8") as f:
        f.write("\n\n".join(log))


# ============================================================================
# PHASE: Subdomains (subfinder) — domains only
# ============================================================================
def enum_subdomains(domain, outdir):
    """Enumerate subdomains and probe live ones with httpx."""
    phase("Subdomains (subfinder + httpx)")
    if not tool_exists("subfinder"):
        warn("subfinder not found; skipping subdomain enumeration.")
        return []
    subs = os.path.join(outdir, "subdomains.txt")
    run(["subfinder", "-d", domain, "-silent", "-o", subs])
    if not os.path.exists(subs) or os.path.getsize(subs) == 0:
        warn("subfinder returned no results.")
        return []
    n = sum(1 for _ in open(subs, encoding="utf-8", errors="replace"))
    add_finding("info", f"{n} subdomains found", "see subdomains.txt")
    live = []
    if tool_exists("httpx"):
        live_file = os.path.join(outdir, "subdomains_live.txt")
        run(["httpx", "-l", subs, "-silent", "-o", live_file])
        if os.path.exists(live_file):
            live = [l.strip() for l in open(live_file, encoding="utf-8",
                    errors="replace") if l.strip()]
            if live:
                add_finding("info", f"{len(live)} live web subdomains",
                            "; ".join(live[:5]))
    return live


# ============================================================================
# PHASE: nmap (ports, services, optional vuln scripts)
# ============================================================================
WEB_KEYWORDS = ("http", "https", "ssl", "https-alt", "http-proxy", "http-alt")
WEB_PORTS    = {80, 443, 8080, 8443, 8000, 8888, 8008, 9443, 3000, 5000}
SMB_PORTS    = {139, 445}


def run_nmap(target, outdir, full=False, vuln_scripts=False):
    """Two-stage scan: fast port discovery, then -sV -sC on open ports only."""
    phase("NETWORK - port and service scan (nmap)")
    if not tool_exists("nmap"):
        err("nmap not found — it is the core phase. Install with: sudo pacman -S nmap")
        return {}

    disc_xml  = os.path.join(outdir, "nmap_discovery.xml")
    port_spec = ["-p-"] if full else ["--top-ports", "1000"]
    info("Discovering open ports...")
    run(["nmap"] + port_spec + ["-T4", "--min-rate", "2000", "-oX", disc_xml, target],
        logfile=os.path.join(outdir, "nmap_discovery.txt"))

    open_ports = ports_from_xml(disc_xml)
    if not open_ports:
        warn("No open ports found.")
        return {}
    ports_csv = ",".join(str(p) for p in sorted(open_ports))
    ok(f"Open ports: {ports_csv}")

    det_xml = os.path.join(outdir, "nmap_detailed.xml")
    info("Detailed scan (-sV -sC) on open ports...")
    run(["nmap", "-sV", "-sC", "-p", ports_csv, "-oX", det_xml,
         "-oN", os.path.join(outdir, "nmap_detailed.txt"), target])
    hosts = parse_nmap_hosts(det_xml)

    for ip, services in hosts.items():
        for s in services:
            extra = f"{s['product']} {s['version']}".strip()
            add_finding("info", f"Open port {s['port']}/{s['proto']} {s['service']}",
                        extra, host=ip)

    if vuln_scripts:
        phase("NETWORK - nmap vuln scripts (--script vuln)")
        vuln_out = os.path.join(outdir, "nmap_vuln.txt")
        run(["nmap", "--script", "vuln", "-p", ports_csv, "-oN", vuln_out, target])
        parse_nmap_vuln(vuln_out, target)
    return hosts


def ports_from_xml(xml_path):
    ports = set()
    if not xml_path or not os.path.exists(xml_path):
        return ports
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return ports
    for port in root.iter("port"):
        st = port.find("state")
        if st is not None and st.get("state") == "open":
            ports.add(int(port.get("portid")))
    return ports


def parse_nmap_hosts(xml_path):
    """Return {ip: [services]} with per-port metadata."""
    hosts = {}
    if not xml_path or not os.path.exists(xml_path):
        return hosts
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError:
        return hosts
    for host in root.iter("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip       = addr.get("addr")
        services = []
        for port in host.iter("port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            pid    = int(port.get("portid"))
            svc    = port.find("service")
            name   = svc.get("name",    "") if svc is not None else ""
            tunnel = svc.get("tunnel",  "") if svc is not None else ""
            is_web = any(k in name for k in WEB_KEYWORDS) or pid in WEB_PORTS
            scheme = "https" if (tunnel == "ssl" or "https" in name
                                 or pid in {443, 8443, 9443}) else "http"
            services.append({
                "port":    pid,
                "proto":   port.get("protocol", "tcp"),
                "service": name,
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "is_web":  is_web,
                "scheme":  scheme,
            })
        if services:
            hosts[ip] = services
    return hosts


def parse_nmap_vuln(path, host):
    """Register each vulnerable line from --script vuln output as a finding."""
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.strip()
        if "VULNERABLE" in s.upper():
            add_finding("high", "nmap vuln script hit", s, host=host)
            add_suggestion(f"Review nmap vuln finding on {host}: {s}")
        elif re.search(r"CVE-\d{4}-\d+", s):
            add_finding("medium", "nmap: CVE detected", s, host=host)


# ============================================================================
# PHASE: SMB / Windows (enum4linux, smbclient, netexec)
# ============================================================================
def audit_smb(host, outdir):
    """Enumerate SMB services for information leakage and null sessions."""
    phase(f"SMB / WINDOWS - enumeration ({host})")
    add_suggestion(
        f"SMB open on {host}: enumerate users/shares and test "
        "null sessions and default credentials."
    )

    nxc = first_tool("netexec", "nxc")
    if nxc:
        info("netexec: host info and shares (null session)...")
        code, out = run([nxc, "smb", host, "-u", "", "-p", "", "--shares"],
                        logfile=os.path.join(outdir, f"netexec_{host}.txt"))
        if re.search(r"READ|WRITE", out):
            add_finding("medium", "SMB shares accessible via null session", host=host)
        m = re.search(r"\(domain:([^)]+)\)", out)
        if m:
            add_finding("info", "SMB domain", m.group(1).strip(), host=host)
        if re.search(r"signing:False", out):
            add_finding("medium", "SMB signing disabled (relay risk)", host=host)
            add_suggestion(
                f"SMB signing OFF on {host}: NTLM relay attack possible "
                "with responder + ntlmrelayx."
            )
    else:
        warn("netexec/nxc not found.")

    if tool_exists("smbclient"):
        info("smbclient: listing shares (null session)...")
        run(["smbclient", "-L", f"//{host}/", "-N"],
            logfile=os.path.join(outdir, f"smbclient_{host}.txt"))

    if tool_exists("enum4linux"):
        info("enum4linux: full enumeration...")
        run(["enum4linux", "-a", host],
            logfile=os.path.join(outdir, f"enum4linux_{host}.txt"))
    else:
        warn("enum4linux not found.")


# ============================================================================
# PHASE: Web — fingerprint, headers, TLS, spider, injections, ffuf, sqlmap
# ============================================================================
SECURITY_HEADERS = {
    "Content-Security-Policy":   ("medium", "Missing CSP (mitigates XSS/injection)"),
    "Strict-Transport-Security": ("medium", "Missing HSTS (enforces HTTPS)"),
    "X-Frame-Options":           ("low",    "Missing X-Frame-Options (clickjacking risk)"),
    "X-Content-Type-Options":    ("low",    "Missing X-Content-Type-Options (MIME sniffing)"),
    "Referrer-Policy":           ("info",   "Missing Referrer-Policy"),
    "Permissions-Policy":        ("info",   "Missing Permissions-Policy"),
}
XSS_PAYLOAD = "vsx<svg/onload=alert(1)>"
SQL_ERRORS  = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|"
    r"Microsoft OLE DB|Unclosed quotation mark|Warning.*\Wmysqli?_)",
    re.IGNORECASE,
)


def recon_httpx(url, outdir):
    if not tool_exists("httpx"):
        return
    out = os.path.join(outdir, "httpx.txt")
    code, output = run(["httpx", "-u", url, "-silent", "-title", "-status-code",
                        "-tech-detect", "-web-server", "-o", out])
    for line in output.strip().splitlines():
        if line.strip():
            add_finding("info", "Web fingerprint", line.strip())


def web_check_headers(url, session):
    try:
        r = session.get(url, timeout=15, allow_redirects=True)
    except Exception as e:
        err(f"Could not connect to {url}: {e}")
        return
    if r.headers.get("X-Powered-By"):
        add_finding("low", "X-Powered-By exposes technology stack",
                    r.headers["X-Powered-By"])
    for header, (sev, msg) in SECURITY_HEADERS.items():
        if header not in r.headers:
            add_finding(sev, msg)
    for c in r.cookies:
        problems = []
        if not c.secure:
            problems.append("missing Secure flag")
        if not c.has_nonstandard_attr("HttpOnly"):
            problems.append("missing HttpOnly flag")
        if problems:
            add_finding("low", f"Insecure cookie '{c.name}'", ", ".join(problems))


def web_check_ssl(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert  = ssock.getpeercert()
                proto = ssock.version()
        add_finding("info", f"TLS negotiated: {proto}")
        if cert and "notAfter" in cert:
            add_finding("info", "Certificate valid until", cert["notAfter"])
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            add_finding("medium", f"Obsolete TLS protocol: {proto}")
    except Exception:
        pass


def web_check_robots_methods(url, session):
    base = "{0.scheme}://{0.netloc}".format(urlparse(url))
    for path in ("robots.txt", "sitemap.xml"):
        try:
            r = session.get(f"{base}/{path}", timeout=10)
            if r.status_code == 200 and r.text.strip():
                add_finding("info", f"{path} found",
                            f"{len(r.text.splitlines())} lines")
        except Exception:
            pass
    try:
        r     = session.request("OPTIONS", url, timeout=10)
        allow = r.headers.get("Allow", "")
        if allow:
            add_finding("info", "HTTP methods allowed", allow)
        risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT")
                 if m in allow.upper()]
        if risky:
            add_finding("medium", "Dangerous HTTP methods enabled",
                        ", ".join(risky))
    except Exception:
        pass


def web_spider(start_url, session, max_pages=80, max_depth=2):
    base_netloc = urlparse(start_url).netloc
    visited, queue = set(), [(start_url, 0)]
    param_urls, forms = set(), []
    while queue and len(visited) < max_pages:
        url, depth = queue.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        try:
            r = session.get(url, timeout=10)
        except Exception:
            continue
        if "text/html" not in r.headers.get("Content-Type", ""):
            continue
        if urlparse(url).query:
            param_urls.add(url)
        links, page_forms = _extract_links_forms(r.text, url)
        for link in links:
            if urlparse(link).netloc == base_netloc and link not in visited:
                queue.append((link, depth + 1))
        forms.extend(page_forms)
    ok(f"{len(visited)} pages crawled, {len(param_urls)} with parameters, "
       f"{len(forms)} forms found.")
    if param_urls:
        add_finding("info", f"{len(param_urls)} URLs with parameters found",
                    "; ".join(list(param_urls)[:5]))
    return param_urls


def _extract_links_forms(html_text, base_url):
    links, forms = set(), []
    if HAS_BS4:
        soup = BeautifulSoup(html_text, "html.parser")
        for a in soup.find_all("a", href=True):
            links.add(urljoin(base_url, a["href"]))
        for form in soup.find_all("form"):
            inputs = [i.get("name") for i in
                      form.find_all(["input", "textarea", "select"])
                      if i.get("name")]
            forms.append({
                "action": urljoin(base_url, form.get("action", base_url)),
                "method": form.get("method", "get").lower(),
                "inputs": inputs,
            })
    else:
        for href in re.findall(r'href=["\']([^"\']+)["\']', html_text):
            links.add(urljoin(base_url, href))
    return links, forms


def web_test_injections(param_urls, session):
    if not param_urls:
        info("No GET parameters to test (use --spider to discover more).")
        return
    for url in param_urls:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            _test_xss(parsed, params, param, session)
            _test_sqli(parsed, params, param, session)


def _build_url(parsed, params, param, value):
    new = {k: v[0] for k, v in params.items()}
    new[param] = value
    return urlunparse(parsed._replace(query=urlencode(new)))


def _test_xss(parsed, params, param, session):
    test_url = _build_url(parsed, params, param, XSS_PAYLOAD)
    try:
        r = session.get(test_url, timeout=10)
    except Exception:
        return
    if XSS_PAYLOAD in r.text:
        vuln(f"Possible reflected XSS in parameter '{param}'")
        add_finding("high", f"Reflected XSS in parameter '{param}'", test_url)
        add_suggestion(f"Confirm XSS at {test_url} and craft a PoC payload.")


def _test_sqli(parsed, params, param, session):
    test_url = _build_url(parsed, params, param, params[param][0] + "'")
    try:
        r = session.get(test_url, timeout=10)
    except Exception:
        return
    if SQL_ERRORS.search(r.text):
        vuln(f"SQL error triggered by quote injection in '{param}'")
        add_finding("high", f"Possible SQLi (error-based) in '{param}'", test_url)
        add_suggestion(f"Run sqlmap on {test_url} (or use --sqli flag).")


def run_sqlmap(param_urls, outdir, cookie=None):
    phase("WEB - automated SQL injection (sqlmap)")
    if not tool_exists("sqlmap"):
        warn("sqlmap not found; skipping.")
        return
    if not param_urls:
        info("No parameter URLs for sqlmap.")
        return
    for url in list(param_urls)[:5]:
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "2", "--risk", "1",
               "--output-dir", os.path.join(outdir, "sqlmap")]
        if cookie:
            cmd += ["--cookie", cookie]
        code, output = run(cmd)
        if re.search(r"is vulnerable|parameter.*injectable", output, re.IGNORECASE):
            vuln("sqlmap confirmed injection!")
            add_finding("critical", "SQLi confirmed by sqlmap", url)
            add_suggestion(f"sqlmap confirmed SQLi on {url}: extract data with --dump.")


def run_ffuf(url, outdir, wordlist, idx=0):
    if not tool_exists("ffuf"):
        warn("ffuf not found; skipping directory fuzzing.")
        return
    if not os.path.exists(wordlist):
        warn(f"Wordlist not found: {wordlist}")
        return
    out = os.path.join(outdir, f"ffuf_{idx}.json")
    run(["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
         "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", out, "-s"])
    if os.path.exists(out):
        try:
            data = json.load(open(out, encoding="utf-8"))
            for res in data.get("results", []):
                add_finding("info", f"Path found ({res.get('status')})",
                            res.get("url", ""))
        except (json.JSONDecodeError, ValueError):
            pass


def audit_web(url, session, outdir, args, idx=0):
    """Full web audit pipeline for a single URL."""
    phase(f"WEB - auditing {url}")
    host = urlparse(url).netloc.split(":")[0]
    recon_httpx(url, outdir)
    if session:
        web_check_headers(url, session)
        if url.startswith("https"):
            port = urlparse(url).port or 443
            web_check_ssl(host, port)
        web_check_robots_methods(url, session)
        param_urls = set()
        if args.spider or args.full:
            param_urls = web_spider(url, session)
        if urlparse(url).query:
            param_urls.add(url)
        web_test_injections(param_urls, session)
        if (args.sqli or args.full) and param_urls:
            run_sqlmap(param_urls, outdir, cookie=args.cookie)
    if args.fuzz or args.full:
        run_ffuf(url, outdir, args.wordlist, idx)
    return url


# ============================================================================
# PHASE: nuclei (all live web URLs)
# ============================================================================
def run_nuclei(urls, outdir, severity=None):
    phase("VULNS - template-based vulnerability scan (nuclei)")
    if not tool_exists("nuclei"):
        warn("nuclei not found; skipping.")
        return
    if not urls:
        info("No web URLs for nuclei.")
        return
    list_file = os.path.join(outdir, "_nuclei_targets.txt")
    with open(list_file, "w", encoding="utf-8") as f:
        f.write("\n".join(urls))
    out = os.path.join(outdir, "nuclei.txt")
    cmd = ["nuclei", "-l", list_file, "-o", out, "-stats"]
    if severity:
        cmd += ["-severity", severity]
    run(cmd)
    if os.path.exists(out):
        for line in open(out, encoding="utf-8", errors="replace"):
            line = line.strip()
            if not line:
                continue
            sev = next((s for s in SEVERITIES if f"[{s}]" in line.lower()), "info")
            add_finding(sev, "nuclei", line)


# ============================================================================
# PHASE: brute-force (hydra) — opt-in
# ============================================================================
DEFAULT_USERS  = ["root", "admin", "administrator", "user", "test"]
DEFAULT_PASSES = ["admin", "password", "123456", "root", "toor", "test", "letmein"]


def run_hydra(host, services, outdir, userlist=None, passlist=None):
    """Light SSH/FTP brute-force (opt-in, noisy — use only in authorized labs)."""
    phase(f"BRUTE-FORCE - hydra ({host})")
    if not tool_exists("hydra"):
        warn("hydra not found; skipping.")
        return
    warn("Noisy phase: use only with authorization and in lab environments.")
    if not userlist:
        userlist = os.path.join(outdir, "_users.txt")
        open(userlist, "w").write("\n".join(DEFAULT_USERS))
    if not passlist:
        passlist = os.path.join(outdir, "_pass.txt")
        open(passlist, "w").write("\n".join(DEFAULT_PASSES))
    targets = {s["service"]: s["port"] for s in services
               if s["service"] in ("ssh", "ftp")}
    if not targets:
        info("No SSH/FTP services found for brute-force.")
        return
    for service, port in targets.items():
        info(f"hydra against {service}://{host}:{port}")
        code, out = run([
            "hydra", "-L", userlist, "-P", passlist, "-t", "4", "-f",
            "-o", os.path.join(outdir, f"hydra_{service}_{host}.txt"),
            "-s", str(port), host, service,
        ])
        for m in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", out):
            vuln(f"Valid {service} credentials: {m.group(1)}:{m.group(2)}")
            add_finding("critical", f"Valid {service} credentials",
                        f"{m.group(1)}:{m.group(2)}", host=host)
            add_suggestion(
                f"Log in via {service} to {host} with "
                f"{m.group(1)}:{m.group(2)}."
            )


# ============================================================================
# Report and final summary
# ============================================================================
def write_report(outdir, target, started):
    """Write REPORT.md with findings sorted by severity."""
    counts = {s: 0 for s in SEVERITIES}
    for f in FINDINGS:
        counts[f["sev"]] += 1

    lines = [
        f"# Vulnerability Report - {target}", "",
        f"- **Date:** {started:%Y-%m-%d %H:%M:%S}",
        f"- **Duration:** {(datetime.now() - started).seconds}s",
        f"- **Output folder:** `{outdir}`", "",
        "## Summary by severity", "",
        "| Severity | Findings |", "|----------|----------|",
    ]
    for s in SEVERITIES:
        lines.append(f"| {s} | {counts[s]} |")
    lines.append("")

    if SUGGESTIONS:
        lines += ["## Suggested attack vectors", ""]
        for sug in SUGGESTIONS:
            lines.append(f"- {sug}")
        lines.append("")

    for s in SEVERITIES:
        items = [f for f in FINDINGS if f["sev"] == s]
        if not items:
            continue
        lines.append(f"## {s.upper()} ({len(items)})")
        lines.append("")
        for f in items:
            host_tag = f" _(host: {f['host']})_" if f["host"] else ""
            detail   = f"  \n  `{f['detail']}`" if f["detail"] else ""
            lines.append(f"- **{f['title']}**{host_tag}{detail}")
        lines.append("")

    lines += ["## Generated files", ""]
    for f in sorted(os.listdir(outdir)):
        if not f.startswith("_"):
            lines.append(f"- `{f}`")

    report = os.path.join(outdir, "REPORT.md")
    with open(report, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return report, counts


def print_summary(target, report, counts, started):
    """Print a visual vulnerability summary to the console."""
    duration = (datetime.now() - started).seconds
    phase("SCAN SUMMARY")

    # ── Header ────────────────────────────────────────────────────────────────
    print(f"  {'Target':<12}: {C.BOLD}{target}{C.RESET}")
    print(f"  {'Duration':<12}: {duration}s")
    print(f"  {'Report':<12}: {C.BOLD}{report}{C.RESET}")
    print()

    # ── Severity table with bar chart ─────────────────────────────────────────
    total = sum(counts.values())
    print(f"  {C.BOLD}{'Severity':<12}  {'Count':>5}  Bar{C.RESET}")
    print(f"  {'-'*12}  {'-'*5}  {'-'*32}")
    for s in SEVERITIES:
        n     = counts[s]
        color = SEV_COLOR[s]
        bar   = color + "#" * min(n, 32) + C.RESET if n else C.GRAY + "-" + C.RESET
        print(f"  {color}{s.upper():<12}{C.RESET}  {n:>5}  {bar}")
    print(f"  {'-'*12}  {'-'*5}")
    print(f"  {'TOTAL':<12}  {total:>5}")
    print()

    # ── Findings by severity (skip info to avoid flooding the screen) ─────────
    shown_sevs = [s for s in ("critical", "high", "medium", "low") if counts[s] > 0]
    for sev in shown_sevs:
        items = [f for f in FINDINGS if f["sev"] == sev]
        color = SEV_COLOR[sev]
        tag   = sev.upper()
        print(f"  {color}{C.BOLD}[{tag}] — {len(items)} finding(s){C.RESET}")
        print(f"  {color}{'-' * 50}{C.RESET}")
        for finding in items:
            host_tag = f" {C.GRAY}[{finding['host']}]{C.RESET}" if finding["host"] else ""
            print(f"  {color}>{C.RESET} {C.BOLD}{finding['title']}{C.RESET}{host_tag}")
            if finding["detail"]:
                # Wrap long details at 80 chars for readability
                detail = finding["detail"]
                while len(detail) > 80:
                    cut = detail[:80].rfind(" ")
                    cut = cut if cut > 40 else 80
                    print(f"    {C.GRAY}{detail[:cut]}{C.RESET}")
                    detail = detail[cut:].lstrip()
                if detail:
                    print(f"    {C.GRAY}{detail}{C.RESET}")
        print()

    # Info count (shown as a single line, not expanded)
    if counts["info"] > 0:
        print(f"  {C.GRAY}[INFO] {counts['info']} informational finding(s) — see {report}{C.RESET}")
        print()

    # ── Suggested attack vectors ──────────────────────────────────────────────
    if SUGGESTIONS:
        print(f"  {C.BOLD}{C.YELLOW}Attack vectors ({len(SUGGESTIONS)}):{C.RESET}")
        for i, s in enumerate(SUGGESTIONS, 1):
            # Wrap long suggestion lines
            prefix = f"  {C.YELLOW}{i:>2}.{C.RESET} "
            indent = "      "
            words, line = s.split(), ""
            first = True
            for word in words:
                if len(line) + len(word) + 1 > 72:
                    print((prefix if first else indent) + line.rstrip())
                    line, first = word + " ", False
                else:
                    line += word + " "
            if line.strip():
                print((prefix if first else indent) + line.rstrip())
        print()

    # ── Final verdict ─────────────────────────────────────────────────────────
    if counts["critical"] > 0:
        print(f"  {C.MAGENTA}{C.BOLD}[!] CRITICAL issues found — review the report immediately.{C.RESET}")
    elif counts["high"] > 0:
        print(f"  {C.RED}{C.BOLD}[!] HIGH severity issues found — prioritize remediation.{C.RESET}")
    elif counts["medium"] > 0:
        print(f"  {C.YELLOW}[!] Medium severity issues found — schedule remediation.{C.RESET}")
    else:
        print(f"  {C.GREEN}[+] No critical, high or medium findings.{C.RESET}")
    print()


# ============================================================================
# Tool availability check
# ============================================================================
TOOL_CATALOG = [
    ("nmap",       "Port and service scanner",                 "sudo pacman -S nmap"),
    ("dig",        "DNS records + zone transfer (AXFR)",       "sudo pacman -S bind-tools"),
    ("subfinder",  "Passive subdomain enumeration",            "sudo pacman -S subfinder"),
    ("httpx",      "Web fingerprint (tech, title, server)",    "sudo pacman -S httpx"),
    ("ffuf",       "Directory and path fuzzer",                "sudo pacman -S ffuf"),
    ("nuclei",     "Template-based vulnerability scanner",     "sudo pacman -S nuclei"),
    ("sqlmap",     "Automated SQL injection",                  "sudo pacman -S sqlmap"),
    ("netexec",    "SMB/AD enumeration (netexec)",             "sudo pacman -S netexec"),
    ("enum4linux", "SMB/Samba enumeration",                    "sudo pacman -S enum4linux"),
    ("smbclient",  "SMB/CIFS client",                         "sudo pacman -S smbclient"),
    ("hydra",      "SSH/FTP brute-force (opt-in)",             "sudo pacman -S hydra"),
]
PYLIB_CATALOG = [
    ("requests", "HTTP client for web checks"),
    ("bs4",      "HTML parser for the spider (beautifulsoup4)"),
]


def check_tools():
    """Print a table showing which tools are installed and which are missing."""
    print(BANNER)
    print(f"{C.BOLD}{C.BLUE}  Tool availability check{C.RESET}")
    print(f"{C.BLUE}  {'-' * 62}{C.RESET}\n")

    missing = []
    print(f"  {'Tool':<16} {'Status':<14} {'Description'}")
    print(f"  {'-'*16} {'-'*14} {'-'*34}")
    for binary, desc, install in TOOL_CATALOG:
        found = tool_exists(binary)
        icon  = (f"{C.GREEN}[OK]{C.RESET}           " if found
                 else f"{C.RED}[MISSING]{C.RESET}      ")
        print(f"  {C.BOLD}{binary:<16}{C.RESET} {icon} {C.GRAY}{desc}{C.RESET}")
        if not found:
            missing.append((binary, install))

    print(f"\n  {'Python lib':<16} {'Status':<14} {'Description'}")
    print(f"  {'-'*16} {'-'*14} {'-'*34}")
    for lib, desc in PYLIB_CATALOG:
        try:
            __import__(lib)
            found = True
        except ImportError:
            found = False
        icon = (f"{C.GREEN}[OK]{C.RESET}           " if found
                else f"{C.YELLOW}[OPTIONAL]{C.RESET}     ")
        print(f"  {C.BOLD}{lib:<16}{C.RESET} {icon} {C.GRAY}{desc}{C.RESET}")
        if not found:
            missing.append((lib, "wsvenva  # activate your workspace venv"))

    if missing:
        print(f"\n{C.YELLOW}  To install missing tools:{C.RESET}")
        for name, cmd in missing:
            print(f"    {C.GRAY}# {name}{C.RESET}")
            print(f"    {cmd}")
    else:
        print(f"\n{C.GREEN}  All tools installed. Ready to scan.{C.RESET}")
    print()


# ============================================================================
# Entry point
# ============================================================================
def main():
    p = argparse.ArgumentParser(
        description="Security auditor: network + web + SMB + DNS.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 vulnscan.py 10.10.10.10\n"
            "  python3 vulnscan.py 10.10.10.10 --full\n"
            "  python3 vulnscan.py http://target.com --spider --sqli --fuzz\n"
            "  python3 vulnscan.py target.com --subdomains --dns\n"
            "  python3 vulnscan.py --check-tools\n"
        ),
    )
    p.add_argument("target", nargs="?",
                   help="IP, CIDR range, domain or URL")
    p.add_argument("--check-tools", action="store_true",
                   help="Show which tools are installed and which are missing")
    p.add_argument("-o", "--output",
                   help="Output folder (default: reports/<host>_<timestamp>)")
    p.add_argument("--full", action="store_true",
                   help="Run all reasonable phases (excludes brute-force)")
    p.add_argument("--ports-full", action="store_true",
                   help="Scan all 65535 ports with nmap")
    p.add_argument("--vuln-scripts", action="store_true",
                   help="Run nmap --script vuln (known CVEs, slower)")
    p.add_argument("--dns", action="store_true",
                   help="DNS recon with dig (automatic for domains)")
    p.add_argument("--subdomains", action="store_true",
                   help="Enumerate subdomains with subfinder (domains only)")
    p.add_argument("--spider", action="store_true",
                   help="Crawl the web app to discover parameters and forms")
    p.add_argument("--sqli", action="store_true",
                   help="Automated SQL injection with sqlmap")
    p.add_argument("--fuzz", action="store_true",
                   help="Directory fuzzing with ffuf")
    p.add_argument("--smb", action="store_true",
                   help="Force SMB enumeration (auto if port 139/445 is open)")
    p.add_argument("--no-smb", action="store_true",
                   help="Skip SMB enumeration even if ports are open")
    p.add_argument("--bruteforce", action="store_true",
                   help="SSH/FTP brute-force with hydra (NOISY, opt-in)")
    p.add_argument("--no-nuclei", action="store_true",
                   help="Skip nuclei vulnerability scan")
    p.add_argument("--wordlist",
                   default="/usr/share/seclists/Discovery/Web-Content/common.txt",
                   help="Wordlist for directory fuzzing")
    p.add_argument("--userlist",
                   help="Username list for hydra")
    p.add_argument("--passlist",
                   help="Password list for hydra")
    p.add_argument("--severity",
                   help="Filter nuclei by severity (e.g. critical,high)")
    p.add_argument("--cookie",
                   help="Session cookie for authenticated web scanning")
    p.add_argument("-H", "--header", action="append",
                   help="Extra HTTP header 'Name: value' (repeatable)")
    args = p.parse_args()

    if args.check_tools:
        check_tools()
        sys.exit(0)

    if not args.target:
        p.error("Specify a target or use --check-tools to inspect installed tools.")

    print(BANNER)
    if not HAS_REQUESTS:
        warn("'requests' not found: web checks will be skipped. Activate venv: wsvenva")
    if not HAS_BS4:
        warn("'bs4' not found: spider will use regex (less accurate).")

    kind, host, url = classify_target(args.target)
    info(f"Target: {C.BOLD}{args.target}{C.RESET} ({kind})")

    # Output saved under reports/<host>_<timestamp>/
    stamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe   = re.sub(r"[^a-zA-Z0-9.]", "_", host)
    outdir = args.output or os.path.join("reports", f"{safe}_{stamp}")
    os.makedirs(outdir, exist_ok=True)
    ok(f"Output folder: {outdir}")

    started  = datetime.now()
    session  = make_session(args.header, args.cookie) if HAS_REQUESTS else None
    web_urls = []

    # DNS and subdomains (domains only)
    if kind == "domain":
        if args.dns or args.full:
            dns_recon(host, outdir)
        if args.subdomains or args.full:
            web_urls += enum_subdomains(host, outdir)

    # Network scan
    nmap_target = host if kind in ("domain", "url") else args.target
    hosts = run_nmap(nmap_target, outdir, full=args.ports_full,
                     vuln_scripts=args.vuln_scripts)

    # Per-host service enumeration
    for ip, services in hosts.items():
        smb_open = any(s["port"] in SMB_PORTS for s in services)
        if smb_open and not args.no_smb:
            audit_smb(ip, outdir)
        for s in services:
            if s["is_web"]:
                web_urls.append(f"{s['scheme']}://{ip}:{s['port']}")

    # If target was a URL or domain, always include it as a web target
    if url:
        web_urls.insert(0, url)
    elif kind == "domain" and not web_urls:
        web_urls += [f"http://{host}", f"https://{host}"]
    web_urls = list(dict.fromkeys(web_urls))  # deduplicate, preserve order

    # Web audit per URL
    for i, wurl in enumerate(web_urls):
        audit_web(wurl, session, outdir, args, idx=i)

    # Nuclei across all web targets
    if web_urls and not args.no_nuclei:
        run_nuclei(web_urls, outdir, severity=args.severity)

    # Brute-force (opt-in)
    if args.bruteforce:
        for ip, services in hosts.items():
            run_hydra(ip, services, outdir, args.userlist, args.passlist)

    # Final report + visual summary
    report, counts = write_report(outdir, args.target, started)
    print_summary(args.target, report, counts, started)
    ok(f"Scan complete. Results saved to: {C.BOLD}{outdir}{C.RESET}")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrupted by user.{C.RESET}")
        sys.exit(130)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vulnscan.py - Auditor de seguridad por consola (red + web + SMB/AD + DNS).

Orquesta las herramientas que ya tienes en tu entorno archpwm para hacer una
auditoria completa de un objetivo: descubrimiento, enumeracion, deteccion de
vulnerabilidades y "puntos de ataque" sugeridos, todo en un reporte final.

Herramientas que usa (todas instaladas en archpwm; cada fase se omite sola si
falta su herramienta):

    dig        -> registros DNS y transferencia de zona (AXFR)        [dominios]
    subfinder  -> enumeracion de subdominios                          [dominios]
    nmap       -> puertos, servicios y (opcional) scripts de vulns
    httpx      -> fingerprint web (tecnologia, titulo, servidor)
    ffuf       -> fuzzing de directorios web
    nuclei     -> vulnerabilidades web con plantillas
    sqlmap     -> SQLi automatizada sobre parametros
    enum4linux / smbclient / netexec -> enumeracion SMB / Windows
    hydra      -> fuerza bruta de login SSH/FTP                        [opt-in]
    (Python)   -> cabeceras, cookies, TLS, robots, metodos, spider, XSS/SQLi basico

Genera un REPORTE.md con los hallazgos ordenados por severidad y una seccion de
vectores de ataque sugeridos.

USO LEGAL: solo contra sistemas con autorizacion explicita (labs, HTB/THM, CTFs,
engagements con permiso). El uso no autorizado es ilegal.

Ejemplos:
    python3 vulnscan.py 10.10.10.10                 # auditoria por defecto
    python3 vulnscan.py 10.10.10.10 --full          # todo lo razonable
    python3 vulnscan.py http://objetivo.com --spider --sqli --fuzz
    python3 vulnscan.py objetivo.com --subdomains --dns
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
# Colores y mensajes
# ============================================================================
class C:
    RESET = "\033[0m"; BOLD = "\033[1m"
    RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"
    BLUE = "\033[94m"; CYAN = "\033[96m"; MAGENTA = "\033[95m"; GRAY = "\033[90m"


def info(m): print(f"{C.CYAN}[*]{C.RESET} {m}")
def ok(m): print(f"{C.GREEN}[+]{C.RESET} {m}")
def warn(m): print(f"{C.YELLOW}[!]{C.RESET} {m}")
def err(m): print(f"{C.RED}[-]{C.RESET} {m}")
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
{C.RESET}{C.GRAY}   auditor de seguridad: red · web · smb · dns  ·  hacking-vault{C.RESET}
"""


# ============================================================================
# Hallazgos y sugerencias para el reporte
# ============================================================================
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_COLOR = {"critical": C.MAGENTA, "high": C.RED, "medium": C.YELLOW,
             "low": C.CYAN, "info": C.GRAY}
FINDINGS = []      # {"sev", "title", "detail", "host"}
SUGGESTIONS = []   # vectores de ataque sugeridos (texto)


def add_finding(sev, title, detail="", host=""):
    sev = sev if sev in SEVERITIES else "info"
    FINDINGS.append({"sev": sev, "title": title, "detail": detail, "host": host})
    tag = sev.upper().ljust(8)
    line = f"{SEV_COLOR[sev]}[{tag}]{C.RESET} {title}"
    if detail:
        line += f"  {C.GRAY}{detail}{C.RESET}"
    print("    " + line)


def add_suggestion(text):
    if text not in SUGGESTIONS:
        SUGGESTIONS.append(text)


# ============================================================================
# Utilidades de ejecucion
# ============================================================================
def tool_exists(name):
    return shutil.which(name) is not None


def first_tool(*names):
    """Devuelve el primer binario disponible de una lista (p.ej. netexec/nxc)."""
    for n in names:
        if tool_exists(n):
            return n
    return None


def run(cmd, logfile=None, timeout=None):
    """Ejecuta un comando externo mostrando su salida en vivo y guardandola."""
    print(f"{C.GRAY}    $ {' '.join(cmd)}{C.RESET}")
    lines = []
    proc = None
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in proc.stdout:
            sys.stdout.write(f"{C.GRAY}    {line}{C.RESET}")
            lines.append(line)
        proc.wait(timeout=timeout)
    except FileNotFoundError:
        err(f"No se encontro el binario: {cmd[0]}")
        return 127, ""
    except subprocess.TimeoutExpired:
        proc.kill()
        warn(f"Tiempo agotado: {cmd[0]}")
    output = "".join(lines)
    if logfile:
        with open(logfile, "w", encoding="utf-8", errors="replace") as f:
            f.write(output)
    return (proc.returncode if proc else 1), output


# ============================================================================
# Clasificacion del objetivo
# ============================================================================
def classify_target(raw):
    """
    Devuelve (kind, host, url) donde:
      kind  = 'cidr' | 'ip' | 'domain' | 'url'
      host  = IP o nombre de host para nmap
      url   = URL base si aplica (web), o None
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


def normalize_url(target):
    target = target.strip()
    if not re.match(r"^https?://", target):
        target = "http://" + target
    return target.rstrip("/")


def make_session(headers=None, cookie=None):
    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": "Mozilla/5.0 (vulnscan; pentest autorizado)"})
    if headers:
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                s.headers[k.strip()] = v.strip()
    if cookie:
        s.headers["Cookie"] = cookie
    return s


# ============================================================================
# FASE: DNS (dig) - solo dominios
# ============================================================================
def dns_recon(domain, outdir):
    """Registros DNS y comprobacion de transferencia de zona (AXFR)."""
    phase("DNS - registros y transferencia de zona (dig)")
    if not tool_exists("dig"):
        warn("dig no esta instalado (bind-tools); se omite el recon DNS.")
        return
    log = []
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "SOA"):
        code, out = run(["dig", "+short", rtype, domain])
        if out.strip():
            log.append(f"== {rtype} ==\n{out.strip()}")
            add_finding("info", f"DNS {rtype}", out.strip().replace("\n", " "))
    # Transferencia de zona en cada NS.
    _, ns_out = run(["dig", "+short", "NS", domain])
    for ns in [n.strip(".") for n in ns_out.split() if n.strip()]:
        code, axfr = run(["dig", "AXFR", f"@{ns}", domain])
        log.append(f"== AXFR @{ns} ==\n{axfr}")
        if "Transfer failed" not in axfr and re.search(r"\bIN\b.*\b(A|CNAME|MX)\b", axfr):
            vuln(f"Transferencia de zona permitida en {ns}!")
            add_finding("high", "Transferencia de zona DNS (AXFR) permitida", ns)
            add_suggestion(f"AXFR abierto en {ns}: extrae todos los registros con "
                           f"'dig AXFR @{ns} {domain}'.")
    with open(os.path.join(outdir, "dns.txt"), "w", encoding="utf-8") as f:
        f.write("\n\n".join(log))


# ============================================================================
# FASE: subdominios (subfinder) - solo dominios
# ============================================================================
def enum_subdomains(domain, outdir):
    """Enumera subdominios y, con httpx, detecta cuales estan vivos."""
    phase("Subdominios (subfinder + httpx)")
    if not tool_exists("subfinder"):
        warn("subfinder no esta instalado; se omite.")
        return []
    subs = os.path.join(outdir, "subdominios.txt")
    run(["subfinder", "-d", domain, "-silent", "-o", subs])
    if not os.path.exists(subs) or os.path.getsize(subs) == 0:
        warn("subfinder no devolvio resultados.")
        return []
    n = sum(1 for _ in open(subs, encoding="utf-8", errors="replace"))
    add_finding("info", f"{n} subdominios encontrados", f"ver subdominios.txt")

    live = []
    if tool_exists("httpx"):
        live_file = os.path.join(outdir, "subdominios_vivos.txt")
        run(["httpx", "-l", subs, "-silent", "-o", live_file])
        if os.path.exists(live_file):
            live = [l.strip() for l in open(live_file, encoding="utf-8",
                    errors="replace") if l.strip()]
            if live:
                add_finding("info", f"{len(live)} subdominios web vivos",
                            "; ".join(live[:5]))
    return live


# ============================================================================
# FASE: nmap (puertos, servicios y scripts de vulnerabilidades)
# ============================================================================
WEB_KEYWORDS = ("http", "https", "ssl", "https-alt", "http-proxy", "http-alt")
WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 8008, 9443, 3000, 5000}
SMB_PORTS = {139, 445}


def run_nmap(target, outdir, full=False, vuln_scripts=False):
    """Dos etapas: descubrir puertos abiertos y luego -sV -sC sobre ellos."""
    phase("RED - escaneo de puertos y servicios (nmap)")
    if not tool_exists("nmap"):
        err("nmap no esta instalado; es la fase central. Instala con: sudo pacman -S nmap")
        return {}
    disc_xml = os.path.join(outdir, "nmap_descubrimiento.xml")
    port_spec = ["-p-"] if full else ["--top-ports", "1000"]
    info("Descubriendo puertos abiertos...")
    run(["nmap"] + port_spec + ["-T4", "--min-rate", "2000", "-oX", disc_xml, target],
        logfile=os.path.join(outdir, "nmap_descubrimiento.txt"))

    open_ports = ports_from_xml(disc_xml)
    if not open_ports:
        warn("No se encontraron puertos abiertos.")
        return {}
    ports_csv = ",".join(str(p) for p in sorted(open_ports))
    ok(f"Puertos abiertos: {ports_csv}")

    det_xml = os.path.join(outdir, "nmap_detallado.xml")
    info("Escaneo detallado (-sV -sC)...")
    run(["nmap", "-sV", "-sC", "-p", ports_csv, "-oX", det_xml,
         "-oN", os.path.join(outdir, "nmap_detallado.txt"), target])
    hosts = parse_nmap_hosts(det_xml)

    for ip, services in hosts.items():
        for s in services:
            extra = f"{s['product']} {s['version']}".strip()
            add_finding("info", f"Puerto {s['port']}/{s['proto']} {s['service']}",
                        extra, host=ip)

    if vuln_scripts:
        phase("RED - scripts de vulnerabilidades de nmap (--script vuln)")
        vuln_out = os.path.join(outdir, "nmap_vuln.txt")
        run(["nmap", "--script", "vuln", "-p", ports_csv,
             "-oN", vuln_out, target])
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
    """Devuelve {ip: [servicios]} con metadatos utiles por puerto."""
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
        ip = addr.get("addr")
        services = []
        for port in host.iter("port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            pid = int(port.get("portid"))
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            tunnel = svc.get("tunnel", "") if svc is not None else ""
            is_web = any(k in name for k in WEB_KEYWORDS) or pid in WEB_PORTS
            scheme = "https" if (tunnel == "ssl" or "https" in name
                                 or pid in {443, 8443, 9443}) else "http"
            services.append({
                "port": pid, "proto": port.get("protocol", "tcp"),
                "service": name,
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
                "is_web": is_web, "scheme": scheme,
            })
        if services:
            hosts[ip] = services
    return hosts


def parse_nmap_vuln(path, host):
    """Marca como hallazgo cada linea de --script vuln que indique vulnerabilidad."""
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8", errors="replace"):
        s = line.strip()
        if "VULNERABLE" in s.upper():
            add_finding("high", "nmap script vuln", s, host=host)
            add_suggestion(f"Revisa el hallazgo de nmap vuln en {host}: {s}")
        elif re.search(r"CVE-\d{4}-\d+", s):
            add_finding("medium", "nmap: CVE detectada", s, host=host)


# ============================================================================
# FASE: SMB / Windows (enum4linux, smbclient, netexec)
# ============================================================================
def audit_smb(host, outdir):
    """Enumera servicios SMB en busca de informacion y sesiones nulas."""
    phase(f"SMB / Windows - enumeracion ({host})")
    add_suggestion(f"SMB abierto en {host}: enumera usuarios/recursos y prueba "
                   f"sesiones nulas y credenciales por defecto.")

    nxc = first_tool("netexec", "nxc")
    if nxc:
        info("netexec: informacion del host y recursos (sesion nula)...")
        code, out = run([nxc, "smb", host, "-u", "", "-p", "", "--shares"],
                        logfile=os.path.join(outdir, f"netexec_{host}.txt"))
        if re.search(r"READ|WRITE", out):
            add_finding("medium", "Recursos SMB accesibles por sesion nula", host=host)
        m = re.search(r"\(domain:([^)]+)\)", out)
        if m:
            add_finding("info", "Dominio SMB", m.group(1).strip(), host=host)
        if re.search(r"signing:False", out):
            add_finding("medium", "SMB signing deshabilitado (riesgo relay)", host=host)
            add_suggestion(f"SMB signing OFF en {host}: posible NTLM relay con responder/ntlmrelayx.")
    else:
        warn("netexec/nxc no disponible.")

    if tool_exists("smbclient"):
        info("smbclient: listado de recursos compartidos (sesion nula)...")
        run(["smbclient", "-L", f"//{host}/", "-N"],
            logfile=os.path.join(outdir, f"smbclient_{host}.txt"))

    if tool_exists("enum4linux"):
        info("enum4linux: enumeracion completa...")
        run(["enum4linux", "-a", host],
            logfile=os.path.join(outdir, f"enum4linux_{host}.txt"))
    else:
        warn("enum4linux no disponible.")


# ============================================================================
# FASE: Web - fingerprint, cabeceras, TLS, spider, inyecciones, ffuf, sqlmap
# ============================================================================
SECURITY_HEADERS = {
    "Content-Security-Policy": ("medium", "Falta CSP (mitiga XSS/inyeccion)"),
    "Strict-Transport-Security": ("medium", "Falta HSTS (fuerza HTTPS)"),
    "X-Frame-Options": ("low", "Falta X-Frame-Options (clickjacking)"),
    "X-Content-Type-Options": ("low", "Falta X-Content-Type-Options (MIME sniffing)"),
    "Referrer-Policy": ("info", "Falta Referrer-Policy"),
    "Permissions-Policy": ("info", "Falta Permissions-Policy"),
}
XSS_PAYLOAD = "vsx<svg/onload=alert(1)>"
SQL_ERRORS = re.compile(
    r"(SQL syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|"
    r"Microsoft OLE DB|Unclosed quotation mark|Warning.*\Wmysqli?_)", re.IGNORECASE)


def recon_httpx(url, outdir):
    if not tool_exists("httpx"):
        return
    out = os.path.join(outdir, "httpx.txt")
    code, output = run(["httpx", "-u", url, "-silent", "-title", "-status-code",
                        "-tech-detect", "-web-server", "-o", out])
    for line in output.strip().splitlines():
        if line.strip():
            add_finding("info", "Fingerprint web", line.strip())


def web_check_headers(url, session):
    try:
        r = session.get(url, timeout=15, allow_redirects=True)
    except Exception as e:
        err(f"No se pudo conectar a {url}: {e}")
        return
    if r.headers.get("X-Powered-By"):
        add_finding("low", "X-Powered-By expone tecnologia", r.headers["X-Powered-By"])
    for header, (sev, msg) in SECURITY_HEADERS.items():
        if header not in r.headers:
            add_finding(sev, msg)
    for c in r.cookies:
        problems = []
        if not c.secure:
            problems.append("sin Secure")
        if not c.has_nonstandard_attr("HttpOnly"):
            problems.append("sin HttpOnly")
        if problems:
            add_finding("low", f"Cookie '{c.name}' insegura", ", ".join(problems))


def web_check_ssl(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
        add_finding("info", f"TLS negociado: {proto}")
        if cert and "notAfter" in cert:
            add_finding("info", "Certificado valido hasta", cert["notAfter"])
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            add_finding("medium", f"Protocolo TLS obsoleto: {proto}")
    except Exception:
        pass


def web_check_robots_methods(url, session):
    base = "{0.scheme}://{0.netloc}".format(urlparse(url))
    for path in ("robots.txt", "sitemap.xml"):
        try:
            r = session.get(f"{base}/{path}", timeout=10)
            if r.status_code == 200 and r.text.strip():
                add_finding("info", f"{path} encontrado",
                            f"{len(r.text.splitlines())} lineas")
        except Exception:
            pass
    try:
        r = session.request("OPTIONS", url, timeout=10)
        allow = r.headers.get("Allow", "")
        if allow:
            add_finding("info", "Metodos HTTP permitidos", allow)
        risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
        if risky:
            add_finding("medium", "Metodos HTTP peligrosos habilitados", ", ".join(risky))
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
    ok(f"{len(visited)} paginas, {len(param_urls)} con parametros, {len(forms)} formularios.")
    if param_urls:
        add_finding("info", f"{len(param_urls)} URLs con parametros", "; ".join(list(param_urls)[:5]))
    return param_urls


def _extract_links_forms(html_text, base_url):
    links, forms = set(), []
    if HAS_BS4:
        soup = BeautifulSoup(html_text, "html.parser")
        for a in soup.find_all("a", href=True):
            links.add(urljoin(base_url, a["href"]))
        for form in soup.find_all("form"):
            inputs = [i.get("name") for i in form.find_all(["input", "textarea", "select"])
                      if i.get("name")]
            forms.append({"action": urljoin(base_url, form.get("action", base_url)),
                          "method": form.get("method", "get").lower(), "inputs": inputs})
    else:
        for href in re.findall(r'href=["\']([^"\']+)["\']', html_text):
            links.add(urljoin(base_url, href))
    return links, forms


def web_test_injections(param_urls, session):
    if not param_urls:
        info("Sin parametros GET que probar (usa --spider para descubrir mas).")
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
        vuln(f"XSS reflejado posible en '{param}'")
        add_finding("high", f"XSS reflejado en '{param}'", test_url)
        add_suggestion(f"Confirma el XSS en {test_url} y construye un PoC.")


def _test_sqli(parsed, params, param, session):
    test_url = _build_url(parsed, params, param, params[param][0] + "'")
    try:
        r = session.get(test_url, timeout=10)
    except Exception:
        return
    if SQL_ERRORS.search(r.text):
        vuln(f"Error SQL al inyectar comilla en '{param}'")
        add_finding("high", f"Posible SQLi (error-based) en '{param}'", test_url)
        add_suggestion(f"Lanza sqlmap sobre {test_url} (o usa --sqli).")


def run_sqlmap(param_urls, outdir, cookie=None):
    phase("WEB - SQLi automatizada (sqlmap)")
    if not tool_exists("sqlmap"):
        warn("sqlmap no esta instalado; se omite.")
        return
    if not param_urls:
        info("No hay URLs con parametros para sqlmap.")
        return
    for url in list(param_urls)[:5]:
        cmd = ["sqlmap", "-u", url, "--batch", "--level", "2", "--risk", "1",
               "--output-dir", os.path.join(outdir, "sqlmap")]
        if cookie:
            cmd += ["--cookie", cookie]
        code, output = run(cmd)
        if re.search(r"is vulnerable|parameter.*injectable", output, re.IGNORECASE):
            vuln("sqlmap reporta inyeccion!")
            add_finding("critical", "SQLi confirmada por sqlmap", url)
            add_suggestion(f"sqlmap confirmo SQLi en {url}: extrae datos con --dump.")


def run_ffuf(url, outdir, wordlist, idx=0):
    if not tool_exists("ffuf"):
        warn("ffuf no esta instalado; se omite el fuzzing.")
        return
    if not os.path.exists(wordlist):
        warn(f"No existe la wordlist: {wordlist}")
        return
    out = os.path.join(outdir, f"ffuf_{idx}.json")
    run(["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
         "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", out, "-s"])
    if os.path.exists(out):
        try:
            data = json.load(open(out, encoding="utf-8"))
            for res in data.get("results", []):
                add_finding("info", f"Ruta encontrada ({res.get('status')})", res.get("url", ""))
        except (json.JSONDecodeError, ValueError):
            pass


def audit_web(url, session, outdir, args, idx=0):
    """Pipeline web completo sobre una URL concreta."""
    phase(f"WEB - auditoria de {url}")
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
# FASE: nuclei (sobre todas las URLs web vivas)
# ============================================================================
def run_nuclei(urls, outdir, severity=None):
    phase("VULNS - analisis con plantillas (nuclei)")
    if not tool_exists("nuclei"):
        warn("nuclei no esta instalado; se omite.")
        return
    if not urls:
        info("No hay URLs web para nuclei.")
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
# FASE: fuerza bruta (hydra) - opt-in
# ============================================================================
DEFAULT_USERS = ["root", "admin", "administrator", "user", "test"]
DEFAULT_PASSES = ["admin", "password", "123456", "root", "toor", "test", "letmein"]


def run_hydra(host, services, outdir, userlist=None, passlist=None):
    """Fuerza bruta ligera de SSH/FTP sobre el host (opt-in, ruidoso)."""
    phase(f"FUERZA BRUTA - hydra ({host})")
    if not tool_exists("hydra"):
        warn("hydra no esta instalado; se omite.")
        return
    warn("Fase ruidosa: usala solo con autorizacion y en labs.")

    # Listas por defecto si no se pasan.
    if not userlist:
        userlist = os.path.join(outdir, "_users.txt")
        open(userlist, "w").write("\n".join(DEFAULT_USERS))
    if not passlist:
        passlist = os.path.join(outdir, "_pass.txt")
        open(passlist, "w").write("\n".join(DEFAULT_PASSES))

    targets = {s["service"]: s["port"] for s in services
               if s["service"] in ("ssh", "ftp")}
    if not targets:
        info("No hay servicios SSH/FTP para fuerza bruta.")
        return
    for service, port in targets.items():
        info(f"hydra contra {service}://{host}:{port}")
        code, out = run([
            "hydra", "-L", userlist, "-P", passlist, "-t", "4", "-f",
            "-o", os.path.join(outdir, f"hydra_{service}_{host}.txt"),
            "-s", str(port), host, service])
        for m in re.finditer(r"login:\s*(\S+)\s+password:\s*(\S+)", out):
            vuln(f"Credenciales {service}: {m.group(1)}:{m.group(2)}")
            add_finding("critical", f"Credenciales {service} validas",
                        f"{m.group(1)}:{m.group(2)}", host=host)
            add_suggestion(f"Accede por {service} a {host} con {m.group(1)}:{m.group(2)}.")


# ============================================================================
# Reporte final
# ============================================================================
def write_report(outdir, target, started):
    counts = {s: 0 for s in SEVERITIES}
    for f in FINDINGS:
        counts[f["sev"]] += 1

    lines = [
        f"# Reporte vulnscan - {target}", "",
        f"- **Fecha:** {started:%Y-%m-%d %H:%M:%S}",
        f"- **Duracion:** {(datetime.now() - started).seconds}s",
        f"- **Resultados:** `{outdir}`", "",
        "## Resumen por severidad", "",
        "| Severidad | Hallazgos |", "|-----------|-----------|",
    ]
    for s in SEVERITIES:
        lines.append(f"| {s} | {counts[s]} |")
    lines.append("")

    if SUGGESTIONS:
        lines += ["## Vectores de ataque sugeridos", ""]
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
            host = f" _(host: {f['host']})_" if f["host"] else ""
            detail = f"  \n  `{f['detail']}`" if f["detail"] else ""
            lines.append(f"- **{f['title']}**{host}{detail}")
        lines.append("")

    lines += ["## Ficheros generados", ""]
    for f in sorted(os.listdir(outdir)):
        if not f.startswith("_"):
            lines.append(f"- `{f}`")

    report = os.path.join(outdir, "REPORTE.md")
    with open(report, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return report, counts


# ============================================================================
# Comprobacion de herramientas disponibles
# ============================================================================

# Todas las herramientas externas que usa el script, agrupadas por capa.
# Cada entrada: (binario, descripcion, comando_de_instalacion)
TOOL_CATALOG = [
    # --- Reconocimiento ---
    ("nmap",       "Escaneo de puertos y servicios",                "sudo pacman -S nmap"),
    ("dig",        "DNS: registros + transferencia de zona (AXFR)", "sudo pacman -S bind-tools"),
    ("subfinder",  "Enumeracion de subdominios",                    "sudo pacman -S subfinder"),
    ("httpx",      "Fingerprint web (tech, titulo, servidor)",      "sudo pacman -S httpx"),
    # --- Web ---
    ("ffuf",       "Fuzzing de directorios web",                    "sudo pacman -S ffuf"),
    ("nuclei",     "Vulnerabilidades con plantillas",               "sudo pacman -S nuclei"),
    ("sqlmap",     "SQLi automatizada",                             "sudo pacman -S sqlmap"),
    # --- SMB / AD ---
    ("netexec",    "Enumeracion SMB/AD (netexec)",                  "sudo pacman -S netexec"),
    ("enum4linux", "Enumeracion SMB/Samba",                        "sudo pacman -S enum4linux"),
    ("smbclient",  "Cliente SMB/CIFS",                             "sudo pacman -S smbclient"),
    # --- Credenciales ---
    ("hydra",      "Fuerza bruta SSH/FTP (opt-in)",                "sudo pacman -S hydra"),
]

# Librerias Python que necesitan estar en el venv.
PYLIB_CATALOG = [
    ("requests",       "HTTP client (fases web propias)"),
    ("bs4",            "HTML parser para el spider (beautifulsoup4)"),
]


def check_tools():
    """Imprime una tabla con el estado de cada herramienta (instalada / falta)."""
    print(BANNER)
    print(f"{C.BOLD}{C.BLUE}  Estado de herramientas{C.RESET}")
    print(f"{C.BLUE}  {'-' * 62}{C.RESET}\n")

    missing = []
    print(f"  {'Herramienta':<16} {'Estado':<13} {'Descripcion'}")
    print(f"  {'-'*16} {'-'*13} {'-'*34}")
    for binary, desc, install in TOOL_CATALOG:
        found = tool_exists(binary)
        icon  = f"{C.GREEN}[OK]{C.RESET}          " if found else f"{C.RED}[FALTA]{C.RESET}       "
        print(f"  {C.BOLD}{binary:<16}{C.RESET} {icon} {C.GRAY}{desc}{C.RESET}")
        if not found:
            missing.append((binary, install))

    print(f"\n  {'Libreria Python':<16} {'Estado':<13} {'Descripcion'}")
    print(f"  {'-'*16} {'-'*13} {'-'*34}")
    for lib, desc in PYLIB_CATALOG:
        try:
            __import__(lib)
            found = True
        except ImportError:
            found = False
        icon = f"{C.GREEN}[OK]{C.RESET}          " if found else f"{C.YELLOW}[OPCIONAL]{C.RESET}    "
        print(f"  {C.BOLD}{lib:<16}{C.RESET} {icon} {C.GRAY}{desc}{C.RESET}")
        if not found:
            missing.append((lib, "wsvenva  # activa el venv de trabajo"))

    if missing:
        print(f"\n{C.YELLOW}  Para instalar lo que falta:{C.RESET}")
        for name, cmd in missing:
            print(f"    {C.GRAY}# {name}{C.RESET}")
            print(f"    {cmd}")
    else:
        print(f"\n{C.GREEN}  Todo instalado. Puedes lanzar el escaner.{C.RESET}")
    print()


# ============================================================================
# Principal
# ============================================================================
def main():
    p = argparse.ArgumentParser(
        description="Auditor de seguridad por consola (red + web + SMB + DNS).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python3 vulnscan.py 10.10.10.10\n"
            "  python3 vulnscan.py 10.10.10.10 --full\n"
            "  python3 vulnscan.py http://objetivo.com --spider --sqli --fuzz\n"
            "  python3 vulnscan.py objetivo.com --subdomains --dns\n"
        ),
    )
    p.add_argument("target", nargs="?", help="IP, rango CIDR, dominio o URL")
    p.add_argument("--check-tools", action="store_true",
                   help="Muestra que herramientas estan instaladas y cuales faltan")
    p.add_argument("-o", "--output", help="Carpeta de salida")
    p.add_argument("--full", action="store_true",
                   help="Ejecuta todas las fases razonables (no incluye fuerza bruta)")
    p.add_argument("--ports-full", action="store_true", help="nmap a los 65535 puertos")
    p.add_argument("--vuln-scripts", action="store_true",
                   help="nmap --script vuln (CVEs conocidas, mas lento)")
    p.add_argument("--dns", action="store_true", help="Recon DNS con dig (auto en dominios)")
    p.add_argument("--subdomains", action="store_true", help="Enumerar subdominios (dominios)")
    p.add_argument("--spider", action="store_true", help="Spider web para descubrir parametros")
    p.add_argument("--sqli", action="store_true", help="SQLi con sqlmap sobre parametros")
    p.add_argument("--fuzz", action="store_true", help="Fuzzing de directorios con ffuf")
    p.add_argument("--smb", action="store_true", help="Forzar enum SMB (auto si 139/445 abierto)")
    p.add_argument("--no-smb", action="store_true", help="No enumerar SMB aunque este abierto")
    p.add_argument("--bruteforce", action="store_true",
                   help="Fuerza bruta SSH/FTP con hydra (RUIDOSO, opt-in)")
    p.add_argument("--no-nuclei", action="store_true", help="Salta nuclei")
    p.add_argument("--wordlist",
                   default="/usr/share/seclists/Discovery/Web-Content/common.txt",
                   help="Wordlist para el fuzzing de directorios")
    p.add_argument("--userlist", help="Lista de usuarios para hydra")
    p.add_argument("--passlist", help="Lista de contrasenas para hydra")
    p.add_argument("--severity", help="Filtra nuclei por severidad (ej. critical,high)")
    p.add_argument("--cookie", help="Cookie de sesion para escaneo web autenticado")
    p.add_argument("-H", "--header", action="append",
                   help="Cabecera HTTP extra 'Nombre: valor' (repetible)")
    args = p.parse_args()

    # --check-tools no necesita objetivo: muestra el estado y sale.
    if args.check_tools:
        check_tools()
        sys.exit(0)

    if not args.target:
        p.error("Especifica un objetivo o usa --check-tools para ver el estado.")

    print(BANNER)
    if not HAS_REQUESTS:
        warn("Falta 'requests': las comprobaciones web propias se omitiran. Activa: wsvenva")
    if not HAS_BS4:
        warn("Falta 'bs4': el spider usara regex (menos preciso).")

    kind, host, url = classify_target(args.target)
    info(f"Objetivo: {C.BOLD}{args.target}{C.RESET} ({kind})")

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r"[^a-zA-Z0-9.]", "_", host)
    outdir = args.output or f"vulnscan_{safe}_{stamp}"
    os.makedirs(outdir, exist_ok=True)
    ok(f"Resultados en: {outdir}")

    started = datetime.now()
    session = make_session(args.header, args.cookie) if HAS_REQUESTS else None
    web_urls = []

    # --- DNS y subdominios (solo dominios) ---
    if kind == "domain":
        if args.dns or args.full:
            dns_recon(host, outdir)
        if args.subdomains or args.full:
            web_urls += enum_subdomains(host, outdir)

    # --- Escaneo de red (nmap) ---
    nmap_target = host if kind in ("domain", "url") else args.target
    hosts = run_nmap(nmap_target, outdir, full=args.ports_full,
                     vuln_scripts=args.vuln_scripts)

    # --- Enumeracion por servicio en cada host ---
    for ip, services in hosts.items():
        smb_open = any(s["port"] in SMB_PORTS for s in services)
        if smb_open and not args.no_smb:
            audit_smb(ip, outdir)
        for s in services:
            if s["is_web"]:
                web_urls.append(f"{s['scheme']}://{ip}:{s['port']}")

    # Si el objetivo era una URL/dominio explicito, audita tambien esa URL base.
    if url:
        web_urls.insert(0, url)
    elif kind == "domain" and not web_urls:
        web_urls += [f"http://{host}", f"https://{host}"]
    web_urls = list(dict.fromkeys(web_urls))  # sin duplicados

    # --- Auditoria web por cada URL viva ---
    for i, wurl in enumerate(web_urls):
        audit_web(wurl, session, outdir, args, idx=i)

    # --- nuclei sobre todas las webs ---
    if web_urls and not args.no_nuclei:
        run_nuclei(web_urls, outdir, severity=args.severity)

    # --- Fuerza bruta (opt-in) ---
    if args.bruteforce:
        for ip, services in hosts.items():
            run_hydra(ip, services, outdir, args.userlist, args.passlist)

    # --- Reporte ---
    phase("RESUMEN")
    report, counts = write_report(outdir, args.target, started)
    resumen = "  ".join(f"{SEV_COLOR[s]}{s}:{counts[s]}{C.RESET}" for s in SEVERITIES)
    print(f"    {resumen}")
    if SUGGESTIONS:
        print(f"    {C.YELLOW}{len(SUGGESTIONS)} vectores de ataque sugeridos (ver reporte).{C.RESET}")
    ok(f"Reporte: {report}")
    print(f"\n{C.GREEN}{C.BOLD}Auditoria completada.{C.RESET} Carpeta: {C.BOLD}{outdir}{C.RESET}\n")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.default_int_handler)
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[!] Interrumpido por el usuario.{C.RESET}")
        sys.exit(130)

<div align="center">

# 🔐 Hacking Vault

**Mi arsenal personal de pentesting y seguridad ofensiva**

OSINT · Recon · Scan · Crypto · Shells — con menú de terminal y consola web

</div>

---

## ⚠️ Solo uso autorizado

> Todo esto es para **fines educativos** y para sistemas en los que tengas
> **permiso explícito** (labs, HTB/TryHackMe, CTFs, engagements con contrato).
> El mal uso es ilegal. El autor no se responsabiliza del uso indebido.

---

## 📁 Estructura

Solo herramientas. Todo es **Python stdlib** (sin `pip`), un archivo por herramienta
y autodocumentado (`-h`).

```
hacking-vault/
│
├── 🚀 hvault.py      Lanzador unificado: menú de terminal + consola web
├── 🧩 hvault/        Núcleo del lanzador (registro declarativo, menú, web, runner)
├── 🐍 scripts/       Herramientas por categoría
│   ├── osint/        OSINT pasivo: crt.sh, hunt de usuario, footprint DNS/WHOIS
│   ├── recon/        Recon activo: puertos sin nmap, DNS/AXFR, web
│   ├── crypto/       Cripto/CTF: magic-decode, cifras clásicas, hashid
│   └── shells/       Reverse shells + listener
└── 🧰 tools/
    └── vulnscan/     Auditor todo-en-uno que encadena tus herramientas
```

---

## 🚀 Lanzador unificado

Una sola puerta de entrada a todas las herramientas, desde un menú de terminal o una
consola web local. Sin dependencias.

```bash
python3 hvault.py              # menú interactivo en terminal (por defecto)
python3 hvault.py web          # consola web local, se abre en el navegador
python3 hvault.py list         # lista todas las herramientas y su id
python3 hvault.py run osint.crtsh example.com --live   # ejecuta una directamente
```

La consola web escucha **solo en loopback** y protege cada petición con una clave
aleatoria que va en la URL: nada fuera de tu máquina puede usarla. Cada herramienta
sigue siendo usable por su cuenta (`python3 scripts/osint/crtsh.py ...`); el lanzador
es una capa de comodidad por encima. Detalle: [`hvault/README.md`](hvault/README.md).

---

## ⭐ Destacado: `vulnscan`

Auditor de seguridad **todo-en-uno por consola** que encadena tus herramientas
(nmap, httpx, nuclei, ffuf, sqlmap, subfinder, SMB, hydra...) en un solo flujo.

```bash
python3 tools/vulnscan/vulnscan.py <objetivo> --full
```

| | |
|---|---|
| 🌐 **Red** | puertos y servicios con nmap |
| 🕸️ **Web** | fingerprint, cabeceras, TLS, XSS/SQLi, fuzzing |
| 🪟 **SMB/AD** | sesiones nulas, recursos, usuarios |
| 🔎 **DNS** | registros y transferencia de zona |
| 📄 **Reporte** | hallazgos por severidad + vectores de ataque |

➡️ Guía completa: [`tools/vulnscan/README.md`](tools/vulnscan/README.md)

---

## 🧰 Herramientas incluidas

| Herramienta | Categoría | Para qué |
|-------------|-----------|----------|
| `scripts/osint/crtsh.py` | OSINT | Subdominios pasivos desde Certificate Transparency (crt.sh) |
| `scripts/osint/username-hunt.py` | OSINT | Dónde está registrado un usuario en ~30 sitios públicos |
| `scripts/osint/footprint.py` | OSINT | Footprint pasivo: DNS (sobre HTTPS) + WHOIS |
| `scripts/recon/dnsrecon.py` | Recon | Registros DNS, intento de AXFR y brute de subdominios |
| `scripts/recon/portscan.py` | Recon | Escáner TCP con hilos para cajas sin nmap |
| `scripts/recon/webenum.py` | Recon | Recon web rápido (cabeceras, cookies, métodos, rutas) |
| `scripts/crypto/magic-decode.py` | Cripto/CTF | Pela capas de codificación hasta dar con texto o flag |
| `scripts/crypto/classic-cipher.py` | Cripto/CTF | César/XOR/Vigenère/Atbash/railfence/frecuencias con scoring |
| `scripts/crypto/hashid.py` | Credenciales | Identifica un hash y da el comando `hashcat`/`john` |
| `scripts/shells/revshell.py` | Explotación | Reverse shells por varios intérpretes + listener |
| `tools/vulnscan/vulnscan.py` | Scan | Auditor todo-en-uno (red, web, SMB/AD, nuclei, fuzzing, reporte) |

➡️ Detalle por categoría: [`scripts/README.md`](scripts/README.md) ·
[`osint/`](scripts/osint/README.md) · [`recon/`](scripts/recon/README.md) ·
[`crypto/`](scripts/crypto/README.md) · [`shells/`](scripts/shells/README.md)

---

## 🎯 ¿Qué cubre cada categoría?

| Categoría | Qué hay aquí |
|-----------|--------------|
| 🕵️ **OSINT** | reconocimiento pasivo: subdominios, usuarios, DNS/WHOIS |
| 🔍 **Recon** | escaneo de puertos, DNS/AXFR, recon web activo |
| 🛡️ **Scan** | auditoría encadenada con `vulnscan` |
| 🧩 **Cripto/CTF** | decodificación, cifras clásicas, identificación de hashes |
| 🐚 **Shells** | reverse shells y listeners |

---

## 🚀 Uso rápido

```bash
# Clonar
git clone <repo> hacking-vault && cd hacking-vault

# (archpwm) activar el entorno Python si lo usas para las herramientas de terceros
wsvenva

# Menú para todo, o una herramienta directa
python3 hvault.py
python3 tools/vulnscan/vulnscan.py <objetivo> --full
```

> 💡 Los resultados de los escaneos se guardan en carpetas locales que el
> `.gitignore` **excluye automáticamente** del repositorio.

---

## 🔗 Recursos útiles

- 📚 [HackTricks](https://book.hacktricks.xyz/)
- 🐧 [GTFOBins](https://gtfobins.github.io/)
- 🎒 [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- 🛡️ [OWASP](https://owasp.org/)

---

<div align="center">

📜 Licencia MIT · con fines educativos

**Hackea con ética, siempre con permiso.** 🎯

</div>

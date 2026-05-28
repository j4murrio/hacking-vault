# vulnscan

Auditor de **seguridad por consola** (red + web + SMB/AD + DNS), escrito en Python.
Orquesta las herramientas que ya tienes en tu entorno
[archpwm](https://github.com/j4murrio/archpwm) para hacer una auditoria completa
de un objetivo: **descubrir → enumerar → detectar vulnerabilidades → sugerir
puntos de ataque**, con un reporte final en Markdown.

Pensado para ser **completo pero legible y facil de ampliar**, y para usar
**solo herramientas que ya tienes instaladas** (cada fase se omite sola si falta
la suya).

---

## Aviso legal

Usalo **solo** contra sistemas con autorizacion explicita: tus labs, maquinas de
HTB/TryHackMe, CTFs o engagements con permiso por escrito. Escanear o atacar
infraestructura de terceros sin permiso es ilegal. La fase de fuerza bruta es
especialmente ruidosa: actívala solo cuando proceda.

---

## Que hace (fases)

```
  Objetivo: IP · rango CIDR · dominio · URL
        │
        ▼
  DNS       dig        ── registros DNS + transferencia de zona (AXFR)   [dominios]
  SUBDOM    subfinder  ── subdominios + httpx para ver cuales viven        [dominios]
  RED       nmap       ── puertos + servicios (-sV -sC)  [+ --script vuln]
        │
        ├─ por cada host y servicio:
        │
  SMB       netexec / enum4linux / smbclient ── sesiones nulas, recursos, usuarios
  WEB       httpx      ── fingerprint (tecnologia, titulo, servidor)
            Python     ── cabeceras, cookies, TLS, robots, metodos HTTP
            Python     ── spider + XSS reflejado + SQLi por error
            sqlmap     ── SQLi automatizada                                [--sqli]
            ffuf       ── fuzzing de directorios                           [--fuzz]
  VULNS     nuclei     ── plantillas de vulnerabilidades sobre todas las webs
  BRUTE     hydra      ── fuerza bruta SSH/FTP                       [--bruteforce]
        │
        ▼
  REPORTE.md  ── hallazgos por severidad + vectores de ataque sugeridos
```

Cada fase es **tolerante a fallos**: si una herramienta no esta instalada o una
peticion falla, avisa y continua en lugar de romperse.

---

## Herramientas que utiliza

> Todas estan en tu archpwm. Las que el ejemplo original usaba pero **tu no
> tienes** (`whatweb`, `wpscan`) se sustituyen por `httpx` y `sqlmap`.

| Capa        | Herramientas                                  | Obligatoria |
|-------------|-----------------------------------------------|:-----------:|
| DNS         | `dig` (bind-tools)                            | No          |
| Subdominios | `subfinder`, `httpx`                          | No          |
| Red         | `nmap`                                         | **Si**      |
| SMB/AD      | `netexec`/`nxc`, `enum4linux`, `smbclient`    | No          |
| Web         | `httpx`, `ffuf`, `nuclei`, `sqlmap`           | No          |
| Web (propio)| `requests` + `beautifulsoup4` (Python)        | recomendado |
| Fuerza bruta| `hydra`                                        | No          |

Las comprobaciones web propias (cabeceras, cookies, TLS, spider, XSS/SQLi basico)
usan **`requests`** y opcionalmente **`beautifulsoup4`**, que estan en tu venv de
trabajo. Actívalo con `wsvenva` antes de ejecutar.

---

## Preparacion

```bash
wsvenva                    # activa el venv (trae requests, beautifulsoup4...)
nuclei -update-templates   # solo la primera vez
chmod +x vulnscan.py       # opcional
```

---

## Uso

```bash
# Auditoria por defecto de una IP (DNS si es dominio, nmap, SMB auto, web, nuclei)
python3 vulnscan.py 10.10.10.10

# Todo lo razonable (spider + sqlmap + ffuf + vuln-scripts NO; ver --full abajo)
python3 vulnscan.py 10.10.10.10 --full

# Web a la carta
python3 vulnscan.py http://objetivo.com --spider --sqli --fuzz

# Dominio: DNS + subdominios
python3 vulnscan.py objetivo.com --dns --subdomains

# Subred completa, todos los puertos
python3 vulnscan.py 10.10.10.0/24 --ports-full

# Escaneo web autenticado
python3 vulnscan.py http://objetivo.com --cookie "session=abc123" -H "X-Api-Key: xyz"

# Fuerza bruta SSH/FTP (RUIDOSO, solo en labs)
python3 vulnscan.py 10.10.10.10 --bruteforce --userlist users.txt --passlist rockyou.txt
```

### Que activa cada modo

- **Por defecto:** DNS (si dominio), nmap top-1000 `-sV -sC`, enum SMB automatica
  si 139/445 estan abiertos, fingerprint web + cabeceras/TLS/robots/metodos +
  inyecciones basicas, y nuclei.
- **`--full`:** ademas spider, sqlmap, ffuf y subdominios. **No** incluye fuerza
  bruta ni `--script vuln` (los dejas explicitos por ser ruidosos/lentos).

### Opciones

| Opcion           | Descripcion                                                     |
|------------------|----------------------------------------------------------------|
| `target`         | IP, CIDR, dominio o URL (obligatorio)                          |
| `-o, --output`   | Carpeta de salida (por defecto `vulnscan_<host>_<fecha>`)       |
| `--full`         | Todas las fases razonables (sin fuerza bruta ni vuln-scripts)   |
| `--ports-full`   | nmap a los 65535 puertos                                        |
| `--vuln-scripts` | `nmap --script vuln` (CVEs conocidas, mas lento)                |
| `--dns`          | Recon DNS con dig (automatico en dominios)                      |
| `--subdomains`   | Enumerar subdominios con subfinder                             |
| `--spider`       | Spider web para descubrir parametros y formularios             |
| `--sqli`         | SQLi automatizada con sqlmap                                    |
| `--fuzz`         | Fuzzing de directorios con ffuf                                 |
| `--smb`/`--no-smb` | Forzar / desactivar la enumeracion SMB                       |
| `--bruteforce`   | Fuerza bruta SSH/FTP con hydra (opt-in, ruidoso)               |
| `--no-nuclei`    | Salta nuclei                                                    |
| `--wordlist`     | Wordlist para el fuzzing (por defecto SecLists `common.txt`)    |
| `--userlist` / `--passlist` | Listas para hydra (si no, usa unas pequenas por defecto) |
| `--severity`     | Filtra nuclei por severidad                                     |
| `--cookie`       | Cookie de sesion para web autenticada                          |
| `-H, --header`   | Cabecera HTTP extra `Nombre: valor` (repetible)                |

---

## Resultados

Todo se guarda en una carpeta con marca de tiempo, p.ej.
`vulnscan_10.10.10.10_20260528_101500/`:

```
vulnscan_.../
├── dns.txt                  # registros DNS y AXFR (dominios)
├── subdominios.txt          # subfinder
├── nmap_descubrimiento.*    # puertos abiertos (etapa rapida)
├── nmap_detallado.*         # version + scripts por puerto
├── nmap_vuln.txt            # --script vuln (si se usa)
├── netexec_<ip>.txt         # enumeracion SMB
├── enum4linux_<ip>.txt
├── smbclient_<ip>.txt
├── httpx.txt                # fingerprint web
├── ffuf_*.json              # rutas encontradas
├── nuclei.txt               # vulnerabilidades por plantillas
├── sqlmap/                  # salida de sqlmap
├── hydra_*.txt              # resultados de fuerza bruta
└── REPORTE.md               # resumen ordenado por severidad + vectores
```

El **REPORTE.md** agrupa los hallazgos en `critical / high / medium / low / info`,
con una tabla resumen y una seccion de **vectores de ataque sugeridos** (que hacer
a continuacion con cada hallazgo).

---

## Como funciona por dentro (resumen)

- El objetivo se **clasifica** (IP/CIDR/dominio/URL) y de ahi se decide que fases
  tienen sentido (p.ej. DNS y subdominios solo para dominios).
- **nmap** corre en dos etapas (descubrir puertos → `-sV -sC` sobre los abiertos)
  y su XML se parsea para saber que servicios hay en cada host.
- Segun los puertos, se **despacha** la enumeracion: SMB (139/445) o web (80/443...).
- Las comprobaciones web propias usan `requests` + libreria estandar (`ssl`,
  `socket`); el spider usa BeautifulSoup (o regex si no esta).
- Cada hallazgo se acumula con su **severidad** (`add_finding`) y, cuando aplica,
  se anade un **vector de ataque** sugerido (`add_suggestion`).
- Al final se vuelca todo a `REPORTE.md` y a un resumen en consola.

El codigo esta dividido en una funcion por fase, con nombres claros y comentarios
en español, para que sea facil de leer y ampliar.

---

## Notas y solucion de problemas

- Si ves `Falta 'requests'`, activa el venv con `wsvenva` (las fases web propias
  lo necesitan; el resto funciona igual).
- Algunos escaneos de `nmap` necesitan privilegios: ejecuta con `sudo` si el
  descubrimiento es lento o incompleto.
- Si `nuclei` no encuentra nada y esperabas hallazgos: `nuclei -update-templates`.
- Si la wordlist por defecto no existe, instala SecLists (`sudo pacman -S seclists`)
  o pasa otra con `--wordlist`.
- `--bruteforce`, `--sqli`, `--fuzz`, `--ports-full` y `--vuln-scripts` pueden
  tardar y/o ser ruidosos: uselos cuando ya tengas claro el objetivo.
- Las pruebas de inyeccion propias son **basicas** (deteccion rapida); para
  confirmar y explotar usa `--sqli` (sqlmap) o Burp Suite.

<div align="center">

# 🔐 Hacking Vault

**Mi arsenal personal de pentesting y seguridad ofensiva**

Scripts · Exploits · Herramientas · Notas · Recursos

</div>

---

## ⚠️ Solo uso autorizado

> Todo esto es para **fines educativos** y para sistemas en los que tengas
> **permiso explícito** (labs, HTB/TryHackMe, CTFs, engagements con contrato).
> El mal uso es ilegal. El autor no se responsabiliza del uso indebido.

---

## 📁 Estructura

```
hacking-vault/
│
├── 🐍 scripts/       Scripts propios (recon, escaneo, automatización)
├── 💥 exploits/      Exploits y pruebas de concepto (PoC)
├── 📖 wordlists/     Diccionarios y listas personalizadas
├── 🧰 tools/         Herramientas y utilidades de terceros
├── 📝 notes/         Metodologías y apuntes
├── ⚙️  configs/       Configuraciones útiles
└── 📑 cheatsheets/   Hojas de referencia rápida
```

---

## ⭐ Destacado: `vulnscan`

Auditor de seguridad **todo-en-uno por consola** que encadena tus herramientas
(nmap, httpx, nuclei, ffuf, sqlmap, subfinder, SMB, hydra...) en un solo flujo.

```bash
python3 tools/vulnscan/vulnscan.py 10.10.10.10 --full
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

## 🎯 ¿Para qué sirve cada cosa?

| Categoría | Qué guardo aquí |
|-----------|-----------------|
| 🔍 **Reconocimiento** | escaneo de puertos, subdominios, OSINT |
| 💥 **Explotación** | exploits, payloads, shells |
| 🕸️ **Web** | SQLi, XSS, CSRF, scanners |
| 🔑 **Credenciales** | fuerza bruta, cracking de hashes |
| ⬆️ **Escalada** | enumeración local y privesc |
| 📡 **Redes/Wireless** | captura y análisis de tráfico |

---

## 🚀 Uso rápido

```bash
# Clonar
git clone <repo> hacking-vault && cd hacking-vault

# Activar el entorno Python (archpwm)
wsvenva

# Lanzar un script
python3 tools/vulnscan/vulnscan.py <objetivo>
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

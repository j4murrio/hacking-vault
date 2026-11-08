# hvault - unified launcher

One entry point for every tool in the vault, from a terminal menu or a local web
console. Pure Python standard library, no dependencies.

```bash
python3 hvault.py              # interactive terminal menu (default)
python3 hvault.py web          # local web console, opens in your browser
python3 hvault.py list         # list every tool and its id
python3 hvault.py run osint.crtsh example.com --live   # run one tool directly
python3 hvault.py report example.com                   # chain passive tools into one report
```

## `report` - sweep whole categories into one report

`report` is the global counterpart to running a single tool. Point it at a domain or an
IP and it runs every applicable tool through the same `runner`, then writes everything to
`reports/<target>_<stamp>.md` (the `reports/` folder is git-ignored, so nothing a scan
collects is committed).

The set of tools is **derived from the registry, not hard-coded**: each tool joins the
sweep when the target fits its primary input (a domain tool needs a domain; port/HTTP/web
tools take a domain or an IP). Drop a new OSINT script into `spec.py` and it is picked up
automatically - nothing else to wire.

- **OSINT** (passive) always runs. **Recon** and **Web** (active, they touch the host) run
  only with `--active`, or when `--only` names their category.
- `--only CATEGORY` limits the sweep to one area - this is the "run all of OSINT at once"
  button (`--only recon`, `--only web`, ...). An active category named with `--only` runs
  without needing `--active`.
- An **IP** has no passive sources, so a plain IP report needs `--active` (or `--only`).
- The heavy `scan.vulnscan` orchestrator is left out of the sweep; run it on its own.

```bash
python3 hvault.py report example.com                   # all OSINT (passive)
python3 hvault.py report example.com --only osint      # same, stated explicitly
python3 hvault.py report example.com --active          # OSINT + Recon + Web
python3 hvault.py report example.com --only recon      # just the recon tools
python3 hvault.py report 10.10.10.10 --active          # IP needs --active
```

## How it works

Every tool is declared once in [`spec.py`](spec.py) as a `ToolSpec` - its id, category,
the script it runs, and its parameters. That single catalog drives everything:

- **`menu.py`** walks the catalog to draw the terminal menu, prompts you for each
  parameter, shows the exact command, and runs it.
- **`web.py`** serves a one-page console (vanilla HTML/JS, no framework) that builds a
  form from the same parameters. It binds to **loopback only** and guards every request
  with a random key printed in the URL, so nothing off your machine can reach it.
- **`runner.py`** turns a `{parameter: value}` mapping into an argv and runs the script
  as a subprocess. The argv is always a **list, never a shell string**, so a value can
  only ever be an argument to its own tool - it cannot inject a second command.

The tools stay fully usable on their own (`python3 scripts/osint/crtsh.py ...`); the
launcher is just a convenience layer over them.

## Adding a tool

Drop your standalone script under `scripts/<category>/`, then add one `ToolSpec` entry to
`build_registry()` in `spec.py` listing its parameters. It then appears in `list`, the
menu and the web console automatically.

> The web console runs tools on your own machine. Keep it local - do not expose the port
> or forward it. Authorized / educational use only.

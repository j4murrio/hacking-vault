# hvault - unified launcher

One entry point for every tool in the vault, from a terminal menu or a local web
console. Pure Python standard library, no dependencies.

```bash
python3 hvault.py              # interactive terminal menu (default)
python3 hvault.py web          # local web console, opens in your browser
python3 hvault.py list         # list every tool and its id
python3 hvault.py run osint.crtsh example.com --live   # run one tool directly
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

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
hvault.py - Unified launcher for the hacking-vault toolkit.

One entry point for every tool in the vault, driven from the same declarative
registry (hvault/spec.py). Standard library only.

    python3 hvault.py                 # interactive terminal menu (default)
    python3 hvault.py web             # local web console in your browser
    python3 hvault.py list            # list every tool and its id
    python3 hvault.py run <id> [args] # run one tool directly, e.g.
                                      #   run osint.crtsh example.com --live
    python3 hvault.py report <target> # sweep whole categories into one report
                                      #   report example.com --only osint
                                      #   report example.com --active

Authorized / educational use only.
"""

import argparse
import subprocess
import sys
from pathlib import Path

from hvault import menu, report, web
from hvault.spec import build_registry

ROOT = Path(__file__).resolve().parent


def cmd_list(registry, _):
    width = max(len(s.id) for s in registry)
    last = None
    for s in registry:
        if s.category != last:
            print(f"\n{s.category}")
            last = s.category
        print(f"  {s.id:<{width}}  {s.summary}")


def cmd_run(registry, args):
    specs = {s.id: s for s in registry}
    spec = specs.get(args.id)
    if not spec:
        sys.exit(f"[-] Unknown tool id '{args.id}'. Try: python hvault.py list")
    path = ROOT / spec.script
    return subprocess.call([sys.executable, str(path)] + args.toolargs)


def cmd_report(registry, args):
    try:
        out = report.generate(registry, args.target, active=args.active,
                              timeout=args.timeout, only=args.only)
    except ValueError as e:
        sys.exit(f"[-] {e}")
    print(f"\n[+] Report written to {out}")
    return 0


def main():
    p = argparse.ArgumentParser(
        description="Unified launcher for the hacking-vault toolkit.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="mode")

    sub.add_parser("menu", help="interactive terminal menu (default)")

    w = sub.add_parser("web", help="local web console")
    w.add_argument("--port", type=int, default=0, help="port (default: random free)")
    w.add_argument("--no-browser", action="store_true", help="do not open a browser")
    w.add_argument("--timeout", type=int, default=300, help="per-run timeout s (default 300)")

    sub.add_parser("list", help="list every tool and its id")

    r = sub.add_parser("run", help="run one tool by id")
    r.add_argument("id", help="tool id, e.g. osint.crtsh")
    r.add_argument("toolargs", nargs=argparse.REMAINDER, help="arguments passed to the tool")

    rep = sub.add_parser("report", help="chain whole categories of tools into one report")
    rep.add_argument("target", help="domain or IP")
    rep.add_argument("--active", action="store_true",
                     help="also run active recon (ports, web)")
    rep.add_argument("--only", metavar="CATEGORY",
                     help="limit to one category, e.g. osint, recon, web")
    rep.add_argument("--timeout", type=int, default=180,
                     help="per-tool timeout s (default 180)")

    args = p.parse_args()
    registry = build_registry()

    if args.mode == "list":
        return cmd_list(registry, args)
    if args.mode == "run":
        return cmd_run(registry, args)
    if args.mode == "report":
        return cmd_report(registry, args)
    if args.mode == "web":
        return web.serve(registry, port=args.port,
                         open_browser=not args.no_browser, timeout=args.timeout)
    return menu.loop(registry)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)

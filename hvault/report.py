"""Chain whole categories of tools into one Markdown report.

`report` is the global counterpart to running a single tool: point it at a
domain or an IP and it runs every applicable tool - derived from the registry,
not a fixed list - through the same runner the menu and web use, then writes
everything to reports/<target>_<stamp>.md. Add a new OSINT script to the
registry and it joins the passive sweep automatically.

Passive categories (OSINT) always run; active ones (Recon, Web) run only with
--active, or when --only names that category. --only limits the sweep to a
single category, so `report example.com --only osint` gathers all the OSINT at
once. The reports/ directory is git-ignored, so nothing a scan collects is
committed.
"""

import datetime as dt
import ipaddress
import re
from pathlib import Path

from . import runner

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"

PASSIVE_CATEGORIES = {"osint"}
ACTIVE_CATEGORIES = {"recon", "web"}
# Heavy / external-tool orchestrators are not part of the quick sweep.
SKIP_IDS = {"scan.vulnscan"}


def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_domain(target):
    return not is_ip(target) and re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", target) is not None


def target_kind(target):
    if is_ip(target):
        return "ip"
    if is_domain(target):
        return "domain"
    return None


def _values_for(spec, target, kind):
    """Map a target onto a tool's primary input, or None if it does not fit.

    A tool is driven by its first positional parameter: domain tools need a
    domain, target/hosts tools take either, url tools get a synthesised
    http://target/. Tools keyed on a username, hash, blob, token or file are not
    target recon and never join the sweep.
    """
    primary = next((p for p in spec.params if p.positional), None)
    if primary is None:
        return None
    key = primary.key
    if key == "domain":
        return {key: target} if kind == "domain" else None
    if key in ("target", "hosts"):
        return {key: target}
    if key == "url":
        return {key: f"http://{target}/"}
    return None


def categories(registry):
    """The category names present in the registry, lowercased."""
    seen = []
    for spec in registry:
        c = spec.category.lower()
        if c not in seen:
            seen.append(c)
    return seen


def plan(registry, target, active=False, only=None):
    """Return the ordered [(tool_id, values)] steps for this target.

    Steps follow registry order. Passive tools always qualify; active ones need
    --active, or an explicit --only on their category. `only` restricts the
    sweep to one category.
    """
    kind = target_kind(target)
    if kind is None:
        return []
    only = only.lower() if only else None
    steps = []
    for spec in registry:
        if spec.id in SKIP_IDS:
            continue
        cat = spec.category.lower()
        if only and cat != only:
            continue
        if cat in PASSIVE_CATEGORIES:
            pass
        elif cat in ACTIVE_CATEGORIES:
            if not (active or only):
                continue
        else:
            continue  # crypto / forensics / shells / scan: not target recon
        values = _values_for(spec, target, kind)
        if values is None:
            continue
        steps.append((spec.id, values))
    return steps


def generate(registry, target, active=False, timeout=180, only=None):
    """Run the plan and write the report. Returns the report Path."""
    if only is not None and only.lower() not in categories(registry):
        raise ValueError(f"unknown category '{only}'; choose from "
                         f"{', '.join(categories(registry))}.")

    specs = {s.id: s for s in registry}
    steps = plan(registry, target, active, only)
    if not steps:
        if target_kind(target) is None:
            raise ValueError(f"'{target}' is neither a domain nor an IP; nothing to run.")
        if is_ip(target) and not active and not only:
            raise ValueError("an IP has no passive steps; add --active to scan it.")
        raise ValueError(f"nothing to run for '{target}'"
                         + (f" in category '{only}'." if only else "."))

    REPORTS.mkdir(exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    out = REPORTS / f"{safe}_{stamp}.md"

    scope = only.lower() if only else ("passive + active" if active else "passive")
    lines = [
        f"# Recon report - {target}",
        "",
        f"- Generated: {dt.datetime.now().isoformat(timespec='seconds')}",
        f"- Scope: {scope}",
        f"- Target type: {'IP' if is_ip(target) else 'domain'}",
        "",
        "> Authorized / educational use only.",
        "",
        "## Contents",
        "",
    ]
    for tool_id, _ in steps:
        lines.append(f"- [{tool_id}](#{tool_id.replace('.', '')})")
    lines.append("")

    for tool_id, values in steps:
        spec = specs.get(tool_id)
        anchor = tool_id.replace(".", "")
        lines += [f"<a id='{anchor}'></a>", f"## {tool_id}", ""]
        if not spec:
            lines += [f"_Tool '{tool_id}' not in registry; skipped._", ""]
            continue
        lines += [f"_{spec.summary}_", "", f"`{runner.preview_cmd(spec, values)}`", ""]
        print(f"[*] {tool_id} ...", flush=True)
        code, output = runner.run(spec, values, timeout=timeout)
        status = "ok" if code == 0 else f"exit {code}"
        output = output.strip() or "(no output)"
        lines += [f"Result: {status}", "", "```", output, "```", ""]

    out.write_text("\n".join(lines), encoding="utf-8")
    return out

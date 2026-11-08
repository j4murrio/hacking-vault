"""Interactive terminal menu over the tool registry."""

from collections import OrderedDict

from . import runner

BANNER = r"""
  _               _ _
 | |____   ____ _(_) |_   hacking-vault toolkit
 | '_ \ \ / / _` | | __|  OSINT - Recon - Scan - Crypto - Shells
 | | | \ V / (_| | | |_   authorized / educational use only
 |_| |_|\_/ \__,_|_|\__|
"""


def by_category(registry):
    cats = OrderedDict()
    for spec in registry:
        cats.setdefault(spec.category, []).append(spec)
    return cats


def ask(prompt, default=None):
    try:
        raw = input(prompt).strip()
    except EOFError:
        raise KeyboardInterrupt
    return raw if raw else (default if default is not None else "")


def prompt_params(spec):
    """Collect values for a tool's params. Returns a dict, or None if cancelled."""
    values = {}
    print(f"\n  {spec.name} - {spec.summary}")
    if spec.note:
        print(f"  note: {spec.note}")
    print("  (enter 'b' at any required field to go back)\n")
    for p in spec.params:
        if p.kind == "flag":
            ans = ask(f"    {p.label}? [y/N]: ").lower()
            values[p.key] = ans in ("y", "yes")
            continue
        if p.kind == "choice" and p.choices:
            opts = "/".join(c or "(none)" for c in p.choices)
            label = f"    {p.label} [{opts}]"
        else:
            label = f"    {p.label}"
        if p.default not in (None, ""):
            label += f" (default {p.default})"
        label += ": " if p.required else " (optional): "
        ans = ask(label, default=p.default)
        if p.required and ans == "b":
            return None
        if p.required and not ans:
            while not ans:
                ans = ask(f"    {p.label} is required: ")
                if ans == "b":
                    return None
        values[p.key] = ans
    return values


def run_tool(spec):
    values = prompt_params(spec)
    if values is None:
        return
    print(f"\n  $ {runner.preview_cmd(spec, values)}\n")
    if ask("  Run this? [Y/n]: ", default="y").lower() in ("n", "no"):
        return
    print("  running...\n" + "-" * 60)
    rc, out = runner.run(spec, values, timeout=900)
    print(out.rstrip("\n"))
    print("-" * 60 + f"  [exit {rc}]")
    ask("\n  (enter to continue) ")


def pick(items, prompt):
    """Show a numbered list; return the chosen item, or None for back/quit."""
    for i, (label, desc) in enumerate(items, 1):
        print(f"   {i:>2}) {label:<24} {desc}")
    print("    b) back / quit")
    choice = ask(f"\n  {prompt}: ").lower()
    if choice in ("b", "q", ""):
        return None
    if choice.isdigit() and 1 <= int(choice) <= len(items):
        return int(choice) - 1
    print("  [invalid choice]")
    return pick(items, prompt)


def loop(registry):
    cats = by_category(registry)
    cat_names = list(cats)
    print(BANNER)
    while True:
        print()
        idx = pick([(name, f"{len(cats[name])} tools") for name in cat_names],
                   "category")
        if idx is None:
            print("  bye.")
            return
        category = cat_names[idx]
        while True:
            print(f"\n  == {category} ==")
            tools = cats[category]
            tidx = pick([(t.name, t.summary) for t in tools], "tool")
            if tidx is None:
                break
            try:
                run_tool(tools[tidx])
            except KeyboardInterrupt:
                print("\n  [cancelled]")

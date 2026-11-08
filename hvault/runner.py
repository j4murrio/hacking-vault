"""Run a registered tool as a subprocess and capture its output.

Tools are invoked as `python <script> <argv>` with the argv built from the
ToolSpec, never through a shell, so a value can only ever be an argument to the
tool it belongs to - it cannot inject a second command.
"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def script_path(spec):
    return ROOT / spec.script


def run(spec, values, timeout=None):
    """Run a tool. Returns (returncode, combined_output)."""
    path = script_path(spec)
    if not path.exists():
        return 127, f"[-] Script not found: {path}"
    cmd = [sys.executable, str(path)] + spec.argv(values)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            cwd=str(ROOT), encoding="utf-8", errors="replace",
            stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired as e:
        partial = (e.stdout or "") + (e.stderr or "")
        return 124, partial + f"\n[-] Timed out after {timeout}s"
    except OSError as e:
        return 1, f"[-] Could not launch: {e}"
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def preview_cmd(spec, values):
    """The command line that run() would execute, for display."""
    return "python " + spec.script + " " + " ".join(spec.argv(values))

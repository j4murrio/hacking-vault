# configs

Reusable configuration for the pentest environment.

**Uses / requires:** `tmux` (≥ 1.9 for the copy-mode key tables).

| File | What it is |
|------|------------|
| [tmux-pentest.conf](tmux-pentest.conf) | tmux tuned for engagements: mouse + long scrollback, vi copy mode, path-aware splits, and `Prefix P` to log a pane to a timestamped file for evidence. |

## tmux config

Try it without touching your setup:

```bash
tmux -f configs/tmux-pentest.conf
```

Adopt it permanently:

```bash
cp configs/tmux-pentest.conf ~/.tmux.conf   # then: tmux, or Prefix r to reload
```

Key bindings (default prefix `Ctrl-b`): `|` / `-` split vertical/horizontal,
`r` reload, `P` start/stop logging the current pane, `v`/`y` select/yank in copy mode.

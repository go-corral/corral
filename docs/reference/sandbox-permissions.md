# Sandbox filesystem baseline

> Generated from `internal/sandbox/baseline/sandbox-permissions.json` by
> `go test ./internal/sandbox -update`. **Do not edit by hand.**

The sandbox exposes **only** the paths below — deny-by-default: a path is
reachable inside the sandbox only if a rule allows it. This is the safe base
filesystem and nothing more. Feature mounts (docker socket, ssh-agent socket,
kubeconfig) come from **Providers**, not this baseline; the per-launch working
directory and your config `providers.paths.rw/ro` are layered on top at launch.

This baseline is **agent-neutral**: the paths the *selected* agent needs outside
its config dir (e.g. Claude Code's `~/.claude.json`) are contributed by that agent
and folded in at launch, so they appear only when that agent runs — they are not
listed here. See `docs/reference/agents.md`.

Tokens (`$HOME`, `$AGENT_CONFIG_DIR`, …) are expanded per launch.

## Linux

| Path | Access | Flags | Description |
| --- | --- | --- | --- |
| `/opt` | ro | — | System binaries (opt) |
| `/usr` | ro | — | System binaries and libraries |
| `/bin` | ro | — | System binaries |
| `/lib` | ro | — | System libraries |
| `/lib64` | ro | optional | 64-bit system libraries |
| `/etc/resolv.conf` | ro | node, resolve-symlinks | DNS resolver config |
| `/etc/hosts` | ro | node | Static host table |
| `/etc/ssl` | ro | — | TLS trust store |
| `/etc/ca-certificates` | ro | — | CA certificates |
| `/etc/passwd` | ro | node | User lookup |
| `/etc/group` | ro | node | Group lookup |
| `/etc/nsswitch.conf` | ro | node | NSS config |
| `/etc/localtime` | ro | node | Local timezone |
| `$HOME/.gitconfig` | ro | optional, node, resolve-symlinks | Git identity |
| `$HOME/.gitignore_global` | ro | optional, node, resolve-symlinks | Global gitignore (core.excludesFile) |
| `$HOME/.config/git` | ro | optional | Git config |
| `$HOME/.config/ccstatusline` | ro | optional | Status-line config |
| `$HOME/.config/corral` | ro | optional | corral's own config, read-only: the in-sandbox PreToolUse hook re-loads it to rebuild the policy engine, so it must be readable inside the sandbox (on macOS Seatbelt a visible-but-denied read is a hard EPERM that fails the hook closed). Read-only so the agent cannot widen its own policy mid-session. |
| `$HOME/.local/bin` | ro | optional | User-installed tools |
| `$HOME/.local/share/uv` | ro | optional | uv tool data |
| `$AGENT_CONFIG_DIR` | rw | — | Agent config dir: sessions, history, caches |

## macOS — Seatbelt

| Path | Access | Flags | Description |
| --- | --- | --- | --- |
| `/opt` | ro | — | System binaries (opt) |
| `/usr` | ro | — | System binaries and libraries |
| `/bin` | ro | — | System binaries |
| `/etc/resolv.conf` | ro | node, resolve-symlinks | DNS resolver config |
| `/etc/hosts` | ro | node | Static host table |
| `/etc/ssl` | ro | — | TLS trust store |
| `/etc/ca-certificates` | ro | — | CA certificates |
| `/etc/passwd` | ro | node | User lookup |
| `/etc/group` | ro | node | Group lookup |
| `/etc/nsswitch.conf` | ro | node | NSS config |
| `/etc/localtime` | ro | node | Local timezone |
| `/System` | ro | — | dyld shared cache and frameworks |
| `/Applications` | ro | — | macOS Applications |
| `/private/var/select` | ro | — | macOS shell selector — /bin/sh reads /var/select/sh at startup. A single /var leaf; the broad /private/var stays denied by absence. |
| `/private/var/db/timezone` | ro | — | Local timezone data (/etc/localtime resolves here on macOS). A single /var/db leaf; the broad /private/var stays denied by absence. |
| `/private/var/db/xcode_select_link` | ro | node | Active Xcode/CommandLineTools selector (xcrun/git/clang readlink it to find the toolchain; target is under /Library, already granted). A single /var/db leaf. |
| `/sbin` | ro | — | System binaries |
| `/Library` | ro | — | macOS frameworks and locale data |
| `/` | ro | node | Root dir node (dyld reads it at launch); traversal only, no subtree |
| `/etc` | ro | node | /etc symlink (kernel readlink to /private/etc) |
| `/tmp` | ro | node | /tmp symlink (kernel readlink to /private/tmp) |
| `/var` | ro | node | /var symlink node — REQUIRED to resolve /var/... paths (e.g. /bin/sh reads /var/select/sh). Grants no /var CONTENT: the broad /private/var is absent. |
| `/dev/null` | rw | node | Null device |
| `/dev/zero` | rw | node | Zero device |
| `/dev/tty` | rw | node | Controlling terminal |
| `/dev/ptmx` | rw | node | Pty master (Bash tool / interactive shell) |
| `/dev/stdin` | rw | node | Standard input |
| `/dev/stdout` | rw | node | Standard output |
| `/dev/stderr` | rw | node | Standard error |
| `/dev/random` | ro | node | Randomness source |
| `/dev/urandom` | ro | node | Randomness source (non-blocking) |
| `/dev/dtracehelper` | rw | node | node DTrace USDT probe registration |
| `/dev/autofs_nowait` | rw | node | autofs do-not-block control device |
| `^/dev/ttys` | rw | regex | Pty slaves (Bash tool / interactive shell) |
| `^/dev/fd/` | rw | regex | Process-substitution / inherited fds |
| `$HOME/.gitconfig` | ro | optional, node, resolve-symlinks | Git identity |
| `$HOME/.gitignore_global` | ro | optional, node, resolve-symlinks | Global gitignore (core.excludesFile) |
| `$HOME/.config/git` | ro | optional | Git config |
| `$HOME/.config/ccstatusline` | ro | optional | Status-line config |
| `$HOME/.config/corral` | ro | optional | corral's own config, read-only: the in-sandbox PreToolUse hook re-loads it to rebuild the policy engine, so it must be readable inside the sandbox (on macOS Seatbelt a visible-but-denied read is a hard EPERM that fails the hook closed). Read-only so the agent cannot widen its own policy mid-session. |
| `$HOME/.local/bin` | ro | optional | User-installed tools |
| `$HOME/.local/share/uv` | ro | optional | uv tool data |
| `$AGENT_BIN_DIR` | ro | optional | Directory of the resolved agent binary |
| `$HOME/Library/Keychains` | rw | — | macOS Keychain |
| `$SESSION_TMPDIR` | rw | — | Per-session temp dir (TMP/TMPDIR/TEMPDIR plus the selected agent's temp override — e.g. claude's CLAUDE_CODE_TMPDIR — point here, and TMPPREFIX=<dir>/zsh so zsh's heredoc temp files land inside it too; Linux uses /tmp/claude in the tmpfs instead) |
| `$AGENT_CONFIG_DIR` | rw | — | Agent config dir: sessions, history, caches |


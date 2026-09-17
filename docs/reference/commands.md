# Command reference

```
corral <command> [flags]
```

`corral <command> -h` prints the command's flags. Flags accept one dash or two
(`-yes` and `--yes` are the same flag).

## corral run

```
corral run [agent] [flags] [-- agent-args]
```

Launches `claude` (the default) or `pi` inside the sandbox. The agent positional,
when given, must be the first token; everything after `--` is passed to the agent
unchanged. Before a real run, new or changed repository config and any enabled
session-hook executable require interactive
[content approval](../explanation/trust-gate.md) before launch.

| Flag               | Effect                                                                                                   |
| ------------------ | -------------------------------------------------------------------------------------------------------- |
| `--dry-run`        | Print the sandbox command and exit. Does not create a credential or run a session hook.                  |
| `--profile <name>` | Apply a named [profile](config.md#profiles); `-p` for short. Repeatable; later profiles win.             |
| `--yes`            | Skip the interactive confirmation shown when a launch raises warnings. Does not approve new repo config. |
| `--home <dir>`     | Home directory inside the sandbox (default: `$HOME`).                                                    |
| `--project <dir>`  | Project directory mounted read-write (default: the current directory).                                   |
| `--command <path>` | Program to run inside the sandbox (default: the agent's binary on `PATH`).                               |
| `--backend <name>` | Sandbox backend, `bwrap` or `seatbelt` (default: this OS's backend).                                     |
| `--bwrap <path>`   | Path to the bwrap binary (default: `bwrap`).                                                             |

## corral sync

```
corral sync [agent] [flags]
```

Updates the selected agent's corral files. For `claude`, it merges policy-hook
registrations into `settings.json` and preserves other settings. For `pi`, it installs
the bare-session presence warning. Each `corral run pi` loads pi's policy extension
separately.

Sync compares the current files before writing, so running it when everything is current
changes nothing. `--remove` removes only what corral installed; a later plain
`corral sync` installs it again. A real sync, including `--remove`, requires approval for
new or changed repository config. `--dry-run` does not.

Each saved Claude Code command checks that the registered corral binary still exists
before running it. Sync also recognizes an older `<bin> hook <sub>` registration and
replaces it with the checked form.

`--binary` resolves a relative path against the current directory before saving it. It
rejects paths containing a double quote, `$`, a backtick, a backslash, or a control
character because those characters would remain active in the saved shell command. If
validation fails, sync writes nothing.

| Flag                | Effect                                                                                          |
| ------------------- | ----------------------------------------------------------------------------------------------- |
| `--dry-run`         | Print what would change without writing.                                                        |
| `--remove`          | Remove corral's hook entries (claude) or presence-warning extension (pi).                       |
| `--settings <path>` | `settings.json` to update (claude; default: `$CLAUDE_CONFIG_DIR` or `~/.claude/settings.json`). |
| `--binary <path>`   | corral binary path to register (claude; default: this executable).                              |

## corral doctor

```
corral doctor [flags]
```

Checks whether the current host is ready to run corral. The report covers the sandbox
backend, every supported agent binary and policy integration, provider prerequisites,
config health, and approval state. `doctor` takes no agent positional; it reports every
agent at once.

For Claude Code, the settings check prints one line. A healthy line reports that all
hooks are registered for this binary. Otherwise it names stale events (an older bare
registration or a different corral binary) and missing events, for example `stale for
PreToolUse, PostToolUse; missing for SessionStart — run corral sync`. `doctor` also
warns when `CORRAL_DISABLE_HOOKS` is set in the invoking shell and reports "set but not
recognized" for an unrecognized value such as `0`.

| Flag               | Effect                                                                |
| ------------------ | --------------------------------------------------------------------- |
| `--backend <name>` | Sandbox backend to check, `bwrap` or `seatbelt` (default: this OS's). |

## corral validate

```
corral validate [flags]
```

Reports config validity, followed by any advisory warnings and sections for configuration
sources, sandbox settings including the resolved private home, the selected agent,
filesystem access, environment passthrough, and enabled providers. Config files appear in
low-to-high precedence order. Provider rows describe what they add to the sandbox and their
setup-error behavior. This command only validates the config; use `corral doctor` to check
system prerequisites.

You can run `validate` on unapproved repository config before deciding whether to approve the files.

| Flag               | Effect                                                                     |
| ------------------ | -------------------------------------------------------------------------- |
| `--profile <name>` | Overlay a named [profile](config.md#profiles); `-p` for short. Repeatable. |
| `--list`           | List every effective blocked path, not just the count.                     |

## corral gc

```
corral gc [flags]
```

Finds provider resources left by a crashed session, such as a per-session
ServiceAccount, and the temporary kubeconfig under `~/.cache/corral/`. It previews the
results and asks before deleting them.

| Flag               | Effect                                                                     |
| ------------------ | -------------------------------------------------------------------------- |
| `--dry-run`        | Preview orphaned resources without deleting anything.                      |
| `--yes`            | Skip the confirmation prompt and delete all previewed resources.           |
| `--profile <name>` | Overlay a named [profile](config.md#profiles); `-p` for short. Repeatable. |

## corral update

```
corral update [flags]
```

Downloads the release archive for this OS and architecture, verifies it against the
release's SHA-256 checksums. A mismatch aborts without touching the installed
binary. After confirmation, the command replaces the binary in place. The release
source (owner and repository on GitHub) is fixed when corral is built. If the
repository is private, set `GITHUB_TOKEN` (or `GH_TOKEN`) so the download can
authenticate; a public repository needs no token.

| Flag                   | Effect                                                                          |
| ---------------------- | ------------------------------------------------------------------------------- |
| `--check`              | Only report whether a newer version exists; download nothing.                   |
| `--timeout <duration>` | Overall network deadline for the release check and download (default: `1m30s`). |
| `--yes`                | Install without the prompt; required non-interactively.                         |

## corral uninstall

```
corral uninstall [flags]
```

Lists corral's agent registrations, cache, state, and audit logs without deleting
anything. `--apply` removes them in confirmed steps: provider resources left by crashed
sessions, each agent's corral files, the cache, repository approval records, and audit
logs. The binary, global config, and helper plugin are not deleted; the report gives the
command for removing each one by hand.

| Flag      | Effect                                                                |
| --------- | --------------------------------------------------------------------- |
| `--apply` | Perform the removal (default: list managed state and delete nothing). |
| `--yes`   | Skip the per-step confirmations. Requires `--apply`.                  |

## corral hook

The policy enforcer. The agent integration invokes it for tool calls, prompts, and
selected tool results, with a JSON event on stdin. For a tool call, exit `0` allows the
call and exit `2` blocks it. `corral sync` registers the command; you never run it by
hand.

## corral version

Prints the version. `--version` and `-v` are aliases.

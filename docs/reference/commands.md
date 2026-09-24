# Command reference

```
corral <command> [flags]
```

`corral <command> -h` prints the command's flags. Flags accept one dash or two
(`-yes` and `--yes` are the same flag).

Errors print as `✗ <message>` and warnings as `! <message>`. `→` names the command that
fixes a problem. When the locale is not UTF-8, the output uses ASCII: `[x]`, `[!]`,
`[ok]`, and `->`. The command after the arrow is never changed. Color is off when the output is not a terminal, `NO_COLOR` is set, or
`TERM` is `dumb`. The `hook` enforcer's output is plain text.

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

Sync prints one line per message, marked `✓`, or unmarked with `--dry-run`, then the
`settings.json` diff:

```text
corral sync   claude
  ✓ updated /home/alice/.claude/settings.json — registered hooks: PreToolUse, PostToolUse, SessionStart, UserPromptSubmit:
--- /home/alice/.claude/settings.json (current)
+++ /home/alice/.claude/settings.json (after sync)
```

If the registered binary is outside every directory the sandbox mounts, sync warns on
stderr that the policy hook cannot run inside the sandbox.

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

Checks whether the current host is ready to run corral. `doctor` takes no agent
positional; it reports every installed agent at once. It checks the host only; run
`corral validate` for the effective policy.

The report starts with a verdict line that counts failed, warning, and passed checks. One
row per area follows. A row shows the worst check in its area, then `+N` for the other
failed or warning checks in that area:

```text
1 failed  ·  2 warnings  ·  9 passed

sandbox     ✓ bwrap
config      ✓ global + project valid
agents      ! pi presence backstop out of date
providers   ✗ docker unavailable
environment ! hooks CORRAL_DISABLE_HOOKS=0 not recognized
update      ✓ up to date as of 2026-09-01
```

| Area          | Checks                                                                                   |
| ------------- | ---------------------------------------------------------------------------------------- |
| `sandbox`     | The backend binary. For bwrap, also the PID namespace and legacy TIOCSTI.                |
| `config`      | Config validity, and approval of repository config and session-hook executables.        |
| `agents`      | Each installed agent and its policy integration, and the configured agent if missing.    |
| `providers`   | The host prerequisite of each enabled provider, such as a Docker socket or an SSH agent. |
| `environment` | `CORRAL_DISABLE_HOOKS` in the shell that runs `doctor`.                                  |
| `update`      | The cached result of the last update check, and the launch check setting. No network.   |

When a check fails or warns, the **needs attention** section lists it with its reason.
If a command fixes the problem, the line after the reason shows it:

```text
needs attention ──────────────────────────────────────────────────
  ✗ docker          unavailable
                    required in config, so the launch stops here
  ! pi              presence backstop out of date
                    ~/.pi/agent/extensions/corral-presence.ts
                    → corral sync pi
```

- **Claude Code hooks:** a healthy check reports `registered for this binary`. Otherwise
  it reports `not registered`, or it names stale events (an older registration or a
  different corral binary) and missing events, for example
  `stale for PreToolUse; missing for SessionStart`. Run `corral sync claude`.
- **pi presence warning:** the `presence backstop` check reports a missing or outdated
  extension. Run `corral sync pi`.
- **Providers:** an unavailable provider fails when the config requires it and warns
  when it is optional. With an invalid config, `doctor` does not check providers.
- **Update check:** `update.checkOnStart: false` warns with the date of the last check.
  Run `corral update --check`.
- **`CORRAL_DISABLE_HOOKS`:** `1` or `true` warns that agents started from this shell
  run without hooks. Other values, such as `0`, warn that hooks stay active. Run
  `unset CORRAL_DISABLE_HOOKS`.
- **Legacy TIOCSTI:** when the kernel allows it, run
  `sudo sysctl -w dev.tty.legacy_tiocsti=0`.

| Flag               | Effect                                                                |
| ------------------ | --------------------------------------------------------------------- |
| `--backend <name>` | Sandbox backend to check, `bwrap` or `seatbelt` (default: this OS's). |

## corral validate

```
corral validate [flags]
```

Reports config validity and the effective policy. It does not check the host; use
`corral doctor` to check system prerequisites.

The report starts with a verdict line that counts the config sources and the warnings.
The rows below it show the sources in low-to-high precedence order with the approval
state of repository config, the extra read-write and read-only grants, and the number of
blocked paths:

```text
✓ config valid  ·  3 sources  ·  2 warnings

sources     global, project approved, profile k8s
writable    ~/work/cache
read-only   /usr/share/doc /etc/ssl
blocked     7 paths: 6 always blocked + 1 configured
            list with corral validate --list --profile k8s
```

Sections follow:

| Section         | Content                                                                                                                                                                                                                                                        |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `warnings`      | Advisory warnings about the config, and repository config or session-hook executables that are not approved, changed since approval, or unreadable. Shown only when there are warnings.                                                                        |
| `blocked paths` | Each effective blocked path, marked `always blocked` or `configured`. Shown only with `--list`.                                                                                                                                                                |
| `settings`      | Each loaded config file with its approval state, the private home, network, hostname, agent settings, environment passthrough names, session-hook executables, and one row per enabled provider with what it adds to the sandbox and its setup-error behavior. |
| `path grants`   | The working directory and each extra grant in one tree, with its access (`rw` or `ro`) and the config that grants it.                                                                                                                                          |

```text
path grants ──────────────────────────────────────────────────────
    ~
    ├── src/corral            rw   project
    └── work/cache            rw   providers.paths.rw
```

Only the rows with an access token are grants. The other tree entries only group paths.
A read-only grant under a read-write path stays writable, so it shows as `rw` with the
source `providers.paths.ro (no effect)`. Run from `$HOME`, the project is a scratch
directory, because `corral run` does not mount the home directory read-write.

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
results and asks before deleting them:

```text
corral gc   1 orphaned resource
  ● kubernetes      ServiceAccount corral/corral-alice-4242-1a2b3c4d (user=alice session=4242-1a2b3c4d)
Reap these 1 resource(s)? [y/N] y
  ✓ reaped 1 resource
```

With nothing to delete, `gc` prints `✓ no orphaned resources`. A provider that cannot
list its resources prints a `!` line. When that happens and no orphans are found, `gc`
prints `! no orphaned resources` and exits 1.

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

```text
corral update
  ! 0.20.0 → 0.21.0 available
    binary          /usr/local/bin/corral
Proceed with the update? [y/N] y
  ✓ updated to 0.21.0
                    re-run corral sync if a release note says the hook
                    registration changed
                    → corral sync
```

When the binary is current, `update` prints `✓ up to date`.

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

The report has three sections: `enforcement`, `state` (removed by `--apply`), and `kept`.
`●` marks an item that is present and `○` an item that is not. With `--apply`, each step
prints its own section and marks each deletion `✓ deleted <path>` or
`✗ cannot delete <path>`. The command ends with `✓ done` or
`✗ finished with errors (see above)`.

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

# Agent reference

corral supports Claude Code, pi, and opencode. All three use the same sandbox, policy rules, providers, and config layers.

## Select an agent

| Method                                             | Behavior                                                                                   |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `agent: claude`, `agent: pi`, or `agent: opencode` | Selects the default agent. The default is `claude`.                                        |
| `corral run pi` or `corral run opencode`           | Overrides `agent` for one launch.                                                          |
| `corral sync pi` or `corral sync opencode`         | Synchronizes the persistent presence warning of that agent instead of Claude Code's hooks. |
| `corral doctor`                                    | Reports readiness for every supported agent; it takes no agent argument.                   |

Arguments for the agent go after `--`, for example `corral run pi -- --help`.

## Compare enforcement and state

|                          | Claude Code                                             | pi                                         | opencode                                              |
| ------------------------ | ------------------------------------------------------- | ------------------------------------------ | ----------------------------------------------------- |
| In-session policy        | Hooks registered in `settings.json`                     | Read-only policy extension loaded by `run` | Read-only policy plugin loaded by `run`               |
| `corral sync`            | Merges corral's hook registrations into `settings.json` | Installs the presence-warning extension    | Installs the presence-warning plugin                  |
| Default config directory | `~/.claude`                                             | `~/.pi/agent`                              | `~/.config/opencode`                                  |
| Config relocation        | `CLAUDE_CONFIG_DIR`                                     | `PI_CODING_AGENT_DIR`                      | `OPENCODE_CONFIG_DIR`                                 |
| Bare-agent warning       | `UserPromptSubmit` hook                                 | `corral-presence.ts` installed by sync     | `corral-presence.js` installed by sync                |
| Startup update behavior  | Depends on install method                               | `PI_OFFLINE=1` disables update checks      | `OPENCODE_DISABLE_AUTOUPDATE=1` disables update check |

`corral run` warns when the selected agent's corral files are missing or stale. Run `corral sync` for the affected agent.

## Deny format

If a tool call is denied, the block message follows a fixxed format:

```text
blocked by corral policy [hook:<rule>]: <reason>. Fix: <fix text>
```

- `[hook:<rule>]` describes the layer and the rule that fired: `always-blocked`, `blocked-path`, `ai-ignore`, `bash`, `path-pattern`, or `secret-scan`.
- `Fix:` describes the setting that the agent proposes to the user.

Claude Code receives the text as `permissionDecisionReason` of the `PreToolUse` decision. The pi and opencode extensions show the stderr line as the block reason. The stderr line has the same text after the prefix `corral: `.

When corral cannot check a call, the message is `None. Corral could not check this call, so it blocked it. Tell the user the error.`

When a call ran but corral hid its output, the replacement output has this format:

```text
output withheld by corral policy [hook:<rule>]: <reason>. The call ran. Fix: <fix text>
```

For the fix of each rule, see [The hook blocked my command](../how-to/troubleshooting.md#the-hook-blocked-my-command) and [A tool output is withheld](../how-to/troubleshooting.md#a-tool-output-is-withheld).

## Claude Code

`corral sync` registers `PreToolUse`, `PostToolUse`, `SessionStart`, and
`UserPromptSubmit` commands in Claude Code's `settings.json`. It preserves other
settings and does nothing when corral's entries are already current. A missing
registered corral binary is ignored outside the sandbox. Inside a corral session, the
saved command exits `2`: Claude blocks `PreToolUse` and `UserPromptSubmit`, but a
`PostToolUse` exit cannot replace the original tool result, so that result may reach the
model unscanned. `corral run` warns about a missing or stale registration; repair it with
`corral sync` before continuing.

corral binds the Claude config directory read-write so account and session state
persist. Policy prevents the agent from editing enforcement settings, registered
hook scripts, and other protected control files through tool calls.

Claude Code also uses these paths outside its config directory:

- `~/.claude.json` on Linux and macOS;
- `~/.claude.json.*` and `~/Library/Caches/claude-cli-nodejs` on macOS;
- `~/.local/share/claude` for native-installer binaries and resources.

corral grants these only for Claude Code. The native-installer tree is read-only,
so Claude Code's background updater and `claude update` cannot replace it from
inside the sandbox. Update Claude Code outside corral. To silence its updater
notice, set `DISABLE_AUTOUPDATER=1` through `providers.env.set`. npm installations
elsewhere are unaffected.

### Claude Code settings

| Config key                         | Default | Effect inside the sandbox                                                                                                                    |
| ---------------------------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `agents.claude.claudeaiConnectors` | `false` | Prevents loading claude.ai account connectors.                                                                                               |
| `agents.claude.telemetry`          | `false` | Disables operational telemetry.                                                                                                              |
| `agents.claude.errorReporting`     | `false` | Disables Sentry error reporting.                                                                                                             |
| `agents.claude.feedbackSurvey`     | `false` | Disables session-quality surveys.                                                                                                            |
| `agents.claude.attributionHeader`  | `true`  | Keeps Claude Code's system-prompt attribution block. Set `false` for a local model or gateway that should omit it.                           |
| `agents.claude.agentView`          | `false` | Disables [agent view](https://code.claude.com/docs/en/agent-view). Its background sessions cannot outlive the sandbox.                       |
| `agents.claude.args`               | `[]`    | Arguments passed to `claude` on every `corral run`, before the arguments after `--`. See [`agents.<agent>.args`](config.md#agentsagentargs). |

`corral validate` reports the connector, telemetry, error-reporting, survey, and
agent view settings, and the configured arguments. See
[`agents.claude`](config.md#agentsclaudeclaudeaiconnectors) for the environment
variables corral sets.

Claude Code's fullscreen TUI can replace the terminal screen containing corral's
startup banner. Unless `settings.json` contains `"tui": "default"`, corral warns
before launch. Run `/tui default` in Claude Code to keep the banner in scrollback,
or use `--yes` when you have reviewed the warning and do not need the pause.

## pi and opencode

pi and opencode have no built-in sandbox. For each `corral run pi` or `corral run opencode`, corral mounts a read-only policy extension (pi) or plugin (opencode) that exists only for that corral-launched session. It checks tool calls, tool results, and prompts, and sends each event to the sidecar.

### Presence warning

`corral sync pi` installs `corral-presence.ts` in pi's global extensions directory. `corral sync opencode` installs `corral-presence.js` in `<config directory>/plugins/`, by default `~/.config/opencode/plugins/corral-presence.js`. Neither file enforces policy, because the per-launch policy extension or plugin is absent from a bare process. Inside corral the opencode plugin does nothing.

- **pi:** warns once when pi starts without corral.
- **opencode:** replaces the first prompt of each session with a warning that names `corral run opencode`. The model relays the warning and the user resubmits the prompt. A subagent session gets no warning.

`corral sync <agent> --remove` removes only this file. To stop the warning without corral, delete the file.

### Arguments and environment

`agents.pi.args` and `agents.opencode.args` add arguments passed to the agent on every run. See [`agents.<agent>.args`](config.md#agentsagentargs).

corral sets `PI_OFFLINE=1` for pi and `OPENCODE_DISABLE_AUTOUPDATE=1` for opencode. pi's startup version and package checks can invoke git over SSH while `~/.ssh` remains masked. To enable the checks or updates deliberately, override the variable with `providers.env.set`:

```yaml
providers:
  env:
    set:
      - name: PI_OFFLINE
        value: ""
```

corral reserves `PI_CODING_AGENT_DIR`, `PI_CODING_AGENT_SESSION_DIR`, `OPENCODE_CONFIG_CONTENT`, and `OPENCODE_CONFIG_DIR`: `providers.env.set` cannot change them.

### pi

pi loads the policy extension `corral-policy.ts` through the `-e` flag.

corral requires pi 0.86.0 or later. The policy extension adds the sandbox note to pi's system prompt as a section. pi stores this section once per session.

By default, corral binds the `~/.pi` directory read-write. pi keeps most account,
session, extension, and tool state under `~/.pi/agent`, while some tooling writes
siblings under `~/.pi`. Policy protects the global extensions directories against
agent edits while leaving account and session state writable.

If `PI_CODING_AGENT_DIR` is set, corral binds that directory instead. It forwards
`PI_CODING_AGENT_DIR` and `PI_CODING_AGENT_SESSION_DIR` from the host and does not allow
`providers.env.set` to replace them. The sandbox therefore uses the locations selected
by the host process.

### opencode

corral supports opencode 2.x. A policy plugin is placed at `~/.cache/corral/opencode-policy/index.js` and activated it `OPENCODE_CONFIG_CONTENT`. If `OPENCODE_CONFIG_CONTENT` is aleady set, corral merges its plugin into that value. The value must be strict JSON without comments.

The plugin maps opencode's tools to the names that the policy rules use. For example, `shell` is checked as `Bash` and `read` as `Read`. A `patch` call is checked as one write per file in the patch.

#### opencode directories

| Path                                           | Grant                   | Content                                   |
| ---------------------------------------------- | ----------------------- | ----------------------------------------- |
| `$OPENCODE_CONFIG_DIR` or `~/.config/opencode` | read-write              | Config, plugins, and instructions         |
| `~/.local/share/opencode`                      | read-write              | Sessions database, credentials and logs   |
| `~/.opencode/bin`                              | read-only, when present | Binary and shim of the official installer |

corral does not bind `~/.local/state/opencode` and `~/.cache/opencode`. These directories could share state outside the sandbox, the private-home contains sandboxed versions.

The following files are protected, writes and edits in tool calls will be prohibited:

- In the config directory: `opencode.json`, `opencode.jsonc`, `cli.json`, `service.json`, and the `plugin` and `plugins` directories.
- In any project: the `.opencode` directory itself, the `plugin` and `plugins` directories and the `cli.json` and `service.json` files in it, and every file named `opencode.json` or `opencode.jsonc`. opencode loads plugins from these locations.

#### opencode server and arguments

Without `--standalone`, opencode sends its work to a shared background service. That service would run outside the sandbox. So `corral run opencode` adds `--standalone`, except when the command is `acp`. It rejects `--server` in `agents.opencode.args` and after `--`, because that flag sends the work to a server outside the sandbox. It also rejects `--no-standalone`, `--standalone=<value>`, and `--standalone` followed by `false`, `no`, `off`, or `0` before the first `--`, because they let opencode use the shared service.

```text
corral run opencode -- run hello    ->  opencode run hello --standalone
corral run opencode -- acp          ->  opencode acp
```

The commands `serve`, `service`, `mcp add`, `plugin add`, `plugin remove`, `upgrade`, `uninstall`, `pair`, `debug paths`, and `debug heap-dump` reject `--standalone` and fail with opencode's usage error. They manage host state, run them without corral.

opencode takes only root flags before a subcommand, so the list accepts only root flags such as `--print-logs` and `-c`. Set the model with `model` in `opencode.json`. `--model` is a flag of `run`.

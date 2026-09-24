# Agent reference

corral supports Claude Code and pi. Both use the same sandbox, policy rules,
providers, and config layers. They differ in how they send events to corral and where
they store state.

## Select an agent

| Method | Behavior |
| --- | --- |
| `agent: claude` or `agent: pi` | Selects the default agent. The default is `claude`. |
| `corral run pi` | Overrides `agent` for one launch. |
| `corral sync pi` | Synchronizes pi's persistent presence warning instead of Claude Code's hooks. |
| `corral doctor` | Reports readiness for every supported agent; it takes no agent argument. |

An unsupported `agent` value is rejected when config loads. Arguments for the agent
go after `--`, for example `corral run pi -- --help`.

## Compare enforcement and state

| | Claude Code | pi |
| --- | --- | --- |
| In-session policy | Command hooks registered in `settings.json` | Read-only policy extension loaded by every `corral run pi` |
| `corral sync` | Merges corral's hook registrations into `settings.json` | Installs the global presence-warning extension |
| Default config directory | `~/.claude` | `~/.pi` |
| Config relocation | `CLAUDE_CONFIG_DIR` | `PI_CODING_AGENT_DIR` |
| Bare-agent warning | `UserPromptSubmit` hook registered by sync | `corral-presence.ts` installed by sync |
| Startup update behavior | Claude Code updater cannot modify a read-only native installation | `PI_OFFLINE=1` disables pi's startup update checks |

`corral run` warns when the selected agent's corral files are missing or stale. Run
`corral sync` for Claude Code or `corral sync pi` for pi, then confirm the result with
`corral doctor`.

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

| Config key | Default | Effect inside the sandbox |
| --- | --- | --- |
| `agents.claude.claudeaiConnectors` | `false` | Prevents loading claude.ai account connectors. |
| `agents.claude.telemetry` | `false` | Disables operational telemetry. |
| `agents.claude.errorReporting` | `false` | Disables Sentry error reporting. |
| `agents.claude.feedbackSurvey` | `false` | Disables session-quality surveys. |
| `agents.claude.attributionHeader` | `true` | Keeps Claude Code's system-prompt attribution block. Set `false` for a local model or gateway that should omit it. |
| `agents.claude.agentView` | `false` | Disables [agent view](https://code.claude.com/docs/en/agent-view). Its background sessions cannot outlive the sandbox. |

`corral validate` reports the connector, telemetry, error-reporting, survey, and
agent view settings. See
[`agents.claude`](config.md#agentsclaudeclaudeaiconnectors) for the environment
variables corral sets.

Claude Code's fullscreen TUI can replace the terminal screen containing corral's
startup banner. Unless `settings.json` contains `"tui": "default"`, corral warns
before launch. Run `/tui default` in Claude Code to keep the banner in scrollback,
or use `--yes` when you have reviewed the warning and do not need the pause.

## pi

pi has no built-in sandbox. For each `corral run pi`, corral mounts a read-only
policy extension named `corral-policy.ts` and passes it to pi with the `-e` flag. The
extension checks tool calls, tool results, and prompts. It exists only for that
corral-launched session.

`corral sync pi` installs `corral-presence.ts` in pi's global extensions directory.
This extension does not enforce policy. It warns once when pi starts without
corral, because the per-launch policy extension is absent from a bare `pi` process.
`corral sync pi --remove` removes only this presence warning.

By default, corral binds the `~/.pi` directory read-write. pi keeps most account,
session, extension, and tool state under `~/.pi/agent`, while some tooling writes
siblings under `~/.pi`. Policy protects the global extensions directories against
agent edits while leaving account and session state writable.

If `PI_CODING_AGENT_DIR` is set, corral binds that directory instead. It forwards
`PI_CODING_AGENT_DIR` and `PI_CODING_AGENT_SESSION_DIR` from the host and does not allow
`providers.env.set` to replace them. The sandbox therefore uses the locations selected
by the host process.

corral sets `PI_OFFLINE=1` because pi's startup version and package checks can invoke
git over SSH while `~/.ssh` remains masked. To enable those checks deliberately,
override it with:

```yaml
providers:
  env:
    set:
      - name: PI_OFFLINE
        value: ""
```

pi currently has no keys under `agents.pi`; an empty `agents.pi: {}` block is
accepted but unnecessary.

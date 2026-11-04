# Agent reference

corral supports Claude Code, pi, and opencode. All three use the same sandbox, policy rules,
providers, and config layers. They differ in how they send events to corral and where
they store state.

## Select an agent

| Method | Behavior |
| --- | --- |
| `agent: claude`, `agent: pi`, or `agent: opencode` | Selects the default agent. The default is `claude`. |
| `corral run pi` or `corral run opencode` | Overrides `agent` for one launch. |
| `corral sync pi` or `corral sync opencode` | Synchronizes the persistent presence warning of that agent instead of Claude Code's hooks. |
| `corral doctor` | Reports readiness for every supported agent; it takes no agent argument. |

An unsupported `agent` value is rejected when config loads. Arguments for the agent
go after `--`, for example `corral run pi -- --help`.

## Compare enforcement and state

| | Claude Code | pi | opencode |
| --- | --- | --- | --- |
| In-session policy | Command hooks registered in `settings.json` | Read-only policy extension loaded by every `corral run pi` | Read-only policy plugin loaded by every `corral run opencode` |
| `corral sync` | Merges corral's hook registrations into `settings.json` | Installs the global presence-warning extension | Installs the global presence-warning plugin |
| Default config directory | `~/.claude` | `~/.pi` | `~/.config/opencode` |
| Config relocation | `CLAUDE_CONFIG_DIR` | `PI_CODING_AGENT_DIR` | `OPENCODE_CONFIG_DIR` |
| Bare-agent warning | `UserPromptSubmit` hook registered by sync | `corral-presence.ts` installed by sync | `corral-presence.js` installed by sync |
| Startup update behavior | Claude Code updater cannot modify a read-only native installation | `PI_OFFLINE=1` disables pi's startup update checks | `OPENCODE_DISABLE_AUTOUPDATE=1` disables opencode's update check |

`corral run` warns when the selected agent's corral files are missing or stale. Run
`corral sync` for Claude Code, `corral sync pi` for pi, or `corral sync opencode` for opencode,
then confirm the result with `corral doctor`.

## Deny format

Every deny from a policy rule has one format:

```text
blocked by corral policy [hook:<rule>]: <reason>. Fix: <fix text>
```

- `[hook:<rule>]` names the layer and the rule that denied the call: `always-blocked`, `blocked-path`, `ai-ignore`, `bash`, `path-pattern`, or `secret-scan`.
- `Fix:` names the setting that the agent proposes to the user. A fix that starts with `None, by design.` has no setting.

Claude Code receives the text as `permissionDecisionReason` of the `PreToolUse` decision. The pi policy extension and the opencode policy plugin show the stderr line as the block reason. The stderr line has the same text after the prefix `corral: `.

When corral cannot check a call, the rule is `fail-closed`, the reason is the error, and the fix is `None. Corral could not check this call, so it blocked it. Tell the user the error.` Claude Code receives this text as the stderr line after the prefix `corral: `, with exit status 2. The pi policy extension and the opencode policy plugin show this text as the block reason.

When a call ran but corral hid its output, the replacement output has this format:

```text
output withheld by corral policy [hook:<rule>]: <reason>. The call ran. Fix: <fix text>
```

The rule is `response-secret` for a credential in the output, or `fail-closed` when corral could not scan the output. Every agent receives this text in place of the tool output.

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

| Config key | Default | Effect inside the sandbox |
| --- | --- | --- |
| `agents.claude.claudeaiConnectors` | `false` | Prevents loading claude.ai account connectors. |
| `agents.claude.telemetry` | `false` | Disables operational telemetry. |
| `agents.claude.errorReporting` | `false` | Disables Sentry error reporting. |
| `agents.claude.feedbackSurvey` | `false` | Disables session-quality surveys. |
| `agents.claude.attributionHeader` | `true` | Keeps Claude Code's system-prompt attribution block. Set `false` for a local model or gateway that should omit it. |
| `agents.claude.agentView` | `false` | Disables [agent view](https://code.claude.com/docs/en/agent-view). Its background sessions cannot outlive the sandbox. |
| `agents.claude.args` | `[]` | Arguments passed to `claude` on every `corral run`, before the arguments after `--`. See [`agents.<agent>.args`](config.md#agentsagentargs). |

`corral validate` reports the connector, telemetry, error-reporting, survey, and
agent view settings, and the configured arguments. See
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

corral requires pi 0.86.0 or later. The policy extension adds the sandbox note to pi's system prompt as a section. pi stores this section once per session.

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

`agents.pi.args` adds arguments passed to `pi` on every run. See [`agents.<agent>.args`](config.md#agentsagentargs).

## opencode

opencode has no built-in sandbox. For each `corral run opencode`, corral writes a policy plugin to `~/.cache/corral/opencode-policy/index.js`, binds its directory read-only, and activates it through `OPENCODE_CONFIG_CONTENT`. The plugin checks tool calls, tool results, and prompts. It adds the sandbox note to the system prompt of every model request. It sends each event to the sidecar and exists only for that corral-launched session.

corral supports opencode 2.x from 2.2.0 and does not check the version. Earlier 2.x builds can run a tool call before the plugin has loaded. opencode 1.x is not supported.

The plugin maps opencode's tools to the names that the policy rules use. For example, `shell` is checked as `Bash` and `read` as `Read`. A `patch` call is checked as one write per file in the patch. A `shell` call runs in its `workdir`, and the policy uses that directory. MCP tool calls get the same rules as Claude Code MCP calls, including the argument secret scan and the path audit. The plugin finds MCP tools through the configured MCP servers, so a tool of an MCP server that a client attaches at run time is checked like a plugin tool. A plugin or project tool with its own path key is checked only by the rules that do not depend on the tool name: `path`, `file_path`, and `command`.

If the host sets `OPENCODE_CONFIG_CONTENT`, corral merges its plugin into that value. The value must be strict JSON without comments. Otherwise the launch fails. To keep comments, move the value into an `opencode.json` file.

### opencode directories

| Path | Grant | Content |
| --- | --- | --- |
| `$OPENCODE_CONFIG_DIR` or `~/.config/opencode` | read-write | Config, plugins, and instructions. corral creates it when absent. |
| `~/.local/share/opencode` | read-write, when present | Sessions database, credentials, and logs. |
| `~/.opencode/bin` | read-only, when present | Binary and shim of the official installer. |

corral does not bind `~/.local/state/opencode` and `~/.cache/opencode`. The state directory holds the address and password of the background service. The cache directory holds helper binaries and npm plugin installs that the host opencode runs later. With the home provider on, the private home holds separate copies of both.

corral ignores the `XDG_*` variables for opencode and drops them from the sandbox. Inside the sandbox, opencode uses the default directories under `$HOME`. To relocate the config directory, set `OPENCODE_CONFIG_DIR`. A host `XDG_CONFIG_HOME` alone moves the host config away from the directory that corral binds. A host `XDG_DATA_HOME` gives separate session lists on the host and in the sandbox.

When `~/.local/share/opencode` is absent, opencode creates its data in the private home. Log in with opencode on the host before the first `corral run opencode`, so the credentials are in the bound directory.

Policy denies writes and deletes of these files from a tool call, in every session and for every agent. Reads stay allowed.

- In the config directory: `opencode.json`, `opencode.jsonc`, `cli.json`, `service.json`, and the `plugin` and `plugins` directories.
- In any project: the `.opencode` directory itself, the `plugin` and `plugins` directories and the `cli.json` and `service.json` files in it, and every file named `opencode.json` or `opencode.jsonc`. opencode loads plugins from these locations.

`AGENTS.md` stays writable.

### opencode server and arguments

Without `--standalone`, opencode sends its work to a shared background service. That service runs outside the sandbox and has no corral plugin. So `corral run opencode` adds `--standalone` before the first literal `--` in the arguments, or at the end. It adds nothing when `--standalone` is present before the first literal `--` or when the first argument is `acp`, which always starts a private server. It rejects `--server` in `agents.opencode.args` and after `--`, because that flag sends the work to a server outside the sandbox. It also rejects `--no-standalone`, `--standalone=<value>`, and `--standalone` followed by `false`, `no`, `off`, or `0` before the first `--`, because they let opencode use the shared service. The flags `--auto`, `--yolo`, and `--dangerously-skip-permissions` stay allowed: they answer opencode's own prompts and do not skip the plugin.

```text
corral run opencode -- run hello    ->  opencode run hello --standalone
corral run opencode -- acp          ->  opencode acp
```

The commands `serve`, `service`, `mcp add`, `plugin add`, `plugin remove`, `upgrade`, `uninstall`, `pair`, `debug paths`, and `debug heap-dump` reject `--standalone` and fail with opencode's usage error. They manage host state. Run them on the host without corral.

`agents.opencode.args` adds arguments passed to `opencode` on every run. See [`agents.<agent>.args`](config.md#agentsagentargs). opencode takes only root flags before a subcommand, so the list accepts only root flags such as `--print-logs` and `-c`. Set the model with `model` in `opencode.json`. `--model` is a flag of `run`.

corral sets `OPENCODE_DISABLE_AUTOUPDATE=1`. Override it with `providers.env.set`, as shown for `PI_OFFLINE` in the pi section. `OPENCODE_CONFIG_CONTENT` and `OPENCODE_CONFIG_DIR` are reserved: `providers.env.set` cannot change them.

### opencode presence warning

`corral sync opencode` installs `corral-presence.js` in `<config directory>/plugins/`, by default `~/.config/opencode/plugins/corral-presence.js`. The plugin does not enforce policy. When opencode starts without corral, it replaces the first prompt of each session with a warning that names `corral run opencode`. The model relays the warning and the user resubmits the prompt. A subagent session gets no warning. Inside corral the plugin does nothing. `corral sync opencode --remove` removes only this file. To stop the warning without corral, delete the file.

### opencode limits

The plugin does not cover these paths:

- The `!` shell mode. A command that the user types runs without a policy check, and its output reaches the model unscanned.
- The output of a background `shell` call. opencode adds it to the conversation later without a tool result, so the plugin does not scan it. The command itself is checked before it runs.
- Files mentioned in a prompt: the plugin scans the typed text and not the content of the file.
- A nested `opencode --server <url>` that the agent starts in a shell command: it sends work to a server that the sandbox can reach. A nested opencode without `--server` loads the plugin, unless the command sets its own `OPENCODE_CONFIG_CONTENT`.
- A plugin that fails to load: opencode logs a warning and runs without policy. The OS sandbox still applies.

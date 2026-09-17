# How corral works

corral combines an OS sandbox with policy checks on the coding agent's tools. The
sandbox limits which host files the process can reach. The policy code can reject a
specific command, file operation, prompt, or tool result.

## Prepare the session once, check each event

The `corral` binary has two execution paths:

- `corral run` prepares one session. It loads and validates config, asks for any
  required approval, checks providers, creates temporary credentials, builds the
  sandbox command, and starts the agent.
- `corral hook` evaluates the events sent by the agent, so it must start quickly. A
  malformed or failed `PreToolUse` check blocks the tool call. A failed `PostToolUse`
  scan replaces the result with a withheld marker. `UserPromptSubmit` scanning is
  advisory and allows the prompt on an internal failure; `SessionStart` can only add a
  note and cannot block.

Work that needs host access or user interaction belongs in `corral run`; the policy
hook never calls a provider or asks the user a question. A config error therefore stops
the launch. Tool calls and selected tool results follow the
[fail-closed rules](threat-model.md#2-the-hook-fails-closed); prompt warnings and the
session-start note do not.

## Start with the filesystem corral provides

The sandbox starts from an embedded
[filesystem allowlist](../reference/sandbox-permissions.md). Config can add read-only
or read-write paths, but it cannot remove baseline restrictions or expose an
always-blocked credential directory.

Provider settings add or remove specific access:

- `block` hides additional directories or files.
- `aiignore` hides paths matched by repository exclusion files.
- `paths` mounts the host paths you grant.
- `env` forwards selected host variables or sets fixed values.

`aiignore` and `env` are active on every launch. `block` and `paths` apply when their
config contains entries. The other providers handle access that needs more than a path
or environment setting:

- `ssh` forwards the host agent socket and selected read-only SSH configuration.
- `docker` mounts the host daemon socket and Docker configuration.
- `home` gives the session a persistent private `$HOME` and links allowed host paths
  into it. It is enabled by default.
- `kubernetes` creates a per-session ServiceAccount and requests a bounded token.
- `gitlab` creates a short-lived personal or project token from a host token.
- `hooks` runs approved host executables before or after the agent session.

Temporary Kubernetes and GitLab credentials are created outside the sandbox. The
host credential used to create them never enters the session. corral removes or
revokes the temporary credential on normal exit, and the credential has its own
expiry if cleanup cannot run.

## Report what the session can use

The startup banner tells you which paths and providers are active. Provider rows can
include the result of a session hook or the scope and expiry of a temporary
credential. `corral validate` lists the contributing config files and summarizes
selected effective policy before you launch.

The agent receives a shorter session note. It names access the agent needs to use
correctly, such as `GITLAB_TOKEN`, the active Kubernetes roles, or a relevant command
quirk. These notes contain metadata, not token values.

## Apply the same policy to Claude Code and pi

Claude Code and pi expose different ways to inspect their tool calls:

- For **Claude Code**, `corral sync` registers commands for `PreToolUse`,
  `PostToolUse`, `SessionStart`, and `UserPromptSubmit` in `settings.json`.
  `corral run` warns when those registrations are missing or stale. A registration
  whose corral binary is missing does nothing outside the sandbox. Inside a corral
  session, its fallback blocks `PreToolUse` and `UserPromptSubmit`, but Claude cannot
  use that fallback to replace a `PostToolUse` result; that result may pass through
  unscanned. Repair the registration before continuing.
- For **pi**, each `corral run pi` mounts a read-only policy extension and passes it to
  pi. `corral sync pi` installs only the warning shown by a bare pi process; it does not
  install persistent policy enforcement.

Both integrations use the same path, command, prompt, and secret-scanning rules. For
selection, state locations, and agent-specific settings, see the
[agent reference](../reference/agents.md).

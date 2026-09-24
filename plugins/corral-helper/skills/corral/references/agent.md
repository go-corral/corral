# Agent playbook: install, launch, and verify corral

Use this playbook when acting on the user's behalf. Canonical install, command, config,
and troubleshooting facts live in the linked references; do not duplicate them here.

## Establish the starting point

First determine whether corral is installed and which agent the user wants:

```sh
command -v corral
corral doctor
```

Inside the corral source checkout, build with `make build` and use `./bin/corral` instead.
Do not reinstall or rewrite integration that is already healthy. Read the command output
and address the failed check it names.

Offer to run safe checks and edits when the session permits it. Ask before changing shell
startup files or shared project config. An interactive `corral run` takes over the
terminal, and restarting the agent remains a user handoff.

## Install and hand over

If no binary is present, follow [install.md](how-to/install.md) exactly. Download the release for
the host OS and architecture, verify the published SHA-256 checksum, then install it on
`PATH`. Never skip verification after a failed download or checksum.

For Claude Code, use this order:

```sh
corral doctor
corral sync
corral doctor
corral validate
corral run -- <claude args>
```

For pi, use:

```sh
corral doctor
corral sync pi
corral doctor
corral validate
corral run pi -- <pi args>
```

The second `doctor` confirms the Claude Code hooks or pi presence-warning extension.
`validate` summarizes selected effective policy before launch. Read warnings first, then
check approval notices under **Configuration** and grants under **Filesystem**. Successful
approvals are silent. `[grant]` identifies grants; terminal output also renders them bold.
Other tree branches only group paths. `--list` shows blocked paths.
Repository config or session-hook executable approval requires an interactive terminal;
do not substitute `--yes` for that review.

If a step fails, use its output rather than restarting the sequence blindly. Common next
references are [troubleshooting.md](how-to/troubleshooting.md) for readiness or policy
failures, [agents.md](reference/agents.md) for agent-specific state, and
[install.md](how-to/install.md) for PATH or macOS Gatekeeper handling.

## Make sandboxed launch the default

Ask which shell startup file the user uses, inspect it for an existing alias, and offer to
add one without duplicating entries:

```sh
alias claude='corral run --'
alias pi='corral run pi --'
```

Add only the alias for the selected agent. Explain that `command claude` or `command pi`
bypasses an alias and starts a bare process. The synchronized presence warning is
advisory; a bare pi process has no corral policy enforcement, while a bare Claude process
retains only its registered hooks and has no filesystem sandbox.

If the current session cannot write the host shell file, give the user the exact line and
target file instead of claiming it was installed. A sync, alias, or config edit affects a
new process, not the already-running agent.

## Verify a fresh sandboxed session

After the user restarts through the alias or `corral run`:

1. Confirm the session-start message says the agent is inside corral.
2. Run `corral doctor` and check that the backend and agent integration are healthy.
3. Ask the sandboxed agent to read `~/.aws/credentials`; the always-blocked path must be
   refused. Do not attempt to inspect the file outside the sandbox.
4. If a provider was enabled, run the verification command from its setup guide:
   [providers.md](how-to/providers.md), [kubernetes.md](how-to/kubernetes.md), or
   [gitlab.md](how-to/gitlab.md).

Treat a failed probe as a diagnosis task. Capture `doctor`, `validate`, and the audit
record's `rule` and `reason`; the current session logs to the file in
`$CORRAL_AUDIT_PATH` (`echo "$CORRAL_AUDIT_PATH"` inside the session). Then follow
[troubleshooting.md](how-to/troubleshooting.md).

## Run commands for the user

Agent arguments go after `--`:

```sh
corral run -- --model opus
corral run pi -- --help
```

Use `corral run --dry-run -- <args>` to inspect the sandbox command. A dry run does not
run session hooks or create temporary credentials, so those results appear only during a
real launch. For profiles, backend overrides, warning prompts, and every flag, read
[commands.md](reference/commands.md).

Do not automatically add `--yes`. It acknowledges advisory launch warnings, but cannot
approve repository config or session-hook executables. Let the user review interactive
approval prompts.

When config must change, follow the minimal-overlay and layer-selection rules in the
skill, verify with `corral validate`, and remind the user to start a new session. Exact
keys and defaults are in [config.md](reference/config.md).

## Maintain or remove the installation

Use [upgrade.md](how-to/upgrade.md) for upgrades,
[commands.md](reference/commands.md#corral-gc) for resources left by crashed sessions,
and [uninstall.md](how-to/uninstall.md) for removal. Preview
destructive cleanup before asking for confirmation; do not imply that `corral uninstall`
removes the binary, global config, or plugin when the uninstall guide leaves those as
manual steps.

For a source build, use the repository's canonical entry point:

```sh
make build
```

The resulting binary is `./bin/corral`.

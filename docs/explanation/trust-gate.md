# Why repository config requires approval

A repository's `.corral.yml` and `.corral.local.yml` can enable providers, add
read-write paths, choose credential targets, and name session hooks that run on the
host. Because the repository author and the operator may be different people,
corral does not let a real `run` or `sync` proceed until the operator approves
these files interactively.

Approval is tied to the exact bytes of each file. The first real `run` or `sync`
prompts, and any later content change prompts again. This includes changes that do
not alter the parsed settings, such as comments.

corral stores approval records under `$XDG_STATE_HOME/corral/trust`, or
`~/.local/state/corral/trust` when `XDG_STATE_HOME` is unset. This is state rather
than cache, so clearing corral's cache does not remove approvals.

## Which files require approval?

The approval check covers repository-discovered `.corral.yml` and
`.corral.local.yml` files. The global config, normally
`~/.config/corral/config.yml`, is owned by the operator and is implicitly trusted.

Session-hook executables are handled separately. Before `corral run`, corral hashes
each readable executable named by an enabled `providers.hooks` entry. The executable
requires approval whether the entry came from repository config or global config.
This prevents a script in the writable project from being changed after its config
was approved and then silently run on the host at the next launch.

`corral sync` approves repository config but does not inspect session-hook
executables, because sync does not run them. Their approval is checked by the next
`corral run`.

## What happens if a file changes?

A changed repository config stops the next `corral run` or `corral sync`. A changed
session-hook executable stops the next `corral run`. The prompt names each new or
changed file so the operator can review it before approving the new content.

A `postEnd` executable needs one additional check because the agent can edit project
files during the session. corral hashes the executable before the agent starts and
again before running it. If the file changed, disappeared, or became unreadable,
corral skips that hook and prints a warning. Other `postEnd` hooks still run, and the
next launch requests approval for readable changed content.

## What can an approved session hook contribute?

A `preStart` hook can contribute environment variables, status text, and notes shown
to the agent. It cannot add sandbox mounts or filesystem grants. A
contribution that assigns corral's reserved control variables is rejected rather
than changing policy inputs or disabling enforcement. A required hook then fails
the launch; an optional hook continues without that contribution. See the
[session-hooks contract](../reference/hooks-contract.md#the-contribution-prestart-stdout)
for the accepted output.

Approval records the operator's decision to run particular file content. corral still
validates the hook's stdout before adding its environment variables or notes to the
session.

## How can I inspect unapproved config?

- `corral validate` lists config sources, summarizes selected effective settings, and
  annotates repository config and session-hook executables with their approval state.
- `corral doctor` reports approval state as part of its config and hook checks.
- `corral run --dry-run` builds the sandbox preview without requiring approval and
  notes files that a real run would ask you to approve.
- `corral sync --dry-run` previews agent synchronization without requiring approval.

A real `run` or `sync` requires a terminal for new approval. Non-interactive use
fails closed until an operator approves the files interactively. `--yes` acknowledges
advisory warnings; it does not approve repository-supplied files.

## What does approval not guarantee?

Approval records only that the operator accepted exact file content. corral does not
judge what the config or executable intends to do. Review the config with
`corral validate` and review executable changes before approving them.

For session hooks, only the configured `exec` file is hashed. Files that it sources,
programs that it invokes, and the interpreter named by its shebang are outside the
approval record. Review those dependencies as you would a Makefile or other build
entry point. If `exec` points directly to a system-managed binary, a package update
changes that binary and therefore requires approval again.

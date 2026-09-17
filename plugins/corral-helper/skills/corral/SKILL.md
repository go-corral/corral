---
name: corral
description: >-
  Help install, configure, run, update, uninstall, and troubleshoot corral, the coding-agent
  sandbox for Claude Code and pi. Trigger when the user mentions corral, a Claude sandbox,
  doctor/sync/validate/run, .corral.yml, provider setup, filesystem or environment grants,
  session hooks, blocked tool calls, the audit log, always-blocked paths (or the former name
  "secure floor"), masked credential directories, or a vague report that the sandbox will not
  allow something.
---

# corral helper

Help the user operate corral from evidence, make the smallest safe change, and verify the
result. Do not reconstruct commands, config keys, defaults, or security behavior from
memory when a reference or the running binary can answer.

For install-to-first-session work, read
[references/agent.md](references/agent.md) first. It is the operational playbook. The
other references are canonical user documentation; consult only those relevant to the
task.

## Required behavior

1. **Inspect before diagnosing.** Use real command output, effective config, and the audit
   record. Do not infer the user's setup from a snippet or from defaults remembered from a
   previous release.
2. **Do not bypass hard controls.** Never suggest disabling or spoofing policy,
   renaming secret material to evade scanning, or using symlinks to evade a blocked path.
   Some rules have no override.
3. **Write minimal config overlays.** Omit built-in defaults unless the user explicitly
   asks to pin them. Preserve unrelated existing settings, choose read-only access unless
   writes are required, and validate after editing.
4. **Use the right config layer.** Ask whether a change is global, shared with the project,
   or local to one user when that is not clear.
5. **Treat audit logs as potentially sensitive.** Inspect verbatim fields before sharing
   or asking the user to share a record.
6. **Offer to perform safe steps.** When tools and permissions allow, offer to run checks
   and make approved edits instead of only printing instructions. Explain steps that need
   the user's terminal or confirmation.

## Diagnose against the running environment

Use these interfaces before proposing a fix:

| Interface | Use it for |
| --- | --- |
| `corral doctor` | Binary, backend, agent integration, config health, provider availability, and update state. |
| `corral validate` | Sectioned config report: sources and approval notices, sandbox settings including the private home, agent settings, path grants, environment names, and enabled providers. It does not show per-field provenance or host availability. |
| `corral run --dry-run -- <agent args>` | The sandbox command that would launch, without running session hooks or creating temporary credentials. |
| The audit record's `rule` and `reason` | The policy decision behind a blocked tool call. |

Validation path trees identify configured grants with `[grant]`; terminal styling also makes
them bold. Do not infer access from grouping branches. `--list` expands blocked paths, not
directory contents.

Run `corral validate` on the host when its paths will guide a diagnosis or config change.
Inside an active corral session, `$HOME` is sandbox-private, so an in-session report is not
the host-effective path view; ask the user for host output instead.

If working in the corral source checkout, use `./bin/corral` after `make build`; otherwise
use the installed `corral` on `PATH`.

For a block:

1. Find the relevant audit line and read `rule` and `reason`.
2. Follow the matching supported action in
   [troubleshooting.md](references/how-to/troubleshooting.md).
3. Confirm any config change with host-side `corral validate`.
4. Start a new corral session and retry the original task.

The default audit path is under the selected agent's config directory, unless
`policy.audit.path` overrides it. Before sharing a record, inspect the Bash `command`,
WebSearch `query`, and WebFetch `url`: those values are recorded verbatim and can contain
an inline credential. Content bodies and most free-text values are byte-counted. See
[audit-log.md](references/reference/audit-log.md).

## Apply the security model

corral has two execution paths:

- `corral run` builds the OS sandbox, sets up enabled providers, and starts Claude Code
  or pi.
- `corral hook` is the fast policy enforcer invoked for tool calls, prompts, and selected
  results. Policy errors fail closed.

Session hooks under `providers.hooks` are different: they are operator-approved host
programs run around a session. Do not confuse them with `corral hook`.

The filesystem starts from a deny-by-default baseline. Path grants add access; they do
not remove baseline rules. Config lists merge append-unique across layers.

These paths are always masked and cannot be enabled by config:

- `~/.ssh`
- `~/.gnupg`
- `~/.aws`
- `~/.kube`
- `~/.config/gcloud`
- `~/.azure`

`providers.block` can only add paths. A symlink does not bypass these masks. When a user
needs access associated with one of these paths, use the supported alternative: SSH
agent forwarding, a Kubernetes or GitLab provider, environment credentials, or a
credential deliberately placed under a non-blocked read-only path grant. The original
blocked path remains unavailable. Read
[threat-model.md](references/explanation/threat-model.md) before advising on a security
limit.

`CORRAL_DISABLE_HOOKS` is only a deliberate opt-out for a bare, unsandboxed Claude Code
session. It is ignored inside `corral run` and is never a fix for a policy denial.
`CORRAL_PRESENCE_ACK` silences only Claude's bare-session warning. `net: open` is the only
supported network mode; do not invent `net: none`.

## Make config changes safely

The normal file layers are:

1. `~/.config/corral/config.yml` for operator-wide settings;
2. `.corral.yml` for shared project settings;
3. `.corral.local.yml` for a per-user project override.

`.corral.local.yml` is ignored by Git only by convention, so ensure the repository's
`.gitignore` covers it. Profiles are overlays selected at launch. Read
[config.md](references/reference/config.md) for exact fields, defaults, constraints, and
merge behavior.

Before editing:

- run `corral validate` on the host to list the contributing sources and selected effective
  settings;
- inspect those source files when you need to identify which layer supplied a value;
- verify the requested field and its effective default;
- ask which layer to use if team policy versus personal preference is ambiguous;
- choose the narrowest path and permission that satisfy the task.

After editing, run host-side `corral validate` again. Repository config requires interactive
content approval on the next real `run` or `sync`; `--yes` does not grant that approval.
Any config change takes effect in a new session.

Inside an active corral sandbox, policy blocks writes to corral's config files. Do not
retry or attempt a bypass. Write the complete proposed content to an ordinary file in the
working directory, such as `corral-local-new.yml`, and ask the user to review and move it
to the protected destination from the host. Do not use a protected basename even under
`scratchpad/`.

## Use the canonical guides

- **Install, first launch, aliases, and live verification:**
  [agent.md](references/agent.md), then [install.md](references/how-to/install.md).
- **Upgrade or uninstall:** [upgrade.md](references/how-to/upgrade.md) and
  [uninstall.md](references/how-to/uninstall.md).
- **Commands and flags:** [commands.md](references/reference/commands.md).
- **Config keys and defaults:** [config.md](references/reference/config.md).
- **Claude Code versus pi:** [agents.md](references/reference/agents.md).
- **SSH, Docker, or private home:** [providers.md](references/how-to/providers.md).
- **Kubernetes:** [kubernetes.md](references/how-to/kubernetes.md). Do not recommend
  `preProvisioned` mode without explaining that users with `edit` in its dedicated
  namespace share all access assigned to the ServiceAccount group.
- **GitLab:** [gitlab.md](references/how-to/gitlab.md). Confirm whether the user needs a
  personal or project token before writing config.
- **Session hooks:** [session-hooks.md](references/how-to/session-hooks.md) for setup and
  recovery; [hooks-contract.md](references/reference/hooks-contract.md) for execution and
  contribution details.
- **Blocks, provider failures, and a launch warning that `$HOME/<path>` is a real entry in
  the private home:** [troubleshooting.md](references/how-to/troubleshooting.md).
- **Repository approval:** [trust-gate.md](references/explanation/trust-gate.md).
- **Guarantees and limits:** [threat-model.md](references/explanation/threat-model.md).
- **Architecture:** [design.md](references/explanation/design.md).

For session hooks, remember only the behavior that changes advice: they execute host code,
readable enabled executables require content approval before `run`, required `preStart`
failures abort launch, `postEnd` failures warn, and stdout from `preStart` is a strict
machine-readable contribution channel. Read the setup and contract pages for everything
else.

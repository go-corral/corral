---
name: corral
description: >-
  Help install, configure, run, update, uninstall, and troubleshoot corral, the coding-agent
  sandbox for Claude Code and pi. Trigger when the user mentions corral, an agent sandbox,
  doctor/sync/validate/run, .corral.yml, provider setup, filesystem or environment grants,
  session hooks, blocked tool calls, the audit log, always-blocked paths, masked credential
  directories, or a vague report that the sandbox will not allow something.
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

| Interface                              | Use it for                                                                                                                                                                                                                             |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `corral doctor`                        | Host readiness per area: backend, config and approval, agent integration, enabled providers, `CORRAL_DISABLE_HOOKS`, and update state. Lists each failed or warning check with its fix command.                                        |
| `corral validate`                      | Sectioned config report: sources and approval notices, sandbox settings including the private home, agent settings, path grants, environment names, and enabled providers. It does not show per-field provenance or host availability. |
| `corral run --dry-run -- <agent args>` | The sandbox command that would launch, without running session hooks or creating temporary credentials.                                                                                                                                |
| The audit record's `rule` and `reason` | The policy decision behind a blocked tool call.                                                                                                                                                                                        |

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
`policy.audit.path` overrides it. Inside an active session, `echo "$CORRAL_AUDIT_PATH"`
prints the file this session logs to. Before sharing a record, inspect the Bash
`command`, WebSearch `query`, and WebFetch `url`: those values are recorded verbatim
and can contain an inline credential. Content bodies and most free-text values are
byte-counted. See [audit-log.md](references/reference/audit-log.md).

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

Besides the built-in defaults, config lives in three files. Choose one by who the
setting is for:

| File                               | Who it is for                     | Git                                            |
| ---------------------------------- | --------------------------------- | ---------------------------------------------- |
| `~/.config/corral/config.yml`      | The user, in every project.       | Outside any repo.                              |
| `.corral.yml` in the project       | All users working in the project. | Commit it with the project.                    |
| `.corral.local.yml` in the project | The user, in this one project.    | Not ignored by itself; add it to `.gitignore`. |

The global config is the user's own file, so corral never asks for approval. The first real `run` or `corral sync` in a repo asks the user to approve the project config files before it uses them and again when they change.
When you recommend a layer, say in one short sentence what the file is for. Profiles are extra layers selected at launch with `--profile`. Read [config.md](references/reference/config.md) for exact fields, defaults, constraints, and merge behavior.

Before editing:

- run `corral validate` list the contributing sources and selected effective settings
- inspect those source files when you need to identify which layer supplied a value
- verify the requested field and its effective default
- ask which layer to use if team policy versus personal preference is ambiguous
- choose the narrowest path and permission that satisfy the task

After editing, run `corral validate` again. Any config change takes effect in a new session.

Inside an active corral sandbox, policy blocks writes to corral's config files. Write the complete proposed content to a file in the working directory, such as `corral-local-new.yml`, and ask the user to review and move it to the protected destination from the host.

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

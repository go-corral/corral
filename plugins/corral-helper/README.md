# corral-helper

A Claude Code plugin that helps users install, configure, run, and troubleshoot
[corral](../../README.md), including corral sessions that run Claude Code or pi.

The plugin provides one skill, `corral`. It triggers for setup, config edits, provider
access, blocked operations, audit logs, always-blocked paths, and related sandbox
questions.

## Install

This repository is a Claude Code plugin marketplace. From Claude Code:

```text
/plugin marketplace add https://github.com/go-corral/corral.git
/plugin install corral-helper@corral
```

For a local checkout:

```text
/plugin marketplace add /path/to/corral
/plugin install corral-helper@corral
```

The skill triggers automatically or can be invoked as `/corral-helper:corral`.

## Content ownership

The plugin separates behavioral instructions from product facts:

- `skills/corral/SKILL.md` owns trigger scope, required safety behavior, the diagnosis
  flow, config-edit rules, and selection of references.
- `skills/corral/references/agent.md` is the hand-maintained operational playbook for
  install-to-first-session work, aliases, live verification, and running commands for the
  user.
- The `how-to/`, `reference/`, and `explanation/` subdirectories under
  `skills/corral/references/` contain symlinks to the matching canonical user
  documentation under `docs/`. Those files own command, config, provider,
  troubleshooting, and security details.

The reference tree preserves the canonical docs hierarchy so relative links keep working
when Claude Code dereferences the symlinks during marketplace installation. The installed
skill is therefore self-contained.

## Maintenance rules

- Edit factual product documentation under `docs/`, not through a reference symlink.
- Keep `SKILL.md` concise and behavioral. Keep detailed facts in canonical references
  rather than copying tables, flags, schemas, or provider procedures into the skill.
- Keep `agent.md` operational. It should describe how to drive a task, not become a second
  command or configuration reference.
- Verify claims against source, `corral validate`, command help, and tests. Generated
  config snippets should omit built-in defaults unless the user asks to pin them.
- When behavior changes, review the canonical doc, `SKILL.md`, and `agent.md` for drift.
  When adding a user-facing doc, add an explicit reference symlink if the skill needs it
  and link it from `SKILL.md`.
- Run `make vale`. Vale checks the canonical docs and the three hand-maintained plugin
  files while skipping symlink duplicates.
- Verify reference links with `find plugins/corral-helper/skills/corral/references -type l`
  and inspect each target. Preserve the `how-to/`, `reference/`, and `explanation/`
  hierarchy when adding one so links remain valid after installation. The repository
  currently has no automated skill-behavior eval. After behavioral changes, manually
  exercise an install request, a blocked-path diagnosis, a minimal config edit with
  multiple source layers, and the audit-sharing warning. Confirm the helper inspects the
  listed source files instead of claiming `corral validate` reports per-field provenance.
  Include nested path grants in the config-edit check: the helper must use `[grant]` rather
  than grouping branches and keep validity separate from host readiness. From an active
  sandbox, confirm it asks for host-side `validate` output before using paths to guide a change.
  For audit questions, confirm the helper uses `echo "$CORRAL_AUDIT_PATH"` to name the file
  the current session logs to.
- Keep Linux/bwrap and macOS/Seatbelt guidance balanced. Source and CI do not replace
  manual macOS verification for platform-specific behavior.

## Layout

```text
plugins/corral-helper/
├── .claude-plugin/plugin.json
├── README.md
└── skills/corral/
    ├── SKILL.md                   # behavior, diagnosis, config rules, reference links
    └── references/
        ├── agent.md               # hand-maintained operational playbook
        ├── how-to/
        │   ├── install.md         → docs/how-to/install.md
        │   ├── upgrade.md         → docs/how-to/upgrade.md
        │   ├── uninstall.md       → docs/how-to/uninstall.md
        │   ├── providers.md       → docs/how-to/providers.md
        │   ├── kubernetes.md      → docs/how-to/kubernetes.md
        │   ├── gitlab.md          → docs/how-to/gitlab.md
        │   ├── session-hooks.md   → docs/how-to/session-hooks.md
        │   └── troubleshooting.md → docs/how-to/troubleshooting.md
        ├── reference/
        │   ├── config.md          → docs/reference/config.md
        │   ├── commands.md        → docs/reference/commands.md
        │   ├── agents.md          → docs/reference/agents.md
        │   ├── hooks-contract.md  → docs/reference/hooks-contract.md
        │   ├── audit-log.md       → docs/reference/audit-log.md
        │   └── sandbox-permissions.md → docs/reference/sandbox-permissions.md
        └── explanation/
            ├── threat-model.md    → docs/explanation/threat-model.md
            ├── trust-gate.md      → docs/explanation/trust-gate.md
            └── design.md          → docs/explanation/design.md
```

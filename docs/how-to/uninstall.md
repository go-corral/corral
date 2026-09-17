# Uninstall corral

Run `corral uninstall` before deleting the binary or config. Without `--apply`, the
command only lists the state and agent integrations it would remove.

1. Review what corral manages:

   ```sh
   corral uninstall
   ```

   This preview lists the agent registrations, cache, state, and audit logs that
   `--apply` would remove. It also lists the binary, config, and plugin that you must
   remove yourself.

2. Remove the managed state:

   ```sh
   corral uninstall --apply
   ```

   For each step you confirm, the command:

   - removes provider resources left by crashed sessions through `corral gc`;
   - removes corral's Claude Code hook registrations and pi presence-warning
     extension;
   - deletes the cache, including private homes and scratch space used for
     agent-installed dependencies;
   - deletes repository approval records;
   - deletes the audit log and its rotated backups.

   `--yes` skips these prompts. Declining a prompt skips only that step. If a
   repository enables a provider in its own `.corral.yml`, run `corral gc` from that
   repository first.

3. Delete the items corral does not manage:

   - the binary and the shell alias: `rm ~/.local/bin/corral` (or wherever the
     [install steps](install.md#install) put it), and drop any
     `alias claude='corral run --'` from your shell rc;
   - your configs: `~/.config/corral/`, plus any per-repo `.corral.yml` /
     `.corral.local.yml`;
   - the helper plugin, if you installed it:

     ```sh
     claude plugin uninstall corral-helper@corral
     claude plugin marketplace remove corral
     ```

## If the binary is already gone

A registered Claude Code hook checks for the corral binary before running it. When the
binary is missing outside the sandbox, the hook exits silently and does not enforce
policy. Remove the stale registrations rather than leaving them in place.

Delete the four `hooks` entries in
`~/.claude/settings.json` (or `$CLAUDE_CONFIG_DIR/settings.json`) whose command
mentions `hook pre-tool-use`, `hook post-tool-use`, `hook session-start`, or
`hook user-prompt-submit`, and delete
`~/.pi/agent/extensions/corral-presence.ts`. Then delete the remaining state:
`~/.cache/corral`, `~/.local/state/corral`, and `~/.claude/corral-audit.jsonl*`.

Paths assume the defaults: adjust for `$XDG_STATE_HOME`, `$XDG_CONFIG_HOME`,
or `$CLAUDE_CONFIG_DIR` if you've overridden them, and if you set
[`policy.audit.path`](../reference/config.md#policyaudit), remove that file
instead.

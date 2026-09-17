# Audit-log format

Every policy decision is appended as one JSON line to the audit log. The default
is `corral-audit.jsonl` under the selected agent's config directory:
`$CLAUDE_CONFIG_DIR` or `~/.claude` for Claude Code, and
`$PI_CODING_AGENT_DIR` or `~/.pi` for pi. Location, rotation, and retention are
configured by [`policy.audit`](config.md#policyaudit); recipes for reading it are in
[troubleshooting](../how-to/troubleshooting.md#reading-the-audit-log).

Each record:

| Field        | Meaning                                            |
| ------------ | -------------------------------------------------- |
| `time`       | timestamp of the decision                          |
| `session_id` | the agent session                                  |
| `tool`       | the tool call (for example `Bash`, `Read`, `Edit`) |
| `action`     | `allow` or `deny`                                  |
| `rule`       | policy rule that made the decision                 |
| `reason`     | human-readable explanation                         |
| `cwd`        | working directory at decision time                 |
| `input`      | a structural summary of the tool parameters        |

The `input` field keeps an allowlist of useful identifiers verbatim, subject to size
limits. Other values are replaced with their byte count.

- **Kept for every tool:** paths, glob and regular-expression patterns, and any argument
  whose key is `command`. This includes MCP tools. A command longer than 8 KiB is
  byte-counted instead.
- **Also kept for built-in tools:** WebSearch `query`, WebFetch `url`, Task `description`
  and `subagent_type`, Grep and NotebookEdit modes, and shell and cell ids.
- **Byte-counted:** content bodies from `Write`, `Edit`, and `MultiEdit`; the `prompt`,
  `plan`, and `message` instruction fields; and other free-text MCP arguments. A counted
  value appears as `"content_bytes": 2148`.

The default log is inside the agent config directory, which is writable in the sandbox
so corral can append decisions. Policy blocks agent tool calls that try to write,
truncate, or delete the live log and its backups.

Before sharing an audit record, inspect every retained `command`, WebSearch `query`, and
WebFetch `url`. These fields may contain an inline token.

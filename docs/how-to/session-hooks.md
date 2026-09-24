# Set up session hooks

Session hooks run host executables around an agent session:

- `preStart` runs before the agent starts and can prepare dependencies or check a
  prerequisite.
- `postEnd` runs after the session and can publish a report or undo setup.

These scripts run on the host. They are unrelated to the `corral hook` policy
enforcer inside the agent integration.

## Add a hook

1. Create an executable script with a shebang. A hook is executed directly, without
   a shell or `$PATH` lookup:

   ```sh
   chmod +x scripts/update-datasources.sh
   ```

2. Add the executable under `providers.hooks`:

   ```yaml
   providers:
     hooks:
       preStart:
         10-update-datasources:
           exec: ./scripts/update-datasources.sh
           args: [--fast]
         20-check-vpn:
           exec: ./scripts/check-vpn.sh
           optional: true
       postEnd:
         session-report:
           exec: ./scripts/session-report.sh
   ```

   Relative paths resolve from the session workdir. Entries run in lexical key
   order, so use prefixes such as `10-` and `20-` when order matters.

3. Run `corral run`. When corral asks for content approval, review each hook
   executable before accepting it. Adding or changing an executable requires new
   approval. `--yes` does not bypass this review.

A non-optional `preStart` failure stops the launch before corral creates temporary
credentials. Use `optional: true` only when the session can safely continue without
that hook. A `postEnd` failure prints a warning and does not replace the agent's exit
status.

### Contribute values to the session

A `preStart` script may print one versioned JSON object to stdout. The object can set
environment variables, add banner status, or add notes shown to the agent:

```json
{
  "corralContributionVersion": 1,
  "env": { "DATASET_REV": "2026-07-24" },
  "status": ["refreshed 3 datasources"]
}
```

Write normal output and diagnostics to stderr. stdout is reserved for this object, so
a stray `echo` makes the hook fail. For the schema, validation, size limits, and
reserved variables, see the
[contribution contract](../reference/hooks-contract.md#the-contribution-prestart-stdout).

## Disable or override a repo hook

Hook entries merge by name across config layers. In `.corral.local.yml`, disable a
repo hook without copying its other fields:

```yaml
providers:
  hooks:
    preStart:
      10-update-datasources:
        enabled: false
```

You can override one scalar field, such as `optional`. `args` merge append-unique,
so a higher layer can add arguments but cannot remove existing ones. To replace an
argument list, disable the original entry and define another key.

## Verify the hooks

Run a new session and check the startup banner. It names each `preStart` entry that
ran or was skipped. A `preStart` script's stderr appears there under the entry name.

When the session ends, corral announces each `postEnd` entry on stderr:

```text
    running post-end session hook providers.hooks.postEnd.session-report
```

`corral run --dry-run` never executes session hooks. Its banner reports that hooks
run only during a real launch.

## Failures

- **`permission denied — is the script executable? (chmod +x)`:** Set the executable
  bit and ensure a script has a valid shebang. For `No such file or directory`,
  check the path relative to the session workdir; bare names do not use `$PATH`.
- **A `preStart` hook aborts the launch:** Read the attributed hook error and fix the
  script. Mark it optional only when its result is not required for a safe session.
- **`stdout is reserved for the contribution interface`:** Move logs to stderr and
  leave stdout empty or print exactly one valid contribution object.
- **The launch waits after a hook finishes:** A background process inherited stdout
  or stderr and kept corral's capture pipe open. Redirect both streams:
  `mydaemon >/dev/null 2>&1 &`.
- **`postEnd` was skipped because it changed:** corral re-hashes the executable before
  running it. If you edited it during the session, start a new session and approve
  the new content.
- **The launch stops at `unapproved session-hook executables`:** Review the named
  files and approve them interactively. The hook has not run yet.

For execution order, environment variables, stream handling, and the contribution
object, see the [session-hooks contract](../reference/hooks-contract.md). For config
fields and merge rules, see
[`providers.hooks`](../reference/config.md#providershooks).

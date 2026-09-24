# Session-hooks contract

This page defines how corral runs the host executables configured under
`providers.hooks`. A `preStart` hook runs before the agent starts; a `postEnd` hook runs
after it exits. For setup, see [Set up session hooks](../how-to/session-hooks.md). For
config fields and merge behavior, see [`providers.hooks`](config.md#providershooks).

Session hooks are unrelated to the `corral hook` process that checks in-sandbox tool
calls.

## Execution

- corral runs `exec` directly without a shell. The file needs its executable bit
  (`chmod +x`). A script's shebang selects the interpreter.
- A relative path, including a bare name, resolves against the session workdir. The
  hook also runs in that directory. corral expands `~` but does not search `$PATH`.
- corral passes `args` as the argv tail. Put pipes, `&&`, redirects, and other shell
  syntax inside the executable.
- Hooks have no timeout. An interrupt (Ctrl-C) stops a running hook.

## When hooks run

- Entries for one event run in lexical key order. Prefix keys with `10-`, `20-`, and
  similar numbers when order matters.
- `preStart` runs after [config and executable approval](../explanation/trust-gate.md)
  and after you accept any launch warnings. It runs before corral creates a temporary
  credential. A non-optional failure or an interrupt stops the launch. Configured
  `postEnd` entries still run.
- `postEnd` runs after a clean exit, nonzero exit, or signal. It also runs when a launch
  aborts after provider setup begins, including a `preStart` failure or a later provider
  failure. corral runs `postEnd` before removing temporary provider resources. Those
  resources are still live, but their contributed environment variables are not passed
  to the hook. A failure only prints a warning; the agent's exit code wins. Ctrl-C
  interrupts the hook, not corral.
- corral checks each `postEnd` executable when the session starts and again before
  running it. If the file changed, disappeared, or did not exist at launch, corral
  skips that entry and names it in a warning. Other entries still run. The next launch
  asks for approval if changed content is readable.
- `corral run --dry-run` never runs a session hook. Its banner says that hooks run only
  during a real launch.

## Environment

Each hook gets the host environment plus:

| Variable            | Value                   |
| ------------------- | ----------------------- |
| `CORRAL_EVENT`      | `preStart` or `postEnd` |
| `CORRAL_AGENT`      | the launched agent      |
| `CORRAL_SESSION_ID` | the session id          |
| `CORRAL_WORKDIR`    | the session workdir     |

`postEnd` also gets `CORRAL_AGENT_EXIT`. Its value is the agent's decimal exit code,
`128+signal` when a signal killed the agent, or the literal `aborted` when the launch
failed before the agent ran.

Hooks inherit the original host environment, not the filtered sandbox environment.
Provider-contributed variables such as the session `GITLAB_TOKEN` and `KUBECONFIG` are
not added. If the host environment already contains either name, the hook receives that
host value instead. Do not assume a `postEnd` command uses the scoped session credential.

## Standard input and output

stdin is `/dev/null` for every event. A hook that reads it, such as `read` or an
unguarded `ssh` passphrase prompt, receives immediate EOF instead of hanging the
launch. Output handling differs by event:

- corral captures `preStart` stdout but never prints it. stdout is limited to 1 MiB
  and reserved for [the contribution object](#the-contribution-prestart-stdout).
- Write `preStart` logs, progress, and errors to stderr. corral captures up to 64 KiB
  and shows it under the config entry in the startup banner after the hook exits.
  Longer output is cut and marked `… output truncated`. When a progress line redraws
  itself with `\r`, the banner shows its final frame. stderr is a pipe rather than a
  TTY, so `isatty(stderr)` is false and well-behaved tools disable color and progress
  bars.
- `postEnd` stdout and stderr go directly to the terminal and are not parsed. Each
  `postEnd` hook is announced on stderr:

  ```
      running post-end session hook providers.hooks.postEnd.<key>
  ```

`CORRAL_EVENT` tells a script shared between the two events which contract it is
running under.

## The contribution (`preStart` stdout)

Empty or whitespace-only stdout means that the hook contributes nothing. Non-empty
stdout must contain exactly one JSON object:

```json
{
  "corralContributionVersion": 1,
  "env": { "DATASET_REV": "2026-07-24" },
  "agentNotes": ["dataset pinned to revision 2026-07-24"],
  "status": ["refreshed 3 datasources"]
}
```

- `corralContributionVersion` is **required** and must be `1` (the schema version).
- `env` (map of string→string), `agentNotes` (list of strings), and `status` (list of
  strings) are optional. Unknown fields and any trailing content after the object are
  **rejected**.
- `env` enters the sandbox environment under the same collision rules as provider
  variables. If an earlier session hook already set a name, the later hook fails. A
  collision with the sandbox environment or another provider fails the launch when
  corral applies all provider results.
- `status` lines appear in the banner under the hook entry. `agentNotes` appear in the
  agent's session-start note; keep them short and free of credentials.
- Each contributed environment name must match
  `^[A-Za-z_][A-Za-z0-9_]*$`. No value or note may contain a NUL byte, and the whole
  contribution's values and notes are capped at 64 KiB.
- `CORRAL_SANDBOX`, `CORRAL_GLOBAL_CONFIG`, `CORRAL_AUDIT_PATH`, `CORRAL_AGENT`,
  `CORRAL_BIN`, `CORRAL_PROVIDER_NOTES`, and `CORRAL_BACKEND_NOTES` are reserved. A
  hook that names one fails because these variables control the in-sandbox policy
  process. The wider reserved list for
  [`providers.env.set`](config.md#providersenv) is a separate config rule.
- A contribution cannot add mounts or path grants. It can contain only `env`,
  `agentNotes`, and `status`.

Any violation (non-JSON output, a missing or wrong `corralContributionVersion`
marker, an unknown field, trailing data, or exceeding the 1 MiB cap) fails the hook
with:

```
providers.hooks.preStart.<key>: stdout is reserved for the contribution interface — <detail> (prints and logs belong on stderr)
```

A non-optional hook then stops the launch. For an `optional: true` hook, corral drops
the contribution, prints a warning row, and continues. `postEnd` output is never
parsed.

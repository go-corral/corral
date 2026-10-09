# Troubleshoot corral

Start most diagnoses with:

```sh
corral doctor      # host and integration readiness
corral validate    # config sources and selected effective policy
```

For config keys, see the [configuration reference](../reference/config.md). For
security boundaries, see the [threat model](../explanation/threat-model.md).

## The hook blocked my command

A hook deny starts with `blocked by corral policy [hook:<rule>]`. It has a reason and a `Fix:` part. The entries below say what each rule matches and give its fix.

```text
blocked by corral policy [hook:blocked-path]: access to /srv/keys (resolved "/srv/keys/a.txt" -> "/srv/keys/a.txt"). Fix: Ask the user to remove the entry from `providers.block.directories` or `providers.block.files` in the config that adds it.
```

The audit log records the same rule name. Find the latest denied event:

```sh
for log in ~/.local/state/corral/audit/*/corral-audit.jsonl; do jq -c 'select(.action == "deny")' "$log" | tail -n 1; done
```

The command prints the latest denied event of each log. Each agent config directory has its own log, the startup banner contains the path. Use the correct [audit-log path](#reading-the-audit-log) if you configured a custom path.

- **`always-blocked`:** The call reaches an [always-blocked path](../explanation/threat-model.md#1-always-blocked-paths) or a path under one. No setting opens it. Supported access goes through a provider, such as the SSH or Kubernetes provider. For a cloud credential in an environment variable, add the variable to [`providers.env.passthrough`](../reference/config.md#providersenv).
- **`blocked-path`:** The call reaches a path that `providers.block` adds. Remove the entry from `providers.block.directories` or `providers.block.files` in the config that adds it.
- **`ai-ignore`:** The path matches `.aiignore`, `.aiexclude`, or another configured exclusion source. If the agent needs the path, change the AI ignore file or `providers.aiignore.sources`.
- **`bash`:** The command contains a blocked operation such as pipe-to-shell, a destructive delete, world-writable `chmod`, or a redirect involving a sensitive path. No setting allows the command. Do the task without the blocked operation, or run the command yourself outside the session.
- **`path-pattern`:** The path looks sensitive or is protected against agent edits, such as corral's config, audit log, or an agent hook registration. No setting exempts the path. Do this step yourself outside the session.
- **`secret-scan`:** File content matches a known credential format or the configured entropy threshold. When a Read matches a file that holds no real credential, add the directory to [`policy.secretScan.skipPaths`](../reference/config.md#policysecretscan). For a Write or an MCP call, the agent uses a placeholder or an environment variable reference instead of the value. For a high-entropy false positive, raise `entropyThreshold`, or set it to `0` to turn off the entropy heuristic. No setting exempts a known format in written content or MCP arguments.

The [threat model](../explanation/threat-model.md) describes rules that cannot be relaxed by configuration.

## The sandbox blocks silently

The sandbox (`os` layer) gives no policy message. On Linux, a masked directory is empty, a masked file reads as `File content masked by corral`, a file under a masked directory or an unmounted path reads as `No such file or directory`, and a write to a read-only path fails with `Read-only file system`. A write outside the working directory and the granted paths can also work on Linux, but it goes to sandbox-private storage that the host does not see. On macOS, a masked path or a path without a grant fails with `Operation not permitted`. A path that is missing in the sandbox can exist on the host. The hook reads the text of a Bash command, but not what the started processes do. So a shell probe that works does not show that a tool call is allowed.

A path grant cannot open an always-blocked path, a `providers.block` entry, or a path that an AI ignore source matches. For a `providers.block` entry, remove the entry. For an AI ignore match, change the AI ignore file. For any other path, add a `providers.paths.ro` grant to read or a `providers.paths.rw` grant to write, as in [A tool cannot use a file under `$HOME`](#a-tool-cannot-use-a-file-under-home).

## Every tool call is blocked with `cannot evaluate policy`

The hook in the session cannot reach the sidecar of `corral run`, so it blocks each call. The message starts with `blocked by corral policy [hook:fail-closed]: cannot evaluate policy:` and names the cause. Exit the agent and start a new session with `corral run`.

After a corral upgrade the hook could become incompatible, restarting the session will help then.

## A tool output is withheld

The tool call ran, but corral replaced its output before the agent saw it. The replacement starts with `output withheld by corral policy [hook:<rule>]`.

- **`response-secret`:** The output contains a known credential format or a value above the entropy threshold. The agent passes the credential through an environment variable or a file path instead of printing it. For a high-entropy false positive, raise [`policy.secretScan.entropyThreshold`](../reference/config.md#policysecretscan).
- **`fail-closed`:** corral could not scan the output, for example because it is larger than the scan limit or the sidecar does not answer. The message names the cause.

## The kubeconfig `Read` block

**Symptom:** the agent's `Read` of the temporary kubeconfig is refused while
`kubectl` works.

The kubeconfig contains a bearer token, so a literal `Read` triggers the secret
scanner. `kubectl`, `helm`, and similar clients can use `$KUBECONFIG` without
putting the token in model context. Do not add the temporary kubeconfig directory to
`skipPaths`.

## `Your prompt appears to contain …`

corral found a known credential format or high-entropy value in the submitted
prompt. The prompt was not sent. Remove or replace the value and submit it again.

Resubmitting the same prompt sends it without another warning. This is an explicit
override for false positives, not confirmation that the value is safe.

## `This Claude session is NOT sandboxed`

A plain `claude` launch triggers the presence warning once per session because it
did not start through `corral run`. Resubmit the prompt to continue unsandboxed,
or exit and run:

```sh
corral run
```

If another sandbox provides the isolation intentionally, set
`CORRAL_PRESENCE_ACK=1` in the environment that launches Claude. This silences
only the presence warning; prompt scanning and tool-call policy remain active.
See [the presence warning](../explanation/threat-model.md#the-presence-warning).

## Hooks do not seem to run

If calls that should be denied all proceed, check these causes in order:

1. Run `corral doctor`. If `CORRAL_DISABLE_HOOKS` is `1` or `true`, corral is
   disabled for agents launched outside its sandbox. Run
   `unset CORRAL_DISABLE_HOOKS` and restart the agent. Other values, including `0`
   and `false`, do not disable hooks; `doctor` reports them as not recognized.
2. Check the `claude` entry under **needs attention** in `corral doctor`. If its
   hooks are **not registered**, **stale**, or **missing**, run `corral sync claude`,
   then run `corral doctor` again.
3. If registrations look present but the registered corral binary was moved or
   deleted, install corral at that path or run `corral sync` from the current
   binary. Outside the sandbox, a missing registered binary is skipped silently.

Inside a session started by `corral run`, `CORRAL_DISABLE_HOOKS` has no effect.

## A configured provider is unavailable

1. Run `corral validate` to confirm that the effective config enables the
   provider.
2. Run `corral doctor` to check its host prerequisite, such as a Docker socket,
   SSH agent, host GitLab token, or kubeconfig.

A required provider that is unavailable stops the launch with:

```text
provider "…" unavailable (required; set optional: true to allow skipping)
```

Fix the missing prerequisite. Set `optional: true` only when the session can safely
continue without the provider's access. The same setting also turns a token creation
or request error into a skip with a warning.

`corral run --dry-run` does not create temporary credentials or run session hooks. It
shows providers that add fixed paths or environment settings and marks the others as
available only during a real launch. A missing required prerequisite still fails the
preview.

See the [provider guide](providers.md) for setup and provider-specific checks.

## My session hook failed or aborted the launch

Session hooks under `providers.hooks` are host programs that run before or after the
session. They are not the `corral hook` policy process. See
[session-hook failures](session-hooks.md#failures)
for exit errors, executable permissions, stdout contribution errors, and hooks
that wait indefinitely for output streams to close.

## A tool cannot use a file under `$HOME`

The `home` provider is enabled by default. It sets `$HOME` to a persistent private
directory, `~/.cache/corral/home-<hash>` by default, and links host paths allowed by the
baseline, the selected agent, or providers. As a result:

- baseline paths such as `~/.gitconfig`, selected-agent state, and explicit
  `providers.paths` grants remain available when they exist on the host;
- host paths outside those allowed sets are absent;
- writes under `$HOME` go to the private home;
- npm, Go, pip, uv, yarn, and pnpm caches persist there between sessions.

Add a `providers.paths.ro` grant when the tool only needs to read a host path. Use
`providers.paths.rw` only when it must change the host path.

If the launch warns that `$HOME/<path>` is a real file or directory in the private home,
the session sees that private copy instead of the host path. Move the entry aside (or
delete it); the next launch restores the link. If the private copy is intended, for
example a tool directory the sandbox populated before the host had one, list it under
[`providers.home.keep`](../reference/config.md#providershome).

If a build downloads dependencies every session, check that the configured private
home is not being deleted between runs. Setting
[`providers.home.enabled: false`](../reference/config.md#providershome) uses the
host home location instead, so writes to granted home paths are no longer isolated.
The always-blocked directories remain masked.

## `providers.paths` resolves through an always-blocked path

corral resolves a symlinked grant before mounting it. It refuses the grant if the
resolved source is an always-blocked directory, lies inside one, or is a symlinked
ancestor that would expose one under another name.

Point the grant at a different path. For SSH access, enable the
[SSH provider](providers.md#ssh) instead; it forwards the agent socket without
exposing private keys.

If the error says the symlink target **contains** an always-blocked path, grant the
resolved target directly as the message suggests. corral can then apply the mask
at the correct location. A normal ancestor grant remains valid: for example,
granting a real dotfiles directory is allowed even when `~/.ssh` points into it,
because the resolved SSH directory is masked inside the grant.

## Config changes seem ignored

- Run `corral validate` to see the built-in, global, `.corral.yml` and `.corral.local.yml` sources ordered by priority.
- Lists merge append-unique, meaning they can only be extended by later config layers.
- A config or profile edit takes effect on the next launch. Exit the agent and run `corral run` again.
- Provider, mount, environment and sandbox changes apply to new sessions.
- Inside a session, `echo "$CORRAL_PROFILES"` shows the profiles that the session applies.
- In a session started without `corral run`, a block with `profile "<name>" not found` means the config no longer defines a selected profile. Restore the profile, or restart the session.

## Reading the audit log

corral logs each policy decision as one JSON line. The default log is in the corral state directory, in a subdirectory for the agent's config directory:

| Agent       | Default audit log                                                                                          |
| ----------- | ---------------------------------------------------------------------------------------------------------- |
| Claude Code | `~/.local/state/corral/audit/<hash>/corral-audit.jsonl`, `<hash>` from `$CLAUDE_CONFIG_DIR` or `~/.claude` |
| pi          | `~/.local/state/corral/audit/<hash>/corral-audit.jsonl`, `<hash>` from `$PI_CODING_AGENT_DIR` or `~/.pi`   |

`XDG_STATE_HOME` replaces `~/.local/state` when it is an absolute path. `<hash>` is the first 4 bytes of the SHA-256 of the config directory, in hex. It matches the private home `~/.cache/corral/home-<hash>`. [`policy.audit.path`](../reference/config.md#policyaudit) overrides these defaults.

The sandbox cannot open the log unless the workdir or a `providers.paths` grant contains it. `CORRAL_AUDIT_PATH` inside a session names the host file. Read the file on the host. The `policy` row of the startup banner prints the exact path: `audit events in <path>`. Replace `<path>` in this example:

```sh
log=<path>
tail -n 20 "$log" | jq .
jq 'select(.action == "deny")' "$log"
```

To read the log inside a session, add the log directory to `providers.paths.ro`.

`corral run` moves a legacy log, `corral-audit.jsonl` in the agent's config directory, and its rotated backups into the default log directory. This happens on every real launch when `policy.audit.path` is unset. If a file cannot be moved, `corral run` prints `legacy audit log not moved: <error>; move the file into <new log directory> or delete it by hand`. Move the file into the named directory, or delete it.

The `rule` and `reason` fields explain the decision. The
[audit-log reference](../reference/audit-log.md) lists the complete record and the
fields stored verbatim.

## Still stuck

Share `corral doctor` output, `corral validate` output, and only the relevant audit
records with the maintainers. Review audit records before sharing them: Bash
`command`, WebSearch `query`, and WebFetch `url` values are stored verbatim and may
contain inline credentials. For development issues, see
[CONTRIBUTING](https://github.com/go-corral/corral/blob/main/CONTRIBUTING.md).

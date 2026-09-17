# Security and threat model

## Scope

corral is a single-user engineering tool. It protects an operator from accidental
destructive commands, unintended credential exposure, and an agent disabling its own
enforcement. It does not try to stop a malicious operator from bypassing a sandbox they
control.

This distinction determines when corral blocks and when it warns. Integrity failures,
such as malformed policy input or access to an always-blocked credential directory,
fail closed. Risks that arise from a deliberate operator choice generally produce a
warning or require an explicit grant.

## Hard guarantees

### 1. Always-blocked paths

These paths are always masked inside the sandbox, regardless of config:

- `~/.ssh`
- `~/.gnupg`
- `~/.aws`
- `~/.kube`
- `~/.config/gcloud`
- `~/.azure`

`providers.block.directories` and `providers.block.files` can add paths but cannot
remove these. The SSH provider exposes only selected read-only configuration such as
`config` and `known_hosts`; it does not expose private keys.

The filesystem baseline already excludes host files by default. The default-on home
provider gives the session a private `$HOME`; disabling that provider uses the host home
location instead. In either case, the fixed list protects these credential stores from
an overly broad explicit grant such as `providers.paths.rw: [~]`.

A path grant cannot use a symlink to reach one of these directories. corral checks the
resolved grant target, and it masks both the configured credential path and its resolved
target when the credential directory itself is a symlink.

The list is intentionally limited to well-known stores of long-lived, host-wide
credentials for which raw in-sandbox access is unnecessary. corral can forward an SSH
agent, create a session Kubernetes credential, or forward an explicitly named cloud
credential through `providers.env.passthrough`. Forge credentials such as
`~/.config/gh` and package credentials such as
`~/.npmrc` are not fixed blocks because builds often read them directly. Use
`providers.block` when an explicit path grant or disabled home isolation would expose
those files.

### 2. The hook fails closed

The `corral hook` policy path returns only allow or block for a tool call. Malformed
input, an unknown event, a rule error, or another evaluation failure blocks rather than
allowing the operation.

A post-tool response requires different mechanics because blocking after execution
cannot remove data already returned by the tool. If response parsing or scanning fails,
corral replaces the response with a withheld marker in the shape the agent expects. It
does not pass the original response through.

The deliberate `CORRAL_DISABLE_HOOKS=1` opt-out applies only outside a corral sandbox.
Inside the sandbox it is ignored, and config cannot set it.

### 3. Filesystem access starts from a deny-by-default baseline

The embedded `sandbox-permissions.json` allowlist compiles to bwrap on Linux and
Seatbelt on macOS. See the
[compiled baseline](../reference/sandbox-permissions.md). Configured
`providers.paths.rw` and `providers.paths.ro` entries add grants; config cannot remove or
loosen baseline rules.

### 4. Temporary credentials are scoped and expire

The Kubernetes and GitLab providers create scoped credentials outside the sandbox,
pass them only into that session, and attempt to revoke them when the session ends. The
credentials also expire independently if cleanup cannot run.

GitLab provides its token through `GITLAB_TOKEN`. Kubernetes writes a mode-0600
kubeconfig under `~/.cache/corral/`, mounts it read-only, and points `KUBECONFIG` at it.
The Kubernetes provider removes the file and cluster objects during normal teardown.
`corral gc` can remove objects and files left by a killed launcher. It cannot remove
GitLab tokens, but they retain their bounded expiry if revocation fails.

Temporary secret values are not written to corral config or the audit log. A hooked
`Read` of the Kubernetes file scans its content and blocks the bearer token. Commands
such as `kubectl` can consume it through `KUBECONFIG` without putting the token in model
context.

### 5. Policy covers commands, files, MCP calls, and tool responses

The Bash rule parses commands and checks destructive deletes, pipe-to-shell patterns,
world-writable `chmod`, sensitive reads and redirects, and writes to protected control
files. File-tool rules check paths, sensitive file names, and written content. Decisions
are appended to the rotated JSON [audit log](../reference/audit-log.md).

MCP tools pass through the same policy path. corral scans their arguments for
credentials and checks recognized path arguments against always-blocked locations. A
credential in an MCP argument or an MCP request for `~/.ssh` is blocked. A remote path
that merely has a sensitive-looking filename is audited rather than blocked because a
configured MCP server may refer to resources outside the local filesystem.

MCP responses and Bash or Grep output are scanned before they enter model context. If a
recognizable secret is found, the entire response is replaced with a marker rather than
partially redacted.

A configured MCP server remains an explicit operator grant. Policy checks its calls as
described above, but does not decide whether the server's normal actions are appropriate.
The agent cannot hand-edit a project `.mcp.json` registry to persist a new server. The
deliberate `claude mcp add` command remains available.

### 6. The agent cannot edit corral's controls

Policy blocks tool calls that write or remove corral config, agent hook registration,
installed hook scripts, protected policy extensions, and other enforcement state. This
prevents the agent from weakening the next policy decision or a later session. It does
not prevent the operator from changing those files outside the sandbox.

### 7. Repository config requires approval

A real `corral run` or `corral sync` cannot proceed with new or changed repository
`.corral.yml` or `.corral.local.yml` content until the operator approves it
interactively. Non-interactive use fails closed. Before `corral run`, readable
session-hook executables also require content approval, including executables named by
global config. See [why repository config requires approval](trust-gate.md) for inspection
commands and coverage limits.

## What corral does not protect against

- **Kernel and sandbox escapes.** corral relies on bwrap user namespaces on Linux and
  Seatbelt on macOS. Vulnerabilities in the kernel or sandbox primitive are outside its
  guarantees.
- **A malicious agent binary or MCP server.** corral assumes it launches the intended
  binary and does not establish the supply-chain integrity of installed MCP servers.
  Claude account connectors are off by default, as are telemetry, error reporting, and
  feedback surveys. See [`agents.claude`](../reference/agents.md#claude-code-settings).
- **Prompt injection and judgments about returned data.** Response scanning recognizes
  credential formats; it does not classify instructions or decide whether content is
  trustworthy. Re-encoded or deeply nested credentials can evade format and entropy
  detectors. A detected response is withheld in full. Claude Code's user-scope
  `~/.claude.json` remains writable because it also stores session state; project
  `.mcp.json` is protected.
- **Claude Code's `!` bash mode.** This mode runs a command client-side and inserts its
  output without a policy hook, so corral cannot scan that output. Filesystem isolation
  still applies, including the always-blocked masks, but any secret deliberately exposed
  inside the sandbox could enter the conversation. Do not use `!` to read credential
  material. `@file` mentions use the hooked `Read` tool and remain covered.
- **Network egress.** The sandbox has normal network access. `net: none` is not
  implemented and is rejected during config loading. Treat every secret explicitly
  passed into the sandbox as reachable over the network.
- **A malicious operator.** An operator who controls the config, environment, and launch
  command can bypass their own sandbox. corral's integrity controls are directed at the
  agent, not its operator.
- **Shared Kubernetes `edit` access in `preProvisioned` mode.** Anyone with `edit` in the
  dedicated corral namespace can create a ServiceAccount and request its token outside
  corral, including a token for another user's live session ServiceAccount. Treat every
  user with that permission as sharing the namespace's access, and keep the namespace
  dedicated to corral. See the
  [`preProvisioned` setup](../how-to/kubernetes.md#preprovisioned-mode).
- **Secrets explicitly granted to the sandbox.** Path grants, environment passthrough,
  and enabled providers make the requested files or credentials available in the
  session. corral cannot infer that a custom path such as `~/work/prod-creds` is
  sensitive. Credential stores relocated with
  `KUBECONFIG`, `CLOUDSDK_CONFIG`, or `AZURE_CONFIG_DIR` also sit outside their fixed
  standard-path masks. Add those paths to `providers.block.directories` or
  `providers.block.files`.

## The presence warning

After `corral sync`, a bare Claude Code session warns once on its first prompt that it is
not sandboxed and asks the user to resubmit. The registered Claude hooks still check tool
calls and scan prompts and selected tool responses, but there is no filesystem sandbox
or credential masking. If the registered corral binary is missing outside the sandbox,
the guarded registration skips it silently, which also means no policy enforcement.

`corral sync pi` installs a similar one-time warning for a bare pi process. That extension
does not enforce policy: pi's policy extension is loaded only by `corral run pi`.
Removing or acknowledging a presence warning therefore does not create sandbox
protection.

These warnings use the launcher's `CORRAL_SANDBOX` marker only to distinguish a
corral-launched session from a bare one. They are intended to catch an accidental bare
launch, not prove that an adversarial process is sandboxed.

## Deliberate opt-outs

These environment variables control Claude Code's registered corral hooks outside the
sandbox:

| Variable | Effect |
| --- | --- |
| `CORRAL_PRESENCE_ACK=1` | Silences the bare-session warning. Prompt scanning and tool policy remain active. |
| `CORRAL_DISABLE_HOOKS=1` | Disables the registered policy hooks and scans for that bare session. |

Only `1` or `true`, case-insensitively, activates either value. The disable variable is
ignored inside `corral run`, cannot be assigned with `providers.env.set`, and is not
forwarded into the sandbox. If it is present in the shell that launches `corral run`, the
startup banner warns that the sandboxed session remains fully enforced. Outside the
sandbox, a process that can alter the operator's environment can set it; this is not
treated as a sandbox escape.

A disabled Claude hook process writes one `hooks-disabled` audit record, and
`corral doctor` reports the variable when it is present in the shell. For pi,
`corral sync pi --remove` removes only the bare-session warning. It does not change the
per-session policy extension activated by `corral run pi`.

## Reporting a security problem

A way for the agent to access an always-blocked path, make a policy error allow a tool
call or expose a response, modify protected enforcement state, or make corral retain a
temporary secret beyond its documented cleanup and expiry violates this threat model and
should be reported to the maintainers.

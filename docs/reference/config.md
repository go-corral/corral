# Configuration reference

## Precedence

| Order | Source                                                                | Use                                                                 |
| ----- | --------------------------------------------------------------------- | ------------------------------------------------------------------- |
| 1     | Built-in defaults                                                     | Defaults                                                            |
| 2     | `~/.config/corral/config.yml` or `$XDG_CONFIG_HOME/corral/config.yml` | Your personal settings                                              |
| 3     | `.corral.yml`                                                         | Intended to be commited with the project as project-scoped defaults |
| 4     | `.corral.local.yml`                                                   | Intended to be gitignored, personal project-scoped settings         |

All settings (profiles too) are merged with lists being appended and uniqued so they can't contain duplicate entries. The config syntax is checked and corral aborts when it's invalid.

Run [`corral validate`](commands.md#corral-validate) to list loaded config files and inspect the effective configuration.

Project config files need your approval before corral uses them to prevent inadvertently running insecure configurations. If the config changes, it needs a new approval.

## The built-in defaults

```yaml
net: open
sandbox:
  seatbelt:
    mach:
      lookup: strict
      allow: []
  bwrap: {}
hostname: corral
agent: claude
agents:
  claude:
    claudeaiConnectors: false
    telemetry: false
    errorReporting: false
    feedbackSurvey: false
    attributionHeader: true
providers:
  block:
    directories: []
    files: []
  aiignore:
    sources: [.aiignore, .aiexclude]
  paths:
    rw: []
    ro: []
  env:
    passthrough:
      - TERM
      - COLORTERM
      - NO_COLOR
      - EDITOR
      - VISUAL
      - PAGER
      - TMPDIR
      - LANG
      - CLAUDE_CONFIG_DIR
      - PI_CODING_AGENT_DIR
      - PI_CODING_AGENT_SESSION_DIR
    set: []
  docker:
    enabled: false
  ssh:
    enabled: false
  home:
    enabled: true
    path: ""
  kubernetes:
    enabled: false
    tokenLifetime: 8h
  gitlab:
    enabled: false
policy:
  secretScan:
    entropyThreshold: 0
    skipPaths: []
  audit:
    path: ""
    rotateInterval: 1w
    retention: 6mo
    gzip: true
  incidentHint: ""
update:
  checkOnStart: true
```

## Top-level keys

### `net`

- **Type:** string enum: `open` or `none`
- **Default:** `open`
- **Behavior:** `open` gives the sandbox normal, unfiltered network access. `none` is
  not implemented and is rejected when config loads. Other values are also rejected.

### `sandbox`

Backend-specific sandbox settings. corral validates both backend sections but applies
only the section for the selected backend.

- **`sandbox.seatbelt.mach.lookup`** (string enum, `strict` | `open`; default
  `strict`) controls which macOS Mach IPC services the sandbox can reach. `strict`
  denies service lookup by default and allows corral's embedded service list plus
  `mach.allow`. `open` permits service lookup except for Seatbelt's explicit
  sandbox-escape blocks.
- **`sandbox.seatbelt.mach.allow`** (list of strings, default `[]`) adds service
  names in `strict` mode. An entry matches one exact service; a trailing `*`
  matches a service-name prefix. Entries must be non-empty and contain no whitespace
  or quotes. A bare `*` is rejected because it would match every service. This list
  has no effect in `open` mode.
- **`sandbox.bwrap`** is an empty map. The Linux backend has no configurable
  backend-specific settings.

> [!warning]
> `sandbox.seatbelt.mach.lookup: open` permits access to services outside corral's
> allowlist. Prefer adding the required service to `mach.allow`.

### `hostname`

- **Type:** string
- **Default:** `corral`
- **Behavior:** sets the hostname presented inside the sandbox.

### `agent`

- **Type:** string
- **Default:** `claude`
- **Valid:** `claude`, `pi`. Other values are rejected when config loads.
- **Behavior:** selects the agent that corral starts. A `corral run <agent>` positional,
  such as `corral run pi`, overrides this setting for one launch. Per-agent settings
  live under [`agents`](#agentsclaudeclaudeaiconnectors).

The [agent reference](agents.md) describes each agent's hooks or extension, config
directory, state, presence warning, and update settings.

### `agents.claude.claudeaiConnectors`

- **Type:** boolean
- **Default:** `false`
- **Behavior:** controls whether sandboxed Claude Code loads the remote MCP servers
  attached to its claude.ai account, including organization-managed connectors. The
  default prevents those connectors from loading; add a required MCP server explicitly
  with `claude mcp add`, or set this field to `true` to use the account's normal connector
  set.

When this field is `false`, corral sets `ENABLE_CLAUDEAI_MCP_SERVERS=false`. Claude Code
checks this variable before loading account or organization connectors.

### `agents.claude.telemetry`

- **Type:** boolean
- **Default:** `false`
- **Behavior:** controls Claude Code's operational telemetry for latency, reliability,
  and usage patterns. The telemetry does not include code or file paths. When this field
  is `false`, corral sets `DISABLE_TELEMETRY=1`; set it to `true` to allow telemetry.

### `agents.claude.errorReporting`

- **Type:** boolean
- **Default:** `false`
- **Behavior:** controls Sentry error reports. When this field is `false`, corral sets
  `DISABLE_ERROR_REPORTING=1`; set it to `true` to allow reports.

### `agents.claude.feedbackSurvey`

- **Type:** boolean
- **Default:** `false`
- **Behavior:** controls the “How is Claude doing?” session survey. When this field is
  `false`, corral sets `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY=1`; set it to `true` to allow
  the survey.

### `agents.claude.attributionHeader`

- **Type:** boolean
- **Default:** `true`
- **Behavior:** controls Claude Code's system-prompt attribution block, which contains
  the client version and prompt fingerprint. The default leaves Claude Code's setting
  unchanged. When this field is `false`, corral sets
  `CLAUDE_CODE_ATTRIBUTION_HEADER=0`. Omitting the block can improve prompt-cache hit rates
  for a local model or LLM gateway.

> All five settings use environment variables corral **reserves** (see
> [`providers.env`](#providersenv)), so an `env.set` entry cannot change them. Use the
> corresponding `agents.claude` setting instead.

### `agents.pi`

- **Type:** empty map
- **Default:** `{}`

pi currently has no agent-specific settings. An explicit `agents.pi: {}` map is accepted
but unnecessary. See [the agents reference](agents.md#pi) for pi's fixed sandbox behavior.

### `providers`

Provider settings control access beyond the filesystem baseline. `block` hides extra
paths, `aiignore` applies repository exclusions, `paths` adds filesystem access, and
`env` controls environment variables. These providers have no `enabled` or `optional`
field; their entries apply whenever present. Blocks and AI-ignore exclusions are
applied before path grants, so a later grant does not expose an excluded path.

`hooks`, `docker`, `ssh`, `home`, `kubernetes`, and `gitlab` are configured separately.
`home` is enabled by default. Hooks have no default entries. Docker, SSH, Kubernetes,
and GitLab start disabled. See the [provider setup guides](../how-to/providers.md) and
[how corral works](../explanation/design.md).

#### `providers.block`

- **Type:** map containing `providers.block.directories` and
  `providers.block.files`. Each is a list of absolute paths or paths beginning with `~`.
- **Default:** `{directories: [], files: []}`
- **Behavior:** adds paths to the always-blocked set.
  - `directories` hides the entire subtree. Linux mounts an empty filesystem over it;
    macOS denies the subtree. The policy hook also rejects matching paths.
  - `files` hides individual files. Linux replaces a file with a read-only
    `File content masked by corral` stub; macOS denies the file. The policy hook also
    rejects matching paths.

> **Always-blocked paths (cannot be disabled).** `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
> `~/.config/gcloud`, and `~/.azure` are
> always blocked. `block` can only add to that set. Listing a file already under one of
> these directories in `providers.block.files` is rejected as redundant. The SSH provider
> adds back only read-only `config`, included files, and `known_hosts`; private keys stay
> masked. See the [provider guide](../how-to/providers.md).

#### `providers.aiignore`

This provider reads repository exclusion files and blocks their matching paths in
addition to the always-blocked paths. corral finds configured source filenames by walking
up from the working directory to the repository root.

- **`providers.aiignore.sources`** is a list of bare filenames. Paths, `.` and `..` are
  rejected. The default is `[.aiignore, .aiexclude]`. List merging lets you add sources
  but not remove either default.
- **Pattern syntax** supports `*` and `?` within one path segment and `**` across
  segments. A leading or embedded `/` anchors the pattern to the repository root. A bare
  name matches at any depth and blocks its subtree. A trailing `/` is accepted. `!`
  negation is not supported.
- **Paths in an exclusion file** are relative to the repository root. By contrast,
  `providers.block` requires absolute paths or paths beginning with `~`.
- **Matching paths** are rejected by the policy hook. At launch, corral also hides
  concrete matching files and directories from the sandbox filesystem.
- **Other source files** such as `.gitignore` can be added with
  `sources: [.gitignore]`. corral ignores `!` re-inclusions and may therefore hide more
  than Git does. `corral run` warns when a source contains negations. Treat a borrowed
  source as a convenience; the always-blocked paths and secret scanner remain the
  credential protections.
- **The default sources** `.aiignore` and `.aiexclude` are protected against agent edits.
  A borrowed source such as `.gitignore` remains writable because agents commonly edit it.
  Its exclusions can therefore change during a session.

#### `providers.paths`

These fields add filesystem access beyond the built-in baseline. Linux uses bind
mounts; macOS adds Seatbelt allow rules.

- **`providers.paths.rw`:** host paths granted read-write access. Default: `[]`.
- **`providers.paths.ro`:** host paths granted read-only access. Default: `[]`.

Paths may use `~` for the home directory. Each entry adds access; it does not change a
baseline rule.

A grant may not re-expose an [always-blocked path](../explanation/threat-model.md#1-always-blocked-paths)
(`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.config/gcloud`, `~/.azure`), and
**symlinks are followed** when that is checked:

- An always-blocked directory, anything under it, or a symlink resolving into it is
  rejected. For example: `providers.paths: "~/sshlink" resolves to "~/.ssh", which is
inside the always-blocked path`. corral checks the resolved directory because that is
  what the sandbox mounts under the symlink's name.
- An ancestor, including `~`, remains valid because corral masks the always-blocked path
  again inside the mount. This also covers an always-blocked directory that is itself a
  symlink. If `~/.ssh` points to `~/dotfiles/ssh`, granting `~/dotfiles` is valid and
  `~/dotfiles/ssh` remains masked.
- A symlink to an ancestor of an always-blocked path, such as `~/link -> ~`, is rejected.
  Grant the resolved path instead so corral can place the mask at the path the sandbox
  uses.

An ordinary symlinked grant that has nothing to do with an always-blocked path
(`~/work -> /mnt/data/work`) is unaffected.

Where grants overlap, **read-write wins over read-only** on both platforms, whichever of
the two is broader. A read-only grant that is an ancestor of the working directory or of a
`providers.paths.rw` entry leaves that directory writable: starting a session in
`~/.agents/skills` with `providers.paths.ro: [~/.agents]` keeps `~/.agents/skills`
writable. A read-only entry inside a read-write grant has no effect. `corral validate` and
`corral run` warn about such an entry.

#### `providers.env`

- **`providers.env.passthrough`:** environment variable names to copy from the host
  when they are set. Default:
  `[TERM, COLORTERM, NO_COLOR, EDITOR, VISUAL, PAGER, TMPDIR, LANG, CLAUDE_CONFIG_DIR, PI_CODING_AGENT_DIR, PI_CODING_AGENT_SESSION_DIR]`.

The sandbox clears the environment and copies only listed variables. Each entry must be
a valid variable name and must not name one of corral's own `CORRAL_*` control markers.
Agent-reserved names such as the config-directory variables in the default list are
allowed here; the wider reserved list applies only to `set`. To keep a host secret out of
the sandbox, do not list its variable. `SSH_AUTH_SOCK` and `GPG_TTY` are not defaults. The
SSH provider sets `SSH_AUTH_SOCK` and forwards its socket when enabled. Add `GPG_TTY` to
`passthrough` only when the session needs the host value. A [profile](#profiles) can add
names to this list.

- **`providers.env.set`:** literal `{name, value}` entries to set inside the sandbox.
  Use this for a fixed value rather than a value copied from the host. Default: `[]`.

  ```yaml
  providers:
    env:
      set:
        - name: NODE_ENV
          value: sandboxed
  ```

  Config loading enforces these rules:

  - Each `name` must be a valid environment variable name.
  - A name can appear in `passthrough` or `set`, but not both. The default passthrough
    list already claims its names.
  - corral reserves `CORRAL_SANDBOX`, `CORRAL_GLOBAL_CONFIG`, `CORRAL_AUDIT_PATH`,
    `CORRAL_AGENT`, `CORRAL_BIN`, `CORRAL_PROVIDER_NOTES`, `CORRAL_BACKEND_NOTES`,
    and `CORRAL_DISABLE_HOOKS`. It also reserves Claude Code's
    `ENABLE_CLAUDEAI_MCP_SERVERS`, `DISABLE_TELEMETRY`, `DISABLE_ERROR_REPORTING`,
    `CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY`, and `CLAUDE_CODE_ATTRIBUTION_HEADER`, plus
    pi's `PI_CODING_AGENT_DIR` and `PI_CODING_AGENT_SESSION_DIR`. Use the
    `agents.claude` fields for Claude Code settings and set pi's directory variables in
    the host environment. Config cannot replace variables that control corral's policy,
    audit log, selected binary, or session notes.
  - A name cannot be set to two different values. Repeating the same `{name, value}` in
    two layers collapses to one entry; a different value is a config error because lists
    merge rather than replace.
  - If `set` replaces a base value supplied by corral, such as `HOME` or `PATH`, corral
    warns and asks for confirmation at startup. `--yes` skips this prompt. A new name
    needs no confirmation.
  - A name that conflicts with a variable from an enabled provider, such as
    `GITLAB_TOKEN`, stops the launch.

#### `providers.hooks`

This section configures host executables that run before (`preStart`) or after
(`postEnd`) the agent session. See [Set up session hooks](../how-to/session-hooks.md)
for the procedure and [Session-hooks contract](hooks-contract.md) for execution order,
environment variables, stream handling, and the stdout contribution object.

- **`providers.hooks.preStart` and `providers.hooks.postEnd`:** maps of
  `name → hook`. Entries merge by field across config layers and run in lexical key
  order. A key may contain letters, digits, `-`, `_`, and `.`, and must start and end
  with a letter or digit.
- **`exec`** (string, required for enabled entries): executable to run. Before
  `corral run`, the exact file content requires interactive approval. See
  [Repository config approval](../explanation/trust-gate.md).
- **`args`** (list of strings, default `[]`): arguments passed after `exec`. Lists merge
  append-unique, so a later layer can add arguments but cannot remove an earlier one.
  To replace the list, disable the original entry and define another key.
- **`optional`** (boolean, default `false`): applies only to `preStart`. When `true`, a
  nonzero exit prints a warning and lets the launch continue. `postEnd` failures always
  warn and never replace the agent's exit status.
- **`enabled`** (boolean, default `true`): controls one entry. Because maps merge by
  field, `.corral.local.yml` can disable a project hook with only `enabled: false`.
- **Default entries:** none. `corral run --dry-run` never runs a session hook.

```yaml
providers:
  hooks:
    preStart:
      10-update-datasources:
        exec: ./scripts/update-datasources.sh
        args: [--fast]
    postEnd:
      session-report:
        exec: ./scripts/session-report.sh
```

#### `providers.docker`

- **`enabled`** (boolean, default `false`): mounts the default Docker daemon socket
  read-write and `~/.docker` read-only.
- **`optional`** (boolean, default `false`): when `true`, a missing socket or other
  provider error prints a warning and skips Docker. When `false`, either error stops the
  launch.

#### `providers.ssh`

- **`enabled`** (boolean, default `false`): forwards the SSH agent socket and
  `SSH_AUTH_SOCK`, then mounts read-only `~/.ssh/config`, included files, and
  `known_hosts`. Private keys remain masked; the host agent performs signing.
- **`optional`** (boolean, default `false`): when `true`, a missing agent or other
  provider error prints a warning and skips SSH. When `false`, either error stops the
  launch.

#### `providers.home`

The home provider sets the sandbox's `$HOME` to a persistent private directory. It
links allowed host paths into that directory; other writes under `~` stay out of the
host home. npm, Go, pip, uv, yarn, and pnpm caches persist there between sessions.

corral never replaces a real file or directory in the private home. Such an entry shadows
the host path it stands in for: `$HOME/<path>` in the session is the private copy, and
`corral run` warns unless the entry is listed under `keep`. For Claude Code without
`CLAUDE_CONFIG_DIR`, a shadowed `~/.claude` also hides the hooks `corral sync` registered,
so `keep` never silences that warning.

- **`enabled`** (boolean, default `true`): when `false`, the sandbox uses the host's
  `$HOME` location instead.
- **`path`** (string, default `""`): host directory to use as the sandbox's `$HOME`.
  corral expands `~`, and the resulting path must be absolute. An empty value uses
  `~/.cache/corral/home-<hash>`, where the stable hash identifies the selected agent's
  config directory: `~/.claude`, `~/.pi`, or the directory `CLAUDE_CONFIG_DIR` or
  `PI_CODING_AGENT_DIR` points to. Each agent and each relocated config directory
  therefore has its own private home. `corral validate` prints the resolved directory.
- **`keep`** (list of strings, default none): private-home entries that intentionally
  shadow an allowed host path, relative to the private home (`.local/share/uv`; a leading
  `~/` means the same). corral skips the shadow warning for a listed entry and anything
  under it.

Home isolation applies to the whole home. To share one host path, add that path under
`providers.paths.rw` or `providers.paths.ro`. corral never links the always-blocked
paths into the private home.

#### `providers.kubernetes`

The Kubernetes provider creates a per-session ServiceAccount, requests a bounded token
outside the sandbox, and mounts a minimal kubeconfig. See the
[Kubernetes setup guide](../how-to/kubernetes.md) for host RBAC and administrator setup.

- **`enabled`** (boolean, default `false`): enables the provider.
- **`mode`** (string enum: `managed` or `preProvisioned`; default `managed`): chooses
  who creates the RBAC bindings. Other values are rejected.
  - In `managed` mode, corral creates RoleBindings and ClusterRoleBindings from
    `permissions`. The host identity needs the required cluster RBAC and permission to
    bind every selected role.
  - In `preProvisioned` mode, an administrator creates group bindings for a dedicated
    namespace. corral creates only the per-session ServiceAccount, revocation Secret,
    and token. The host identity needs the stock `edit` role in that namespace.
    `permissions` must be absent, and `serviceAccountNamespace` is required.
- **`optional`** (boolean, default `false`): when `true`, a missing host prerequisite or
  provider error prints a warning and skips Kubernetes. When `false`, either error stops
  the launch.
- **`tokenLifetime`** (duration, default `8h`, maximum `24h`): requested token lifetime.
  The cluster may return a shorter lifetime. The startup banner reports the actual
  expiry and warns when it is shorter than requested.
- **`as`** (string, default empty): user to impersonate for the provider's host-side
  Kubernetes API calls, like `kubectl --as`. The base identity needs `impersonate`
  permission, but this setting does not change the ServiceAccount in the session token.
- **`serviceAccountNamespace`** (string): namespace for the per-session ServiceAccount
  and, in `preProvisioned` mode, its revocation Secret. The default in `managed` mode is
  `corral`; corral creates a missing namespace. In `preProvisioned` mode there is no
  default, and the administrator must create the namespace first.
- **`permissions`** (list of [permission entries](#kubernetes-permission-entries)):
  RBAC for the session ServiceAccount. The default is one cluster-wide binding to the
  built-in `view` ClusterRole. This field is valid only in `managed` mode.
- **`readOnlyRoles`** (list of role names, default `[]`): additional role names corral
  should treat as read-only. `view` and `infra-view` are always in the read-only set.
  At launch, corral warns when `permissions` names another role. This check compares
  names without querying the cluster and never blocks the launch. The field has no
  effect in `preProvisioned` mode because that mode rejects `permissions`.

##### Kubernetes permission entries

This list is valid only in `managed` mode. Each entry must have exactly one scope,
`clusterWide` or `namespaceSelector`, and exactly one role, `clusterRole` or `role`:

- `clusterWide` (boolean) with `clusterRole` (string) creates one
  `ClusterRoleBinding`.
- `namespaceSelector` with `clusterRole` creates a `RoleBinding` to that ClusterRole in
  every matching namespace.
- `namespaceSelector` with `role` (string) creates a `RoleBinding` to that namespaced
  Role in every matching namespace.

`clusterWide: true` **requires** a `clusterRole` (a ClusterRoleBinding cannot reference a
namespaced Role). `namespaceSelector` mirrors a Kubernetes `LabelSelector`:

```yaml
permissions:
  - clusterWide: true
    clusterRole: view
  - namespaceSelector:
      matchLabels:
        team: platform
      matchExpressions:
        - key: tier
          operator: In # In | NotIn | Exists | DoesNotExist
          values: [prod, staging]
    clusterRole: edit
```

An empty `namespaceSelector` matches all namespaces. corral warns before launch but
allows you to continue.

#### `providers.gitlab`

The GitLab provider uses the host's `$GITLAB_TOKEN` to create a scoped, short-lived
token outside the sandbox. It sets the new token as `GITLAB_TOKEN`, forwards supported
`glab` connection variables from the host, and revokes the token on normal exit. It adds
no mounts. See the [GitLab setup guide](../how-to/gitlab.md) for host-token requirements.

- **`enabled`** (boolean, default `false`): enables the provider.
- **`optional`** (boolean, default `false`): when `true`, a missing host token or provider
  error prints a warning and skips GitLab. When `false`, either error stops the launch.
- **`type`** (string enum: `personal` or `project`; default `personal`): token type.
  Other values are rejected.
  - A `project` token belongs to a synthetic `project_<id>_bot` user, which owns issues,
    merge requests, comments, and other objects created with the token.
  - A `personal` token belongs to the user identified by the host token. GitLab's admin
    endpoint creates it, so the host token must have administrator rights.
- **`host`** (string without a URL scheme): GitLab instance. Config has no fixed default;
  corral checks `GITLAB_HOST`, then `GL_HOST`, and otherwise uses `gitlab.com`. Set this
  field for a self-hosted instance. corral never infers it from the Git remote.
- **`project`** (project path or numeric ID): project for a project token. By default,
  corral reads `origin` from `<workdir>/.git/config`. Auto-detection therefore requires
  the workdir to be the root of a regular checkout; set this field for a subdirectory or
  linked worktree. This field is used only when `type` is `project`; personal tokens
  ignore it.
- **`scopes`** (list, default `[read_repository, read_api]`): scopes for the session
  token. Set `[api]` when the session needs to create or change issues and merge requests.
- **`role`** (string enum: `guest`, `reporter`, `developer`, `maintainer`, or `owner`;
  default `developer`): maximum project role for a project token. This field is rejected
  for personal tokens because they use the GitLab user's existing project roles.
- **Token lifetime:** fixed at one day, GitLab's minimum expiry granularity.

### `policy`

Tunes the hook-side policy engine.

#### `policy.incidentHint`

- **Type:** string
- **Default:** empty, which uses `Treat this credential as potentially exposed:
rotate/revoke it and inform IT/Security.`
- **Behavior:** replaces the incident-response sentence appended to secret-detection
  messages. Use it for an organization-specific contact or runbook, and do not include
  credentials.

#### `policy.secretScan`

- **`entropyThreshold`** (float, default `0`): values greater than `0` enable the
  high-entropy heuristic at that bits-per-byte threshold. A threshold around `4.0` to
  `4.5` is typical for base64. `0` scans only known credential formats. Negative values
  are rejected.
- **`skipPaths`** (list of absolute or `~`-relative directories, default `[]`): paths
  exempt from content scanning.

#### `policy.audit`

The audit log records one JSON line per policy decision. Each line includes the decision
and a summary of the tool parameters; see the [audit-log format](audit-log.md). Logging is
always enabled, and the removed `enabled` key is rejected. If writing the log fails, the
policy decision does not change. Policy prevents the agent from truncating or deleting
the live log and backups.

When the live log is older than `rotateInterval`, corral renames it to
`<path>.<UTC-timestamp>`. At rotation time, it removes backups older than `retention` and
adds `.gz` when `gzip` is enabled. Durations accept Go units such as `12h` and `90m`,
plus `d` (day), `w` (week), `mo` (30 days), and `y` (365 days).

- **`path`** (absolute or `~`-relative path, default empty): log file location. An empty
  value places `corral-audit.jsonl` under the selected agent's config directory:
  `$CLAUDE_CONFIG_DIR` or `~/.claude` for Claude Code, and `$PI_CODING_AGENT_DIR` or
  `~/.pi` for pi. In the sandbox, `CORRAL_AUDIT_PATH` holds the log path. For a custom
  path, corral creates the parent directory and adds it to
  [`providers.paths.rw`](#providerspaths), so use a dedicated directory. corral refuses
  a parent directory that is or contains the home directory.
- **`rotateInterval`** (duration, default `1w`): age at which corral rotates the live
  log. Must be positive.
- **`retention`** (duration, default `6mo`): how long to keep a rotated backup, measured
  from its rotation window. Must be positive and at least `rotateInterval`.
- **`gzip`** (boolean, default `true`): compress rotated backups as `.gz` files.

Recipes for reading the log:
[troubleshooting](../how-to/troubleshooting.md#reading-the-audit-log).

### `update`

This section controls the version check performed by `corral run`. It does not change
the policy hook. See [corral update](commands.md#corral-update) for the command and
[Upgrade corral](../how-to/upgrade.md) for the procedure.

- **`checkOnStart`** (boolean, default `true`): checks at most once per day, with state
  cached under `~/.cache/corral`. When a newer release exists, the launch banner prints
  an advisory notice; this notice does not trigger confirmation by itself. The check has
  a short timeout, failures do not stop the launch, and `--dry-run` never runs it. Set
  this field to `false` to disable launch-time checks.

The release source (owner and repository on GitHub) is fixed when corral is built from the
module path and cannot be changed by config. If the repository is private, set
`GITHUB_TOKEN` (or `GH_TOKEN`) in the environment so the check can authenticate; a public
repository needs no token.

### `profiles`

- **Type:** map of profile name to partial config.
- **Behavior:** `corral run --profile <name>` or `-p <name>` applies a named profile after
  the built-in, global, project, and local config. Repeat the flag to apply profiles from
  left to right. Later profiles replace scalar values, while lists continue to merge
  append-unique. Selecting one name twice or selecting an unknown name is an error.

```yaml
profiles:
  offline:
    hostname: corral-offline
  # corral run -p offline -p ansible adds a vault password to the env allowlist
  # without restating the base passthrough:
  ansible:
    providers:
      env:
        passthrough: [ANSIBLE_VAULT_PASSWORD]
```

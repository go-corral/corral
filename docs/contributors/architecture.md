# corral: architecture

This contributor-facing reference records the locked decisions, the two-program
structure, and the per-package architecture. For *using* corral see
[the user docs](../README.md); for the threat model and the hard guarantees see
[threat-model.md](../explanation/threat-model.md); for dev setup and conventions see
[CONTRIBUTING.md](../../CONTRIBUTING.md).

> **Verify against the source.** This document explains *why* the design is shaped
> the way it is; it is not generated. Where it could drift from the code, the source,
> `go test`, and `git log` are ground truth; confirm against them before concluding
> something is missing.

`corral` sandboxes a Claude Code instance and enforces security policy on its tool
calls.

## Locked decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Language | **Go** | Fast hook startup (no per-tool-call latency tax), `client-go` for the kubernetes pain, a single static binary, trivial Linux+macOS cross-compile. |
| Scope | **Full rewrite, one language** | Single toolchain, clean end state; the rewrite-trap risk is mitigated by the checklist below. |
| Egress | **Out of scope** | No egress filtering ships today; the sandbox has full network access. If it is ever added, the intended shape is a dynamic prompt-proxy (not static rules), sketched under "Egress" below so today's choices keep that option open. |
| Config | **Layered YAML** (global / project / `.local`) | A single validated config tree (deep-merged across layers) instead of a sprawl of environment variables. |

## Two execution profiles

corral is **two programs with opposite constraints, served by one Go binary**:

- **Launcher** (`corral run`): runs once per session, latency-irrelevant, carries the
  heavy logic (build the `SandboxSpec`, resolve providers, launch the child).
- **Hook enforcer** (`corral hook …`): fires on *every* tool call (the PreToolUse
  matcher is the match-all `*`, so every decision is audited, allow or deny),
  must start in milliseconds, and **must fail closed**. Go's ~5-15 ms startup
  is why it beat Python here (a ~100 ms/call interpreter tax would be a felt
  per-call regression).

Operational consequence: heavy logic belongs in the launcher path; the hook path
stays fast and **never fails open**.

## Config

`internal/config`. Three tiers, deep-merged, schema-validated, **fail-closed on
parse error**:

1. `~/.config/corral/config.yml` (or `$XDG_CONFIG_HOME/corral/`): global defaults
2. `.corral.yml`: project, committed (discovered by walking up from the cwd)
3. `.corral.local.yml`: gitignored per-user overrides

**Merge semantics.** Later layers replace earlier **scalars** (so a `.local`
`enabled: false` overrides that one knob, it does not kill a whole provider); **lists
merge append-unique**, additive, never silently dropping a lower layer's entries, so
the built-in defaults always apply. Config files use the `.yml` extension only;
`.yaml` is not read.

**Two consumers.** The launcher reads the merged config directly; `corral sync`
writes the hook registrations into Claude's own `settings.json`. Named **profiles**
(e.g. `k8s-admin`, `offline`) select variants; `--profile`/`-p` is repeatable to stack several
as successive layers, later one winning on scalars.

**Startup banner & advisory warnings.** Every `corral run` prints a banner to
**stderr** that shows what the session can reach under the *effective* (layered +
profile) config. Beside the mark it shows the version and profiles, then a roll-up:
the project dir, extra rw/ro grants, the `$HOME` mode, and the audit log. Below it, one
ruled section lists the provider status rows. Advisory **warnings**
(highlighted on a tty, suppressed under `NO_COLOR`/`TERM=dumb`) flag footguns that work
but deserve a second look: docker enabled (root-equivalent host access), a
`providers.paths.rw` grant that overrides a baseline read-only system path, and a
`providers.block` entry that does not exist on the host. `corral validate`
surfaces the same advisory set from one shared renderer. The banner is on stderr so
`--dry-run`'s stdout (the argv) stays pipeable.

**Self-protection of corral's own config.** The project dir is mounted read-write, so
the policy hook denies *writes/deletes* (not reads) of corral's own launcher config:
`.corral.yml`, `.corral.local.yml`, the global `corral/config.yml`, exactly as it
protects the Claude-side hook settings. Otherwise a prompt-injected agent could plant a
config that widens the sandbox on the next launch. The always-blocked paths are un-grantable
regardless.

**claude.ai connectors (`agents.claude.claudeaiConnectors`, default `false`).** A Claude
subscription login auto-injects the account's claude.ai connectors (remote MCP servers),
which may be **org-managed** (not user-disableable in the web app), the opposite of
corral's explicit-grants model, so they are **off by default**. When `false`, the
launcher sets `ENABLE_CLAUDEAI_MCP_SERVERS=false` in the sandbox env, Claude Code's own
kill switch, which short-circuits before the account/org fetch and so overrides
org-managed enablement. A specific server can be added explicitly as a local MCP (which
is also removable). Set `true` to opt the whole account set back in.

## Agents

corral supports more than one coding agent (Claude Code and pi today; Codex planned). Each
agent differs in small, specific ways: its binary name, where it keeps account/auth state,
how policy enforcement is wired (claude registers a hook in `settings.json`; pi rides an
in-process bridge corral activates per launch), what env it needs, and which paths it touches
outside its config dir. `internal/agents` isolates all of that behind one interface so the
sandbox, cli, config, policy, and providers packages never name a specific agent.

**Package split (one interface, one package per agent).**

- `internal/agents/spec`, the **contract**: the `Agent` interface, the `AgentConfig` interface,
  plus every agent-neutral carrier type (`Launch`, `ConfigPath`, `StatusInput`,
  `SyncInput`/`SyncReport`, …) and the shared `BinDir` helper. It is the **leaf**.
  It imports only `internal/health`, whose `health.Check` is the result type of `Doctor`.
- `internal/agents/claude`, `internal/agents/pi`: one **implementation per agent**, each its
  own package depending only on `spec` (claude additionally imports the leaf `internal/agents/claude/claudecfg`
  for `settings.json` generation). Each exposes `New() spec.Agent` and asserts conformance with
  `var _ spec.Agent = agent{}`, **and owns its yaml-tagged config type** (`claude.Config`,
  `pi.Config`) implementing `spec.AgentConfig` (the config-derived sandbox env and `validate` fields):
  `internal/config` embeds those agent-owned types into its `Agents` struct and dispatches to the
  selected agent's config, so the config surface and the code that consumes it live in the same
  package (mirroring how the provider packages own their `Config` types). `Launch()` carries only
  the STATIC per-agent contribution (temp-env aliases, the policy extension) that depends on the
  agent's identity, not its config. The compiler now prevents one agent's package from reaching
  into another's internals, or an upper layer from touching an implementation detail.
- `internal/agents`, the **facade**: it builds the registry from `claude.New()` + `pi.New()`,
  exposes `Lookup`/`Known`/`Default`/`AllReservedEnv`, and re-exports the `spec` types as
  **aliases** (`type Launch = spec.Launch`). Upper layers import only this one package; an
  implementation returns `spec.Launch` and the cli consumes `agents.Launch` with no conversion.

This layering is what lets each agent be its own package without an import cycle. The cycle a
naïve split hits (the registry must import the implementations to register them, and the
implementations must import the package that holds the interface) is broken by keeping the
**contract** (`spec`) separate from the **registry** (`agents`): implementations depend on
`spec` only. Two packages then depend on the implementations: the facade imports them to build
the registry, and `internal/config` imports them to embed their agent-owned `Config` types (the
ownership arrow points config → agent, exactly as it does for providers, compile-graph-only,
one static binary either way). The dependency graph is strictly one-way: `claude`/`pi` → `spec`;
`agents` → {`spec`, `claude`, `pi`}; `config` → {`agents`, `claude`, `pi`}; `cli` → `agents`. The
seam imports neither `internal/sandbox` nor `internal/config`; config bridges **to** agents
(`AgentLaunch`/`AgentEnv`/`AgentConfigPaths`/…), and the `agents.ConfigPath → sandbox.Rule`
mapping lives in `cli` (the composition root that imports both). Adding an agent is therefore a
new package plus one entry in the facade's registry list, its `Config` field on the
`config.Agents` struct, and a matching `agentConfig()` dispatch case, the drift-guard test
(`TestAgentConfigDispatch`) fails until that case exists.

How an agent contributes to a launch (its `Launch` values and `ConfigPaths`) is described under
[Sandbox](#sandbox): the agent supplies plain data, the launcher folds it into the spec.

## Sandbox

`internal/sandbox`. A declarative **`SandboxSpec`** (filesystem `paths` rw/ro, blocked
paths, env passthrough, net policy, syscall policy) that is **backend-agnostic** and
compiled per backend. The abstraction is deliberately **thin**, because bwrap (argv flags) and
Seatbelt (SBPL profile) share little, so a shared *spec* plus a per-OS split beats an
elaborate driver hierarchy.

**Per-backend packages behind the `Backend` interface.**

- `bwrap.Backend` (`internal/sandbox/bwrap`, Linux): emits `bwrap` argv.
- `seatbelt.Backend` (`internal/sandbox/seatbelt`, macOS): generates the SBPL profile
  run via `sandbox-exec`. Go's `crypto/x509` → trustd Mach-IPC path works inside the
  profile (TLS is not broken by Seatbelt).
- Future backends (Landlock, nsjail, devcontainer) are each a new sub-package + one
  factory case.

`DefaultSpec` builds **one** spec for every backend (it does not compile the baseline or
carry a backend field; it supplies the per-launch mounts + the baseline `Tokens`). Each
backend compiles the embedded baseline **itself** in a `Prepare(spec, w)` step: bwrap
folds the baseline into `spec.Mounts/Symlinks` (so `Argv` stays a pure spec→argv
emitter); seatbelt creates the isolated `/tmp` session dir, sets the temp env + its
`$SESSION_TMPDIR` token, and returns a cleanup + a pre-exec `Chdir`. The launcher runs
`Prepare → Argv` uniformly; the per-backend differences live behind interface methods
(`Prepare`/`Argv`/`ReadOnlyTargets`/`UnavailableHint`). The **factory**
(`cli.newBackend`, the one `switch Kind`) lives at the composition root, so the
`sandbox` package imports no backend (no import cycle).

**Symlinked baseline sources.** When a baseline rule's host path is a symlink, the Linux
compiler by default *reproduces the link* (`--symlink target path`), correct for a
merged-`/usr` layout (`/bin → usr/bin`), whose target lives under the mounted `/usr`. That
breaks for a link pointing **outside** the mounted tree: on systemd-resolved distros
`/etc/resolv.conf → /run/systemd/resolve/stub-resolv.conf`, and nothing under `/run` is
mounted, so a reproduced link dangles and DNS dies. The rule flag **`resolveSymlinks`**
(shared with macOS) fixes this: the compiler **fully canonicalizes the path** (every symlink
hop, symlinked ancestors included) and **binds the real target's content at the unresolved
destination** instead. Full resolution, not one hop, is what macOS needs: seatbelt matches a
rule against the kernel-canonical path of the file opened, so a chained or symlinked-ancestor
dotfile (`~/.gitconfig → ~/.dotfiles/git/gitconfig`, `~/.dotfiles` itself a symlink) would
otherwise grant a path the kernel never presents and the read `EPERM`s. The `resolv.conf` and
`$HOME/.gitconfig` rules set it; it inherits the rule's optionality, so a required rule still
fails closed if the resolved target is absent.

The two backends then diverge, and the difference is load-bearing. Linux binds the target **at
the unresolved destination**, so inside the namespace the path is a real file and no link is
ever walked. macOS has no bind-remap: the child walks the host chain for real, and
canonicalizing is itself a policed read: the kernel must `readlink` each node, which
deny-by-default refuses for any node the profile does not name. So the Seatbelt compiler grants
the resolved target **and every symlink node crossed on the way to it**, each as a node
(`literal`), never a subtree. This is the same grant the baseline makes by hand for `/etc`,
`/tmp` and `/var`, "REQUIRED to resolve /var/… paths". Granting only the endpoint produces the
confusing failure where the sandbox allows the file and the read still `EPERM`s at a link above
it.

**Backend selection** is resolved **once** per command via `sandbox.Kind` +
`ResolveKind(override)`, the single place `runtime.GOOS` maps to a backend
(`DefaultKind`: linux→bwrap, darwin→seatbelt, **else an explicit "unsupported OS" error**
so we fail early instead of guessing). An explicit `-backend bwrap|seatbelt` is honored
on **any** OS (so `run --dry-run -backend bwrap` can inspect the bwrap argv on macOS; a
real launch still gates on the backend's `Available()`). Each backend owns a `Doctor()`
returning only its own `health.Check` results (bwrap: binary + PID namespace + legacy TIOCSTI;
seatbelt: `sandbox-exec`).
The two backend-intrinsic `runtime.GOOS` checks that remain are correct and stay: the
Seatbelt backend's `Available()`, and the hook's `logicalSysPath` `/private`
normalization (real-OS filesystem semantics, not launch-time dispatch).

**The embedded baseline is the law.** `internal/sandbox/baseline/sandbox-permissions.json`
(`go:embed`) is a hard, schema-validated, **deny-by-default** base-filesystem allowlist,
with OS differences carried per-rule via `archs`. Both backends compile from it, which
makes Linux vs. macOS directly comparable and conformance-testable. User `providers.paths.rw` /
`providers.paths.ro` layer **additively** on top; the baseline itself is never loosened by config.

The baseline is **agent-neutral**. Files the *selected* agent needs OUTSIDE its config dir
(Claude Code's `~/.claude.json` + its macOS atomic-write siblings and node cache) are the
agent's `ConfigPaths()` (plain data on the `agents.Agent` interface), which `cli` maps to
`sandbox.Rule` and the launcher unions with the embedded baseline via `sandbox.RulesFor(spec)`.
Both backends and the home-symlink farm compile `RulesFor` (baseline + `spec.AgentRules`), so an
agent path is compiled **identically** to an embedded rule (token expansion, `archs`, regex), yet
appears only when that agent runs; `corral run pi` binds no claude path. Keeping these on the
agent (not the embedded JSON) is what makes the baseline genuinely agent-neutral; the generated
[permissions reference](../reference/sandbox-permissions.md) therefore lists only the baseline.

**The always-blocked paths.** `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.config/gcloud`,
and `~/.azure` are **always** blocked and
**cannot be removed** by config; `providers.block.directories`/`providers.block.files` can only *add*. Relative
paths and overlapping grants are rejected at config load. (See [threat-model.md](../explanation/threat-model.md)
for the full guarantee and the criterion an entry must meet; policy's
`secretDirComponents`/`secretDirPairs` segment classifier must include each addition.)

Containment is enforced on **real** paths, which splits the guard across the two programs
because only one of them may touch host state:

- `paths.Config.Validate`: the **lexical** check, in the config-load path both programs run.
- `paths.Config.ValidateResolved`: the **symlink-resolving** check, called only from the
  launcher (`cli.checkResolvedPathGrants`, from `run` and `validate`). It lives there
  deliberately: it stats the host, and `config.Validate` is re-run by the hook on every tool
  call; that path must stay fast and must not acquire host-dependent failure modes. bwrap
  `realpath()`s every bind source before it pivots, so a grant that only resolves into an
  always-blocked path would mount the secret dir under the link's unmasked name; a symlinked grant
  is therefore refused in **both** containment directions (into it, and containing it).
- `config.AlwaysBlockedMaskPaths`: the FS mask adds the **resolved** path when an always-blocked
  dir is itself a host symlink (dotfiles-managed `~/.ssh`). This is the one case where the mask,
  not the hook, is authoritative: in-sandbox that path is an empty tmpfs (bwrap) or denied
  (Seatbelt), so the symlink is gone and the hook's `CanonicalizeRoot` cannot rediscover the
  target. Safe, because a masked directory has nothing left to leak. It de-duplicates, so a
  normal home emits a byte-identical argv/profile (the goldens do not move).

**Working directory.** The per-launch writable workdir is the launcher's to supply, not
the baseline's: it binds `$PWD` read-write at its own in-sandbox path. **Exception:** when
`$PWD` resolves to `$HOME`, it does *not* bind home (that would expose the whole home tree
*and* back the always-blocked masks with the real host secret paths); instead it creates a
fresh `os.MkdirTemp` scratch dir and leaves home unbound. The scratch dir is
intentionally **not** cleaned up (it lives under
`$TMPDIR`, reaped by the OS; keeping it lets the launcher keep the `syscall.Exec` fast
path). Implemented in `cli/run.go` `resolveWorkdir`.

The scratch dir, like every project workdir, is mounted at its **own path** on both
backends, and that path is where the launch `chdir`s. There is **no in-sandbox remap**:
macOS Seatbelt has no bind-remap and can only allow a path *in place*, so forcing both
backends onto the same own-path model keeps them identical. The one Linux subtlety: bwrap
emits the fresh `/tmp` tmpfs **before** the bind mounts, so a scratch dir under `/tmp`
layers on top of the empty tmpfs instead of being shadowed (the blocked-path masks still
come *after* the binds, so they keep winning (see `bwrap.Backend.Argv`). Within the bind
section, every read-only bind precedes every read-write bind, so a read-write grant shadows
any read-only grant it overlaps, whichever of the two is broader. That is the bind-mount
rendering of Seatbelt's rule that a path is writable wherever a read-write grant covers it,
and it keeps the two backends identical here as well.
`SandboxSpec.Mounts[].Dst` remains a low-level bind-remap capability for providers and
overlays, but the workdir path no longer uses it.

**Existence-guarded registration.** Every hook command corral persists is wrapped, not bare:

```sh
if [ -x "<bin>" ]; then exec "<bin>" hook <sub>;
elif [ -n "$CORRAL_SANDBOX" ]; then echo "<msg>" >&2; exit 2; fi
```

The registration is *global*, so it fires in sessions corral did not launch, under a
different sandbox, or after corral is uninstalled. Each state below is deliberate:

| Binary | Context | Result |
| --- | --- | --- |
| present | anywhere | `exec` replaces the shell, so corral's own exit status reaches Claude Code untouched |
| absent | outside corral's sandbox | silent exit 0 (a POSIX `if` with no matching clause), so a foreign sandbox sees no error spam |
| absent | inside corral's sandbox | `exit 2`: enforcement is broken and must not look healthy |

The `exit 2` effect differs per event and cannot be made uniform: `PreToolUse` and
`UserPromptSubmit` **block**, while `PostToolUse` and `SessionStart` cannot block and only
surface the message. Even there the visible error is the point. The shape is constrained twice:
`exec` must never become `&& …` or `… || true` (that swallows a fail-closed exit 2 and turns the
gate into a no-op), and the interpolated binary path is validated at sync time. A relative
path is first made absolute; a path containing `"`, `$`, a backtick, `\`, or a control
character is refused because those characters stay live inside the double-quoted `sh`
string. The registration is written with
JSON HTML-escaping **off**, so `>&2` survives literally rather than as `>&`; the goldens
that pin it stay reviewable as the security artifact they are.

A legacy *bare* entry (`<bin> hook <sub>`, what corral wrote before the guard) is still
recognized as corral-owned, so an ordinary `corral sync` **replaces** it; Claude Code merges
hooks additively, so a leftover bare entry would otherwise run corral a second time per call.

**Sandbox-presence warning (one-time soft block).** Because the registration reaches a bare
`claude` too, the `UserPromptSubmit` hook fires whether or not Claude was launched via
`corral run`. When it detects it is *outside* the sandbox it **swallows the first prompt and
shows a prominent warning, then lets the session proceed**, a speed bump, not a wall. Its
purpose is to catch the accidental bare-`claude` launch: filesystem isolation and the
credential masks are off there, leaving the policy engine as the only barrier. It is
explicitly **not** a defense against deliberately running unsandboxed: after the one
warning, re-submitting the prompt proceeds (`resubmit-once`, keyed on a per-session marker
under `$TMPDIR`); a fresh session re-warns.

**Two opt-outs, kept distinct.** `CORRAL_PRESENCE_ACK=1` silences the *warning* and nothing
else (the prompt secret scan and tool-call policing keep running) for someone deliberately
working under another sandbox. `CORRAL_DISABLE_HOOKS=1` disables corral *entirely*. They are
separate on purpose: if the only way to stop a once-per-session nag were the kill switch, the
warning would train users to disable the safety layer, and the first thing they would lose is
the prompt secret scan. Both parse strictly (`1`/`true` only) so a `0` or `false` never reads as
"off". The kill switch is honored **only** when `CORRAL_SANDBOX` is absent; inside corral's own
sandbox it is ignored, and `corral run` says so when it sees it set, which is what keeps a
bare-launch convenience from becoming an in-sandbox enforcement switch; it is also in config's
reserved env set and absent from the passthrough defaults. It leaves one `hooks-disabled` audit
line per session, so a session with corral disabled is never indistinguishable from one whose enforcement
silently broke.

Because the block is a one-shot acknowledgment, detection does **not** need to be
unspoofable: `sandbox.InsideCorral()` simply reads the launcher-set `CORRAL_SANDBOX` env
marker (`sandbox.SandboxEnvVar`). That is cross-platform, **cgo-free** (preserving the
static binary + clean cross-compile), and identical on both backends. The warning is
delivered via a **`UserPromptSubmit` hook returning `{"decision":"block","reason":…}`**:
empirically the block path is the *only* hook channel that reliably reaches the human:
non-blocking `additionalContext`/`systemMessage` reach only the model, and `SessionStart`
cannot block at all, so blocking once is the only way to guarantee the warning is seen.

**SessionStart note.** A `SessionStart` command hook (`corral hook session-start`) emits a
deliberately short, **model-only** `additionalContext` note: what is writable, that the
always-blocked paths are masked (so the model doesn't waste turns probing them), that tool calls
are policy-gated, and that scratch files belong in a project-local `scratchpad/` rather
than the harness's `/tmp` scratchpad path (unreachable on Linux's fresh tmpfs, session-private
on macOS's `$TMPDIR`, so files left there are invisible to the user). That scratch bullet is
kept **backend-agnostic** (no `$TMPDIR` token, no `runtime.GOOS` branch); the platform-specific
`/tmp` mechanics stay on the backend channel below. Two secret-free channels then append extra bullets, each read from a
launcher-set env var: the **resolved backend's `AgentNotes()`** via `CORRAL_BACKEND_NOTES`
and the **active providers' `AgentNotes`** via `CORRAL_PROVIDER_NOTES` (see *Providers*);
session-dynamic lines like the minted `GITLAB_TOKEN`'s scope/expiry. Backend notes render
first; today only the seatbelt backend contributes any, that `/tmp` is inaccessible and to
use `$TMPDIR`, plus a heads-up that SIP tools print a harmless `xcrun_db-*` warning to ignore
, so driving the `/tmp` line off the backend rather than a `runtime.GOOS` branch keeps the
hook backend-agnostic. An absent/empty var appends nothing. It is gated on the `CORRAL_SANDBOX` marker, so for a bare
claude running outside the sandbox it is a **silent no-op** (it must not claim a sandbox that isn't there). It
is registered with **no matcher** (the match-all form, so it re-injects after
startup/resume/clear/compact). `SessionStart` cannot block, so the hook only ever exits 0;
a marshal error fails safe by injecting nothing.

## Policy engine

`internal/policy`. One dispatched subcommand per event (`corral hook pre-tool-use --tool
Bash`), registered in Claude's `settings.json`. It closes the classic regex-matching
policy bypasses:

- **Realpath-canonicalize** every path before matching → kills renamed-secret and
  traversal bypasses.
- **Parse** the Bash command (do not regex it) → catches two-step pipe-to-shell,
  split-octal `chmod`, redirect-to-`.env`.
- **Content secret scan** (entropy + known formats: AWS keys, JWT, PEM, …) on read/write,
  with a tunable threshold and per-path opt-out.
- **Exit-2 fail-closed contract.** Every error path (unparseable input, evaluation
  failure, panic, signal) **blocks** (exit 2), never silently allows. `InstallFailClosedSignals`
  makes SIGINT/SIGTERM/SIGHUP exit 2 rather than Go's default 128+signo. This is the
  cardinal invariant of the package.
- **Structured JSON audit log**, rotated; it records the decision and reason plus a
  *structural* summary of the tool parameters (`input`) via `HookEvent.SanitizedInput`. An
  allowlist is kept verbatim: paths/patterns and the Bash command for any tool, plus the
  identifier fields of BUILT-IN tools (`auditBuiltinKeys`: WebSearch `query`, WebFetch `url`,
  `Task` `description`/`subagent_type`, the Grep/NotebookEdit modes, shell/cell ids). Every
  other value (content bodies, the free-text instruction fields (`prompt`/`plan`/`message`),
  the free-text args MCP tools name freely, unknown keys) is reduced to a byte count. The
  built-in identifier set is NOT applied to MCP tools (only the path set is), so a free-text
  MCP arg the secret scanner may flag and block never lands verbatim.
- **MCP tool calls are in scope.** The match-all PreToolUse matcher (`*`) covers `mcp__.*`, so MCP
  arguments are scanned for secrets (egress) and path-args checked against the blocked roots;
  a name-only "looks sensitive" classification of an MCP path-arg is **audit-only, not a
  block** (MCP args routinely name remote resources, so the local name classifier must not
  false-block). A separate **PostToolUse** hook scans MCP _responses_ and Bash command
  output, and withholds a secret-bearing one from the model (ingress, the priority
  direction, since a leaked secret in context is the harder problem). MCP arg/response shapes
  are arbitrary JSON, so the scans run on raw bytes and treat an unrecognized shape as
  _empty_, never a fail-closed block of a legitimate call (the built-in tools keep their
  strict contract). **PostToolUse withholding works by replacing the result via
  `hookSpecificOutput.updatedToolOutput`**: neither `exit 2` nor a `decision:block` withholds
  a PostToolUse result (it is already in context when the hook fires), so fail-closed here
  means _replace_, and every error path emits a withheld-marker replacement. The replacement
  **must match the original result's shape**: a content-block array for MCP, a `{stdout,…}`
  object for Bash, or Claude silently ignores it (a fail-open; handled by
  `updatedToolOutputFor`). The agent is blocked from hand-editing the project `.mcp.json`
  registry (the deliberate `claude mcp add` flow is not); `~/.claude.json` stays writable (it
  doubles as Claude session state).
- **The hooked tool call is the only enforcement seam, and `!` bash-mode sits outside it.**
  corral polices what crosses a *hooked* boundary (`PreToolUse`/`PostToolUse`/`UserPromptSubmit`).
  Claude Code's interactive `!` bash mode runs a command client-side and inserts its output into
  the context with **no hook of any kind**: it is not a `Bash` tool call and does not pass
  through `UserPromptSubmit`; so the secret scan never sees it (confirmed empirically 2026-06-18,
  issue #38). The filesystem sandbox still bounds the blast radius: the always-blocked paths stay
  masked even from `!`, so exposure is limited to sandbox-readable paths (chiefly the working dir). By
  contrast `@file` mentions **are** in scope; current Claude Code resolves them through the
  hooked `Read` tool (the older inline-slurp bypass that motivated #38 is gone), so they inherit
  the path-pattern and content scans. There is no settings surface to disable or reroute `!`
  today; closing it is an **upstream feature request**, not a corral-side fix. The runtime
  surfaces the gap as a line under the `policy` row of the startup banner, plus the security doc.

## Providers

`internal/providers`. Providers are how **sanitized host capabilities** cross the sandbox
boundary, the additive *grant* dual of the deny-by-default floor (the always-blocked
paths mask `~/.ssh`/`~/.kube`/the cloud CLI dirs; ssh-agent forwarding, the minted
kubeconfig, and aws-sts re-grant the *capability* without exposing the raw secret).

**Package split (same layering as agents).** The contract (`Provider`, `Contribution`,
`Session`, `Reaper`/`Orphan`, plus the shared implementation helpers (`ErrNoDryRun`,
`IsSocket`/`IsRegular`, `SanitizeLabel`)) lives in the leaf package
`internal/providers/spec` (imports only `sandbox`, for `Mount`). Each provider is its own
package (`internal/providers/{block,aiignore,paths,env,hooks,ssh,docker,home,gitlab,kubernetes}`)
depending only on `spec` (one exception: aiignore also imports `policy` for the shared
pattern matcher; the authoritative hook half must enforce the exact same globs), exposing
`New(...) spec.Provider`, **and owning its yaml-tagged
config type** (`gitlab.Config`, `kubernetes.Config`, …): `internal/config` embeds those
provider-owned types into its `Providers` struct, so the config surface and the code that
consumes it live in the same package, and no provider package imports `config`. (Config
therefore depends on the provider packages, and transitively on `sandbox` and heavyweight
deps like `client-go`, which is compile-graph-only: one static binary either way.)
`internal/providers` is the **facade**: it re-exports the `spec` types as **aliases**
(`type Contribution = spec.Contribution`) and owns the **engine**: `Active`/`Resolved`,
`Resolve`/`ResolvePreview`, `Apply`, `Cleanup`, and the gc reaper helpers, which only the
launcher calls, never an implementation. The **registry** (below) is the one place that
*constructs* implementations; its `Build`/`Probe` funcs call `ssh.New`, `docker.New`, …
directly; `config` imports the packages only for their `Config` data types.

**The provider registry** (`internal/providers/registry`) is the single, ordered
enumeration of the provider set, the analogue of the agents registry, adapted to two
provider-specific constraints: the impl packages cannot import `config` (the ownership
arrow points the other way), and the constructors take non-uniform inputs, so instead
of self-registering implementations it is a table of `Registration` entries (Name,
Builtin flag, and `Enabled`/`Optional`/`Grants`/`Warnings`/`Build`/`Probe` funcs over
`*config.Config` + a small host-facts `Deps` carrier). Every provider view derives from
it: the launch assembly (phase A `Builtins` / phase B `Features`), doctor's `Known`
probes, validate's `Views` intent summary, and the config-derived advisory
`ConfigWarnings`. Its order IS the canonical declaration order (apply order, collision
attribution, LIFO cleanup); reflection drift-guard tests pin it to the
`config.Providers` field order and pin the built-in set. Adding a provider = impl
package + config field + defaults block + one `Registration`; a half-registered
provider (parsing but silently never activating, which for a deny-style built-in
would be a silent fail-open) can no longer slip through: the drift guards fail the
test suite. The registry lives beside, not inside, the facade so the engine stays
config-free.

**Built-in vs. feature providers.** Every config-owned capability is a provider now; the
distinction that remains is *when* and *how* each resolves:

- **Built-in providers** (`block`, `aiignore`, `paths`, `env`, the leading fields of the
  `providers:` config section, declaration order = application order, deny before grant).
  Always active when their input is non-empty, never `optional`. Their `Mint` is **PURE by
  contract** (dryRun-identical, no side effect; pinned by a registry-level sweep), which is
  what allows the launcher to resolve them in **phase A, before the confirmation gate**: an
  `env.set` override surfaces as an advisory warning that feeds the gate (an aiignore
  `!`-negation is a non-gating status line, over-masking grants less, not more), and their
  deny channels are in the spec before phase B validates feature mounts against them. They
  contribute through the dedicated channels in the `Contribution` snippet below, which
  replicate the exact semantics the same config had when it was applied to the spec
  directly (grants stay collision-exempt Optional mounts; an `EnvSet` name CLAIMs its key,
  so a minted var colliding with it fails closed, attributed across both phases). Two
  deliberate asymmetries: the **always-blocked paths**
  never flow through a provider (`DefaultSpec` bakes them in, structurally out of reach),
  and **`env.passthrough` application** stays in `DefaultSpec`, because the base <
  passthrough < agent-env < sandbox-marker layering is load-bearing (the defaults forward
  agent config-dir relocators the agent's own env must win over; the marker is set last).
  The env provider owns the config surface, its validation, and the reporting: its
  `Validate` rejects a passthrough naming a corral marker outright (config, which owns the
  agent registry, passes it the reserved sets). The **provider-side half** of that same fence
  lives in `Resolved.Apply`, which pre-claims corral's control markers (`CORRAL_SANDBOX`,
  `CORRAL_GLOBAL_CONFIG`, `CORRAL_AUDIT_PATH`, `CORRAL_AGENT`, `CORRAL_BIN`) and both notes
  channels UNCONDITIONALLY (not just when this launch happened to set them), so no provider
  `Env` can plant one. It matters because the conditional ones (the global-config pin,
  `CORRAL_BIN`) are absent on most launches, and because one provider's `Env` is authored
  outside corral's own code: a session hook's stdout contribution (the hook executable
  is trust-hashed nowadays, but the fence deliberately does not lean on that; approval
  is a human judgment, not a content proof). The **hook never runs a provider**: it
  re-derives block/aiignore from the same config accessors (and the same
  `aiignore.Discover`) on every tool call, which is also what keeps mid-session aiignore
  matches enforced; the launch-time mask is defense-in-depth, the hook is authoritative.
- **Feature providers** (docker, ssh, home, kubernetes, gitlab): opt-in sanitized host
  capabilities: mounts + env + cleanup, "what a capability adds". Resolved in **phase B,
  after the gate**, because a minter's Mint is irreducibly a side effect (a declined
  launch must mint nothing). The `resolveProviders` test seam guards exactly this phase
  against dry-run and declined launches; pure phase A calls `providers.Resolve` directly.

Env vars are part of the provider pattern as a provider **output** (`Contribution.Env`:
k8s→`KUBECONFIG`, gitlab→`GITLAB_TOKEN`/`_HOST`, ssh→`SSH_AUTH_SOCK`). A capability's env
and mount travel **together** inside its provider, only when enabled, so `SSH_AUTH_SOCK`
is **not in the default `providers.env.passthrough`**; the SSH provider injects it only
with the matching socket. `GPG_TTY` is also absent by default and must be added to
passthrough explicitly when needed. Generic, non-feature vars (`TERM`, `LANG`,
`CLAUDE_CONFIG_DIR`, …) stay in the base passthrough, owned by the built-in env provider.

```go
// Contribution is purely in-memory & ephemeral: it has NO path into Config, so a
// minted secret structurally cannot be persisted to .corral.yml or the audit log.
type Contribution struct {
    Mounts     []sandbox.Mount             // providers import sandbox, one-way
    Env        map[string]string           // e.g. KUBECONFIG, GITLAB_TOKEN (secrets)
    Status     []string                    // for the OPERATOR (startup banner)
    AgentNotes []string                    // for the MODEL (session-start note)
    Warnings   []string                    // for the OPERATOR (after the providers section; a failing Mint puts them in its error)
    Cleanup    func(context.Context) error // in-session teardown (LIFO); nil if nothing to undo
    // PostSession is the session-END dual of Cleanup: declaration order (not LIFO),
    // unbounded context, warn-only, fires on any ended session + on an aborted launch once
    // registered. Used by the providers.hooks postEnd scripts (NOT the corral hook enforcer).
    // nil when the provider registers no session-end hook. It is also the
    // ONE field honored from a Contribution returned ALONGSIDE a Mint error, so a provider
    // that already produced side effects gets its pairing even for the abort it caused.
    PostSession func(ctx context.Context, exit SessionExit) error

    // Built-in channels (block/aiignore/paths/env: launcher half of the config
    // features; semantics replicate the pre-conversion direct spec application):
    RWPaths, ROPaths           []string   // same-path Optional grants, collision-exempt
    BlockedDirs, BlockedFiles  []string   // append-unique FS-mask extensions (not the always-blocked set)
    EnvSet                     []EnvEntry // ordered pins; override-with-warning
}

// Session is the per-launch context, used for resource naming + GC matching.
type Session struct{ User, ID, WorkDir string }

type Provider interface {
    Name() string
    Available(ctx context.Context) bool // prerequisites present?
    // Mint runs OUTSIDE the sandbox. dryRun (set by ResolvePreview: the --dry-run
    // profile, and the pre-gate mount set of a real launch) forbids side effects: a
    // minter whose contribution is irreducibly a live API call returns
    // spec.ErrNoDryRun and is listed as not-expanded in the preview.
    Mint(ctx context.Context, sess Session, dryRun bool) (*Contribution, error)
}

// Reaper is the OPTIONAL interface for providers that create out-of-process
// resources (minters: k8s SAs, temp kubeconfigs). It powers `corral gc` ONLY, and is
// a SEPARATE concern from in-session teardown: Contribution.Cleanup captured the exact
// handle Mint created and fires on exit; GC runs in a *different* process (the original
// is dead/SIGKILLed) so it rediscovers orphans by naming convention (corral-<user>-*),
// previews them, and Reaps only the approved subset. Socket-brokers don't implement it.
type Reaper interface {
    Provider
    GC(ctx context.Context) ([]Orphan, error)          // preview: list orphans, never delete
    Reap(ctx context.Context, approved []Orphan) error // delete the approved subset
}
```

**Orchestration rules.** Contributions apply in **config-declaration order** (phase A
built-ins, then phase B features); a duplicate env key or mount **target**
(provider-vs-provider or provider-vs-baseline) is a **launch error**, never a silent
override (fail-closed), and a later contribution's mounts are validated against the deny
channels earlier ones added. On a `Mint()` error mid-sequence, already-accumulated
cleanups unwind **LIFO** before the launch aborts.

**Two narrations, two audiences.** Both channels carry provider attribution: the engine
pairs every line with its provider (`providers.Notice`), so no consumer has to guess which
provider said what. `Status` speaks to the **operator**: the launcher's startup banner
renders the lines as name-labeled rows in the ruled `providers` section (what was minted,
scope, lifetime), the built-ins and the feature providers together after the mint. `AgentNotes` speaks to the **model**: `Resolved.Apply` newline-joins the
active providers' lines as `- <provider>: <note>` markdown bullets (paths backtick-quoted
by `spec.SummarizeQuoted`; self-delimiting even when a human echoes the var unquoted) into
the reserved `CORRAL_PROVIDER_NOTES` env var (`sandbox.ProviderNotesEnvVar`), appending
across the two phases (the second `Apply` never clobbers the first's notes), which the
in-sandbox session-start hook appends to the sandbox note; one env read, no file I/O on
the hook's hot path, and an absent var (no notes, or an older launcher) degrades to the
base note.
Notes exist only for **active** providers and may carry Mint-time dynamic facts (the
minted token's kind/scopes/expiry) plus quirks the model would otherwise waste turns on
(`glab auth status` misreporting env-token auth as unauthenticated). Both channels are
authored from metadata and MUST NOT carry a token value; the env var is reserved on both
sides (`providers.env.set` may not name it; a provider `Env` entry claiming it fails `Apply`
closed), and notes are deliberately terse; they ride the model's context every turn.

**Config.** Providers live in a typed-struct `providers:` subsection (not `map[string]any`),
so `KnownFields(true)` still fails closed on a typo'd key; adding a provider is a code
change, which is fine (a provider *is* code). Each provider carries `optional: bool` (a
`Mint()` error downgrades to skip-with-warning instead of failing the launch). docker and
ssh take `enabled` only, no sub-toggles; turning the feature on does everything it
needs.

**Lifecycle kinds** the one interface must cover (all reduce to a Contribution):

- *socket-broker*: mount a daemon socket; the daemon is the trust boundary: **docker**
  and **ssh** (the latter forwards the ssh-agent, including gpg-agent's ssh socket). Mints
  nothing; owns its socket mounts and the matching env as one feature.
- *credential-minter*: mint a scoped credential *outside* the sandbox, inject token +
  config: **kubernetes** (`client-go`), **gitlab**, later **gh**, **vault**, **aws-sts**.
- *artifact-sanitizer* (planned): read a host config, emit a filtered copy, mount that:
  later **git identity** (strip `credential.helper`/signing unless a credential provider
  is active).
- *home redirect*: **home** (default ON): redirect `$HOME` to a sandbox-private dir and
  symlink the allowed-under-home host paths into it, isolating writes to `~` (and the
  home-relative build caches) while persisting them across sessions. Mints no credential;
  it shapes the filesystem view. Subsumes the earlier standalone `cache` provider.
- *session hooks*: **hooks** (`providers.hooks`): run host-side executables around the
  session lifecycle (`preStart` before the agent, `postEnd` after). Each hook names ONE
  executable file (`exec` + `args`, exec'd directly, no shell), a shape chosen so the
  repo-config trust gate can hash the file: config bytes and hook code ride the same
  approve-once store (`collectHookExecs` in the cli composes it; `hooks.ResolveExec`/
  `hooks.HashFile` are the shared resolution+digest), and `postEnd` re-hashes at fire time
  (the session is the one window a live agent can rewrite a workdir hook; a mismatch skips
  that entry, warn-only). Mints and mounts nothing; a `preStart` hook's **stdout is a strict
  contribution channel** (captured, never printed: empty, or one `corralContributionVersion`
  JSON object) that folds `env`/`agentNotes`/`status` into the sandbox while its stderr is
  captured and surfaced post-exit. `postEnd` gets terminal stdout/stderr and the original
  host environment, not provider-contributed sandbox variables, through a `PostSession`
  closure. It leads the feature providers, so a non-optional `preStart` abort mints nothing;
  a `preStart`-only config keeps the `syscall.Exec` fast path, any enabled `postEnd` forces
  the supervised path. This is the launcher-side session-lifecycle dual of the in-sandbox
  `corral hook` enforcer, and **unrelated** to it despite the shared word.

**The `ssh` provider.** Enabling it grants the agent **and** a read-only view of the SSH
*config* (agent forwarding alone gave keys/signing but no `known_hosts`/`config`, breaking
host-key verification and `ProxyJump`/aliases). The design mounts the real files, guarded:

- **Overlay layering** mirrors the always-blocked masks: the mask empties `~/.ssh` with a tmpfs
  applied *last*; the provider re-adds only vetted files *on top* via `Mount.Overlay`
  (emitted after the masks, see the Sandbox section). So even if `$HOME` is bound, keys
  can't leak: the base is empty and keys are never in the overlay set.
- **What's overlaid:** `~/.ssh/config`, every file it `Include`s (resolving `~`,
  relative→`~/.ssh`, globs; recursing with depth/cycle/count caps), and `~/.ssh/known_hosts`
  (all read-only), plus the agent socket (rw; its path may sit under a masked dir, e.g. a
  gpg-agent socket under `~/.gnupg`).
- **Guards:** bind the `EvalSymlinks`-resolved realpath (bwrap can't be tricked into
  following a mount-time symlink); regular files only; and the overlay **never resolves into
  the other masked secret dirs** (`~/.gnupg`, `~/.aws`, `~/.kube`, …); enabling `ssh` must not
  side-door the other masked capabilities. Strict `~/.ssh` containment is relaxed so the common dotfiles
  case (`~/.ssh/config` symlinked into `~/dotfiles`) works; an `Include` surfaces whatever
  readable file it points at (read-only), wherever it lives, **except** the forbidden roots.

**The `kubernetes` provider** (first minter, via `client-go`): mint a short-lived
ServiceAccount token *outside* the sandbox (so exec-credential helpers, oidc/aws/gcloud,
work) and bind a minimal kubeconfig in. Per-session SA names (`corral-<user>-<session>`) +
reliable cleanup. `providers.kubernetes.mode` selects one of two provisioning strategies:

- **`managed`** (default): corral also creates the RoleBindings/ClusterRoleBindings the
  `permissions` list (`permissions[].namespaceSelector`/`clusterWide` × `role`/
  `clusterRole`) describes, so the minting identity needs cluster-scoped RBAC plus
  escalation rights over whatever it binds; includes the immutable-`roleRef`
  delete-then-recreate trick on a role change. RBAC is validated at `Mint()` time, not at
  config load.
- **`preProvisioned`**: an admin binds RBAC to a dedicated namespace once, outside
  corral, via the built-in `system:serviceaccounts:<namespace>` group; corral only
  creates the SA and a per-session, identically-labeled, empty revocation `Secret`
  (`type: Opaque`), then mints the token via `TokenRequest` with a `boundObjectRef` to
  that Secret; deleting either the SA or the Secret on session end invalidates the
  token immediately, layered on top of the normal self-expiry backstop. `permissions` is
  rejected at config load in this mode. corral does not create or delete a
  `Role`, `RoleBinding`, `ClusterRoleBinding`, or `Namespace`; it only attempts a `get`
  of the configured namespace and continues with a warning if that read is forbidden.
  It never lists namespaces cluster-wide. `corral gc` here only lists/reaps labeled SAs
  and Secrets in the one
  configured namespace.

Only the *intent* (`providers.kubernetes.enabled`/`.mode`) persists; tokens live only in
`Contribution.Env`; the audit log records the decision, never the value.

**The `home` provider** (default ON): redirects `$HOME` to a sandbox-private directory
(an empty config path defaults to `~/.cache/corral/home-<hash>`, one per agent config
directory) and symlinks the allowed-under-home host paths into it. Tools that write to
`~`, and the home-relative build caches (npm, go, pip, uv, yarn, pnpm), are isolated
there yet persist across sessions; set `enabled: false` to use the real `$HOME`. It
subsumes the earlier standalone `cache` provider, and unlike the minters it injects no
credential; it shapes the filesystem view.

**Resolved lifecycle rules.**

- *unavailable* (no socket/kubeconfig) → skip safely.
- enabled + available + `Mint()` **errors** → **fail closed** (block launch); set
  `optional: true` to downgrade to skip-with-warning.
- *cleanup* tracked LIFO, fired on exit/signal/panic. Crashed-session GC (orphaned
  SAs/kubeconfigs after SIGKILL) is an explicit **`corral gc`** that **previews and requires
  approval, never deletes without check + confirm**.
- *post-session hooks* (`providers.hooks` postEnd) run in **declaration order** after the
  agent exits and **before** cleanup, warn-only on an unbounded context. The script inherits
  the original host environment, not provider-contributed sandbox variables. It runs after
  any ended session and after an aborted launch once the callback has been registered.

## Egress (out of scope)

`internal/egress` does **not** exist. corral ships with full network access and does not
attempt egress filtering. The design sketch below is kept only so
today's choices don't paint that option into a corner:

If it is ever built, egress routes through a corral-owned filtering proxy (outside the sandbox, so it
can prompt the user). Decisions are **live**, not fixed at launch: HTTPS via `CONNECT` +
plaintext SNI inspection for domain-level allow/deny **without MITM**; an unknown domain
stalls the connection and prompts `allow egress to x.y? [y/N/always]` (`always` persists to
`.corral.local.yml`); the netns is wired so the proxy is the only route out (UDP/443 blocked
to force QUIC→TCP fallback so SNI stays visible); raw-socket/proxy-unaware traffic is blocked
fail-closed. It doubles as the WebFetch/WebSearch audit log.

**Constraint:** keep the launch path from hard-coding "network is fully open" anywhere it
would be costly to undo; net setup stays behind the `SandboxSpec.net` field even though it
is only ever set to `open` today.

## Rewrite-trap checklist

The hard-won bash knowledge that must not be lost in the rewrite; each shipped as a
well-tested module with golden-file coverage:

- ✅ macOS `/private` path normalization + full symlink resolution (symlink-install)
  + the lstat-ancestor walk for realpath-walking tools (kustomize, `EvalSymlinks`). Miss one
  and Seatbelt rules silently fail to match. (`normalizeMacPath` + `metadataAncestors`,
  `internal/sandbox/seatbelt`.)
- ✅ Fail-closed exit-2 + signal handling on **every** hook error path
  (`InstallFailClosedSignals`, `internal/policy/hook.go`).
- ✅ `kubectl create token` equivalent runs *outside* the sandbox (client-go `TokenRequest`
  in the launcher); exec-credential auth plugins registered, live-verify against a real
  cluster (oidc/aws/gcloud).
- ✅ Immutable-`roleRef` delete-then-recreate on role change
  (`applyClusterRoleBinding`/`applyRoleBinding`).
- ✅ SBPL string escaping; bwrap arg quoting: every special char tested (`sbplEscape`,
  `internal/sandbox/seatbelt`).
- ✅ Temp kubeconfig holds a live token; `Contribution.Cleanup` removes it on exit (LIFO);
  SIGKILL orphans are swept by `corral gc`.

## Project layout

```
corral/
  cmd/corral/           # thin main: parse argv, dispatch to internal/cli
  internal/cli/         # command dispatcher + subcommands: run, hook, sync, validate, doctor, gc, update
  internal/cli/report/  # terminal render layer: detail grid, glyphs, color + ASCII fallbacks
  internal/config/      # layered YAML load + merge + validation
  internal/agents/      # agent seam: spec/ (Agent contract + neutral types), claude/ (+ claudecfg/: generate / merge Claude settings.json) + pi/ (per-agent impls), facade registry
  internal/selfupdate/  # launcher-side self-update: release fetch, checksum verify, in-place replace
  internal/sandbox/     # SandboxSpec + bwrap / seatbelt backends; embedded sandbox-permissions.json baseline
  internal/policy/      # hook enforcer: bash parser, secret scan, path-pattern gate, exit-2 fail-closed
  internal/health/      # readiness check result type shared by the sandbox backends, agents, and doctor
  internal/pathutil/    # path containment helpers (AtOrUnder, …) shared by config + sandbox
  internal/audit/       # rotated JSON decision log
  internal/providers/   # provider seam: spec/ (Provider contract + shared helpers), one package per provider (block/ aiignore/ paths/ env/ hooks/ ssh/ docker/ home/ gitlab/ kubernetes/, each owning its Config type), registry/ (canonical ordered table all provider views derive from), facade w/ engine (Resolve/Apply/Cleanup)
  # internal/egress/    # not implemented: sketched filtering proxy + dynamic allowlist + prompt
```

`sandbox-permissions.json` and its schema are embedded baseline files (schema-validated,
OS differences via `archs`).

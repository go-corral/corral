// Package config loads corral's layered YAML configuration — global defaults,
// a committed project file, and a gitignored per-user override — deep-merged,
// later layers winning.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/agents/claude"
	"github.com/go-corral/corral/internal/agents/pi"

	"github.com/go-corral/corral/internal/audit"
	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/providers/aiignore"
	"github.com/go-corral/corral/internal/providers/block"
	"github.com/go-corral/corral/internal/providers/docker"
	"github.com/go-corral/corral/internal/providers/env"
	"github.com/go-corral/corral/internal/providers/gitlab"
	"github.com/go-corral/corral/internal/providers/home"
	"github.com/go-corral/corral/internal/providers/hooks"
	"github.com/go-corral/corral/internal/providers/kubernetes"
	"github.com/go-corral/corral/internal/providers/paths"
	"github.com/go-corral/corral/internal/providers/ssh"
	"github.com/go-corral/corral/internal/sandbox/bwrap"
	"github.com/go-corral/corral/internal/sandbox/seatbelt"
	"github.com/go-corral/corral/internal/selfupdate"
	"gopkg.in/yaml.v3"
)

type Net string

const (
	NetOpen Net = "open"
	// NetNone is reserved but unimplemented; Validate rejects it.
	NetNone Net = "none"
)

// Sandbox holds backend-specific sandbox tuning. Each field is the owning
// backend package's config type; the node for whichever backend isn't running
// is ignored.
type Sandbox struct {
	Seatbelt seatbelt.Config `yaml:"seatbelt"`
	Bwrap    bwrap.Config    `yaml:"bwrap"`
}

func (s Sandbox) Validate() error {
	if err := s.Seatbelt.Validate(); err != nil {
		return err
	}
	return s.Bwrap.Validate()
}

// Config is the fully-merged, validated corral configuration.
type Config struct {
	Net       Net               `yaml:"net"`
	Sandbox   Sandbox           `yaml:"sandbox"`
	Hostname  string            `yaml:"hostname"`
	Agent     string            `yaml:"agent"`
	Agents    Agents            `yaml:"agents"`
	Providers Providers         `yaml:"providers"`
	Policy    Policy            `yaml:"policy"`
	Update    selfupdate.Config `yaml:"update"`
	Profiles  map[string]Config `yaml:"profiles"`
}

func (c *Config) EffectiveAgent() string {
	if c.Agent != "" {
		return c.Agent
	}
	return agents.Default
}

func (c *Config) agent() agents.Agent {
	if a, ok := agents.Lookup(c.EffectiveAgent()); ok {
		return a
	}
	a, _ := agents.Lookup(agents.Default)
	return a
}

func (c *Config) agentConfig() agents.AgentConfig {
	switch c.EffectiveAgent() {
	case "pi":
		return c.Agents.Pi
	default:
		return c.Agents.Claude
	}
}

func (c *Config) AgentConfigDir(home string, host map[string]string) string {
	return c.agent().ConfigDir(home, host)
}

func (c *Config) AgentLaunch() agents.Launch {
	return c.agent().Launch()
}

func (c *Config) AgentEnv() map[string]string {
	return c.agentConfig().SandboxEnv()
}

func (c *Config) AgentValidationFields() []agents.BannerField {
	return c.agentConfig().ValidationFields()
}

func (c *Config) AgentConfigPaths() []agents.ConfigPath {
	return c.agent().ConfigPaths()
}

// Agents holds per-agent configuration. Each field is the owning agent package's
// Config type. Adding an agent adds a sibling field here.
type Agents struct {
	Claude claude.Config `yaml:"claude"`
	Pi     pi.Config     `yaml:"pi"`
}

// Providers configures corral's sanitized-capability providers. Each field is
// the owning provider package's Config type — a typed struct, not
// map[string]any, so strict decode rejects a typo'd key. Field order is
// declaration order (apply order, collision attribution, LIFO cleanup).
type Providers struct {
	Block      block.Config      `yaml:"block"`
	AIIgnore   aiignore.Config   `yaml:"aiignore"`
	Paths      paths.Config      `yaml:"paths"`
	Env        env.Config        `yaml:"env"`
	Hooks      hooks.Config      `yaml:"hooks"`
	Docker     docker.Config     `yaml:"docker"`
	SSH        ssh.Config        `yaml:"ssh"`
	Home       home.Config       `yaml:"home"`
	Kubernetes kubernetes.Config `yaml:"kubernetes"`
	Gitlab     gitlab.Config     `yaml:"gitlab"`
}

// Policy tunes the policy engine (the hook-side gates).
type Policy struct {
	SecretScan   SecretScan   `yaml:"secretScan"`
	Audit        audit.Config `yaml:"audit"`
	IncidentHint string       `yaml:"incidentHint"`
}

// SecretScan tunes the content secret scanner.
type SecretScan struct {
	EntropyThreshold float64  `yaml:"entropyThreshold"`
	SkipPaths        []string `yaml:"skipPaths"`
}

// coreReservedEnvNames are the env vars corral's own machinery controls. env.set
// may not name them, so a config typo can never unset the sandbox marker, retarget
// the pinned global-config path, audit-log path or agent id, or redirect the corral binary.
// CORRAL_DISABLE_HOOKS is reserved so a repo-shipped .corral.yml can't plant an
// enforcement-off value. CORRAL_PRESENCE_ACK is deliberately not reserved: it
// only silences a warning, so there is nothing to forge.
var coreReservedEnvNames = []string{
	"CORRAL_SANDBOX",
	"CORRAL_GLOBAL_CONFIG",
	"CORRAL_AUDIT_PATH",
	"CORRAL_AGENT",
	"CORRAL_BIN",
	"CORRAL_PROVIDER_NOTES",
	"CORRAL_BACKEND_NOTES",
	"CORRAL_DISABLE_HOOKS",
}

var reservedEnvNames = buildReservedEnvNames()

func buildReservedEnvNames() map[string]bool {
	m := make(map[string]bool, len(coreReservedEnvNames))
	for _, n := range coreReservedEnvNames {
		m[n] = true
	}
	for _, n := range agents.AllReservedEnv() {
		m[n] = true
	}
	return m
}

// AlwaysBlockedPaths are blocked regardless of config. Config can only add to
// this set, never remove from it, so a config typo cannot unblock a secret
// directory. An entry must meet the criterion in docs/explanation/threat-model.md.
var AlwaysBlockedPaths = []string{
	"~/.ssh", "~/.gnupg", "~/.aws", "~/.kube", "~/.config/gcloud", "~/.azure",
}

const defaultsYAML = `
net: open
hostname: corral
# Backend-specific sandbox tuning, keyed by backend; the node for whichever backend isn't
# running is ignored. seatbelt (macOS): mach.lookup defaults to "strict" — deny-default
# mach-lookup, re-allowing only the curated allowlist plus mach.allow (a trailing "*" in an
# allow entry is a name prefix). Set "open" to fall back to allow-default mach-lookup with
# just the scoped sandbox-escape denies. bwrap (Linux) has no knobs yet.
sandbox:
  seatbelt:
    mach:
      lookup: strict
      allow: []
  bwrap: {}
# Which coding agent corral sandboxes ("claude" or "pi"); see docs/reference/agents.md.
agent: claude
# Per-agent configuration. claude.ai account connectors (Context7/Atlassian/Zoom,
# auto-injected by a Claude subscription login) are OFF inside the sandbox by default —
# deny-by-default, like the rest of corral. Set true to let the sandboxed Claude load them.
# The telemetry/errorReporting/feedbackSurvey knobs disable Claude Code's "phone-home"
# traffic by default (they set DISABLE_TELEMETRY=1 / DISABLE_ERROR_REPORTING=1 /
# CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY=1); set any true to allow it. attributionHeader defaults
# true (Claude's own default); set false to drop the system-prompt attribution block
# (CLAUDE_CODE_ATTRIBUTION_HEADER=0) — useful for a local LLM / LLM gateway. agentView
# defaults false (CLAUDE_CODE_DISABLE_AGENT_VIEW=1): its background sessions cannot outlive
# the sandbox.
agents:
  claude:
    claudeaiConnectors: false
    telemetry: false
    errorReporting: false
    feedbackSurvey: false
    attributionHeader: true
    agentView: false
providers:
  # --- built-in providers: always active, applied before the feature providers ---
  # Paths the sandbox masks and the hook denies, split by kind: directories are masked
  # recursively; files are masked by a read-only stub (bwrap) / literal deny (Seatbelt).
  # Both ADD to the always-blocked paths (~/.ssh, ~/.gnupg, cloud/kube credential
  # dirs — the full list lives in code); neither can weaken them.
  block: {directories: [], files: []}
  # Repo AI-exclusion sources: filenames corral walks up the repo tree for (.aiignore /
  # .aiexclude are built in; config ADDS to this list). Each file's patterns become hook
  # denies + launcher FS masks. Adding a general-purpose file like .gitignore is allowed but
  # over-approximates — corral drops "!" negations, so it may mask more than the file intends
  # (the launcher warns when a source carries negations); only the native defaults are
  # self-protected from the agent's own edits.
  aiignore: {sources: [.aiignore, .aiexclude]}
  # Extra host paths granted into the sandbox (rw / read-only).
  paths: {rw: [], ro: []}
  env:
    # SSH_AUTH_SOCK is intentionally not here: the ssh provider injects it only when it
    # also forwards the matching socket. GPG_TTY must be added explicitly when needed.
    # CLAUDE_CONFIG_DIR / PI_CODING_AGENT_DIR / PI_CODING_AGENT_SESSION_DIR are agent
    # config-dir relocators: forwarded so the agent inside the sandbox uses the same dir corral
    # resolved, bound rw, and write-protects. The pi pair is also reserved (reservedEnvNames) so
    # env.set cannot relocate pi's config/sessions out from under that protection.
    passthrough: [TERM, COLORTERM, NO_COLOR, EDITOR, VISUAL, PAGER, TMPDIR, LANG, CLAUDE_CONFIG_DIR, PI_CODING_AGENT_DIR, PI_CODING_AGENT_SESSION_DIR]
    # set fixes vars to literal values inside the sandbox (a name may be in passthrough OR
    # set, not both). Overriding a value corral already sets warns + prompts at startup.
    # set: [{name: FOO, value: bar}]
  # --- feature providers ---
  # Session hooks are host-side executables around the agent lifecycle. preStart runs
  # before the agent and can abort the launch; postEnd runs after the session or a later
  # launch abort and only warns on failure. They are unrelated to the corral hook enforcer.
  # Keys run in lexical order. exec is invoked directly in the workdir with args appended;
  # optional applies to preStart, and enabled:false disables a lower-layer entry. No entries
  # are defaulted because a map default would merge into every user config.
  # hooks:
  #   preStart:
  #     10-update-datasources: {exec: ./scripts/update-datasources.sh, args: [--fast]}
  #   postEnd:
  #     session-report: {exec: ./scripts/session-report.sh}
  # Socket-brokers / feature providers: enabled turns the whole feature on.
  docker:
    enabled: false
  ssh:
    enabled: false
  # Private $HOME: default ON. Redirects HOME to a sandbox-private dir (path below; empty =
  # ~/.cache/corral/home-<hash>, one per agent config dir) and symlinks the allowed-under-home
  # host paths into it, so tools that write to ~ (and home-relative caches: npm, go, pip, uv,
  # yarn, pnpm) are isolated there and persist across sessions. Set enabled:false to use the
  # real $HOME.
  home:
    enabled: true
    path: ""
  # Credential-minter (M5c). Per-session ServiceAccount + RBAC + a short-lived token,
  # all minted OUTSIDE the sandbox; a minimal kubeconfig is bound in. permissions is left
  # unset here on purpose (the in-code default is one cluster-wide bind to the view
  # ClusterRole); a YAML default would force-union into any user list (append-unique merge).
  # mode (managed | preProvisioned) and serviceAccountNamespace are likewise unset here:
  # both have in-code defaults (managed, corral), and a YAML default for the namespace
  # would make the key never-empty — preProvisioned mode requires it explicitly.
  kubernetes:
    enabled: false
    tokenLifetime: 8h
  # Credential-minter: a scoped, short-lived GitLab access token (personal or project),
  # minted OUTSIDE the sandbox and injected as env. See the gitlab docs for type/scopes/role.
  gitlab:
    enabled: false
policy:
  secretScan:
    entropyThreshold: 0
    skipPaths: []
  # The audit log is always on — tool-call decisions are unconditionally logged, so there
  # is no enable switch. Rotation is TIME-based: the live log is rolled to a timestamped
  # backup once it is older than rotateInterval, backups older than retention are pruned,
  # and each backup is gzip'd. Durations accept d/w/mo/y on top of Go's h/m/s.
  audit:
    path: ""
    rotateInterval: 1w
    retention: 6mo
    gzip: true
  # Appended to every secret-detection deny/withhold message as the incident next
  # step. Empty uses the built-in wording (rotate/revoke + inform IT/Security); set
  # an org-specific runbook/contact string to override. Never contains a secret.
  incidentHint: ""
# Self-update. checkOnStart prints a throttled (once/day, cached under ~/.cache/corral),
# best-effort "newer version available" notice on 'corral run'; set false to disable all
# launch-time version checks. The release source is fixed at compile time (the module path)
# and intentionally not configurable.
update:
  checkOnStart: true
`

// LoadOptions configures Load.
type LoadOptions struct {
	Home       string
	GlobalPath string
	ProjectDir string
	Profiles   []string
}

// Source records a configuration layer that contributed to the merged result.
type Source struct {
	Kind string
	Path string
	// SHA256 is the hex content hash of the exact bytes parsed for a file layer,
	// computed at read time so it is TOCTOU-free. The repo-config trust gate keys
	// approval on this hash.
	SHA256 string
}

// Load resolves the standard layer paths, merges them, applies the selected
// profiles, and validates. Returns the merged config, the contributing sources,
// and an error.
func Load(opt LoadOptions) (*Config, []Source, error) {
	home := opt.Home
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return nil, nil, fmt.Errorf("resolve home: %w", err)
		}
		home = h
	}
	globalPath := opt.GlobalPath
	if globalPath == "" {
		globalPath = defaultGlobalPath(home)
	}
	projectDir := opt.ProjectDir
	if projectDir == "" {
		if wd, err := os.Getwd(); err == nil {
			projectDir = wd
		}
	}

	merged, err := parseYAMLMap([]byte(defaultsYAML))
	if err != nil {
		return nil, nil, fmt.Errorf("internal: bad default config: %w", err)
	}
	sources := []Source{{Kind: "defaults"}}

	_, projFile, localFile := findProjectFiles(projectDir)
	fileLayers := []struct {
		kind, path string
	}{
		{"global", globalPath},
		{"project", projFile},
		{"local", localFile},
	}
	var layers []parsedLayer
	for _, fl := range fileLayers {
		if fl.path == "" {
			continue
		}
		data, err := os.ReadFile(fl.path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, nil, fmt.Errorf("read %s config %s: %w", fl.kind, fl.path, err)
		}
		m, err := parseYAMLMap(data)
		if err != nil {
			return nil, nil, fmt.Errorf("parse %s config %s: %w", fl.kind, fl.path, err)
		}
		layers = append(layers, parsedLayer{path: fl.path, m: m})
		merged = mergeMap(merged, m)
		sum := sha256.Sum256(data)
		sources = append(sources, Source{Kind: fl.kind, Path: fl.path, SHA256: hex.EncodeToString(sum[:])})
	}

	if _, err := decodeStrict(merged); err != nil {
		return nil, nil, fmt.Errorf("%w%s", err, migrationHint(layers))
	}

	if len(opt.Profiles) > 0 {
		seen := make(map[string]bool, len(opt.Profiles))
		for _, name := range opt.Profiles {
			if seen[name] {
				return nil, nil, fmt.Errorf("profile %q selected more than once", name)
			}
			seen[name] = true
		}
		profiles, _ := merged["profiles"].(map[string]any)
		base := cloneMap(merged)
		delete(base, "profiles")
		for _, name := range opt.Profiles {
			prof, ok := profiles[name].(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("profile %q not found", name)
			}
			base = mergeMap(base, prof)
			sources = append(sources, Source{Kind: "profile", Path: name})
		}
		merged = base
	} else {
		delete(merged, "profiles")
	}

	cfg, err := decodeStrict(merged)
	if err != nil {
		return nil, nil, fmt.Errorf("%w%s", err, migrationHint(layers))
	}
	cfg.expandPaths(home)
	if err := cfg.Validate(home); err != nil {
		return nil, nil, err
	}
	return cfg, sources, nil
}

// Validate performs semantic validation beyond the schema, after path expansion
// — a still-relative path is a misconfiguration rejected here, since unexpanded
// it would silently fail to block or mount anything (fail-open).
func (c *Config) Validate(home string) error {
	switch c.Net {
	case NetOpen, "":
	case NetNone:
		return fmt.Errorf("net: none is not implemented (egress filtering is out of scope); only net: open is supported")
	default:
		return fmt.Errorf("net: %q is not one of open|none", c.Net)
	}

	if err := c.Sandbox.Validate(); err != nil {
		return err
	}

	if c.Agent != "" && !slices.Contains(agents.Known(), c.Agent) {
		return fmt.Errorf("agent: %q is not a supported agent (%s)", c.Agent, strings.Join(agents.Known(), "|"))
	}

	floor := make([]string, len(AlwaysBlockedPaths))
	for i, f := range AlwaysBlockedPaths {
		floor[i] = filepath.Clean(expandTilde(f, home))
	}

	if err := c.Providers.Block.Validate(floor); err != nil {
		return err
	}
	if err := c.Providers.AIIgnore.Validate(); err != nil {
		return err
	}
	if err := c.Providers.Paths.Validate(floor); err != nil {
		return err
	}
	if err := c.Providers.Env.Validate(coreReservedEnvNames, reservedEnvNames); err != nil {
		return err
	}
	if err := c.Providers.Hooks.Validate(); err != nil {
		return err
	}

	for _, p := range c.Policy.SecretScan.SkipPaths {
		if err := pathutil.RequireAbs("policy.secretScan.skipPaths", p); err != nil {
			return err
		}
	}
	if c.Policy.SecretScan.EntropyThreshold < 0 {
		return fmt.Errorf("policy.secretScan.entropyThreshold must be >= 0, got %v", c.Policy.SecretScan.EntropyThreshold)
	}
	if p := c.Policy.Audit.Path; p != "" {
		if err := pathutil.RequireAbs("policy.audit.path", p); err != nil {
			return err
		}
	}
	if err := c.Policy.Audit.Validate(); err != nil {
		return err
	}

	if err := c.Providers.Home.Validate(); err != nil {
		return err
	}

	if err := c.Providers.Kubernetes.Validate(); err != nil {
		return err
	}
	if err := c.Providers.Gitlab.Validate(); err != nil {
		return err
	}

	return nil
}

func expandDedup(home string, lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, list := range lists {
		for _, p := range list {
			e := expandTilde(p, home)
			if e != "" && !seen[e] {
				seen[e] = true
				out = append(out, e)
			}
		}
	}
	return out
}

// ConfigBlockedDirs returns config-added blocked directories, ~-expanded and
// deduped. The always-blocked set is excluded (DefaultSpec bakes it in).
func (c *Config) ConfigBlockedDirs(home string) []string {
	return expandDedup(home, c.Providers.Block.Directories)
}

// ConfigBlockedFiles returns config block.files, ~-expanded and deduped.
func (c *Config) ConfigBlockedFiles(home string) []string {
	return expandDedup(home, c.Providers.Block.Files)
}

// EffectiveBlockedPaths returns every path the policy denies: always-blocked,
// blocked dirs, and blocked files. The single source of truth for the hook deny
// roots and for diagnostics.
func (c *Config) EffectiveBlockedPaths(home string) []string {
	return expandDedup(home, AlwaysBlockedPaths, c.Providers.Block.Directories, c.Providers.Block.Files)
}

// AlwaysBlockedExpanded returns the always-blocked secret directories,
// ~-expanded. Exposed so diagnostics can mark them distinctly from config blocks.
func AlwaysBlockedExpanded(home string) []string {
	out := make([]string, 0, len(AlwaysBlockedPaths))
	for _, p := range AlwaysBlockedPaths {
		out = append(out, expandTilde(p, home))
	}
	return out
}

// AlwaysBlockedMaskPaths returns the always-blocked paths for the sandbox FS
// mask: the ~-expanded set plus the resolved real path of any entry that is
// itself a host symlink. A dotfiles-managed ~/.ssh (-> ~/dotfiles/ssh) masked at
// its lexical name only would be re-exposed under its real name by an unrelated
// grant. When no entry is a symlink the resolved form dedups away, leaving the
// emitted argv/profile unchanged.
func AlwaysBlockedMaskPaths(home string) []string {
	floor := AlwaysBlockedExpanded(home)
	out := make([]string, 0, len(floor))
	seen := make(map[string]bool, len(floor))
	for _, p := range floor {
		for _, q := range []string{p, pathutil.Resolve(p)} {
			if !seen[q] {
				seen[q] = true
				out = append(out, q)
			}
		}
	}
	return out
}

func (c *Config) expandPaths(home string) {
	exp := func(ss []string) {
		for i := range ss {
			ss[i] = filepath.Clean(expandTilde(ss[i], home))
		}
	}
	exp(c.Providers.Paths.RW)
	exp(c.Providers.Paths.RO)
	exp(c.Providers.Block.Directories)
	exp(c.Providers.Block.Files)
	exp(c.Policy.SecretScan.SkipPaths)
	if c.Policy.Audit.Path != "" {
		c.Policy.Audit.Path = filepath.Clean(expandTilde(c.Policy.Audit.Path, home))
	}
	if c.Providers.Home.Path != "" {
		c.Providers.Home.Path = filepath.Clean(expandTilde(c.Providers.Home.Path, home))
	}
	for _, m := range []map[string]hooks.Hook{c.Providers.Hooks.PreStart, c.Providers.Hooks.PostEnd} {
		for k, h := range m {
			if h.Exec != "" {
				h.Exec = expandTilde(h.Exec, home)
				m[k] = h
			}
		}
	}
}

func defaultGlobalPath(home string) string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "corral", "config.yml")
	}
	return filepath.Join(home, ".config", "corral", "config.yml")
}

func findProjectFiles(start string) (dir, projFile, localFile string) {
	if start == "" {
		return "", "", ""
	}
	cur := start
	for {
		proj := filepath.Join(cur, ".corral.yml")
		local := filepath.Join(cur, ".corral.local.yml")
		hasProj := fileExists(proj)
		hasLocal := fileExists(local)
		if hasProj || hasLocal {
			if !hasProj {
				proj = ""
			}
			if !hasLocal {
				local = ""
			}
			return cur, proj, local
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", "", ""
		}
		cur = parent
	}
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

func expandTilde(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home, p[2:])
	}
	return p
}

func parseYAMLMap(data []byte) (map[string]any, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// mergeMap deep-merges over onto base: nested maps recurse, lists merge
// append-unique, scalars are replaced. base is not mutated. Append-unique is
// deliberate: a higher layer can extend a list but never drop what a lower
// layer set, so the built-in defaults always apply.
func mergeMap(base, over map[string]any) map[string]any {
	out := cloneMap(base)
	for k, ov := range over {
		if bv, ok := out[k]; ok {
			if bm, ok1 := bv.(map[string]any); ok1 {
				if om, ok2 := ov.(map[string]any); ok2 {
					out[k] = mergeMap(bm, om)
					continue
				}
			}
			if bl, ok1 := bv.([]any); ok1 {
				if ol, ok2 := ov.([]any); ok2 {
					out[k] = unionAny(bl, ol)
					continue
				}
			}
		}
		out[k] = ov
	}
	return out
}

// unionAny concatenates a then b, dropping duplicates by type+value, preserving
// first-seen order. Config lists are homogeneous strings, so this is the
// append-unique merge.
func unionAny(a, b []any) []any {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]any, 0, len(a)+len(b))
	for _, list := range [][]any{a, b} {
		for _, it := range list {
			key := fmt.Sprintf("%T\x00%v", it, it)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, it)
		}
	}
	return out
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch t := v.(type) {
		case map[string]any:
			out[k] = cloneMap(t)
		case []any:
			out[k] = append([]any(nil), t...)
		default:
			out[k] = v
		}
	}
	return out
}

var movedKeys = []struct{ old, new string }{
	{"paths", "providers.paths"},
	{"block", "providers.block"},
	{"aiignore", "providers.aiignore"},
	{"env", "providers.env"},
	{"claudeaiConnectors", "agents.claude.claudeaiConnectors"},
}

type parsedLayer struct {
	path string
	m    map[string]any
}

func movedKeyRenames(m map[string]any) []string {
	var out []string
	for _, k := range movedKeys {
		if _, ok := m[k.old]; ok {
			out = append(out, k.old+" → "+k.new)
		}
	}
	if profiles, ok := m["profiles"].(map[string]any); ok {
		names := make([]string, 0, len(profiles))
		for name := range profiles {
			names = append(names, name)
		}
		slices.Sort(names)
		for _, name := range names {
			pm, ok := profiles[name].(map[string]any)
			if !ok {
				continue
			}
			for _, k := range movedKeys {
				if _, ok := pm[k.old]; ok {
					out = append(out, fmt.Sprintf("profiles.%s.%s → profiles.%s.%s", name, k.old, name, k.new))
				}
			}
		}
	}
	return out
}

// migrationHint builds the guidance appended to a strict-decode error when a
// config file uses moved keys. Empty when no moved key is present.
func migrationHint(layers []parsedLayer) string {
	var b strings.Builder
	for _, l := range layers {
		if renames := movedKeyRenames(l.m); len(renames) > 0 {
			fmt.Fprintf(&b, "\nhint: %s: move %s", l.path, strings.Join(renames, ", "))
		}
	}
	if b.Len() > 0 {
		b.WriteString("\nhint: the moved keys keep their fields — only the nesting changed. " +
			"The yaml line numbers above refer to the merged config, not the files named here. " +
			"Update the config together with the corral binary (a stale schema also fail-closes the hook); " +
			"see docs/reference/config.md")
	}
	return b.String()
}

// decodeStrict marshals the merged map and decodes it into a Config with unknown
// fields rejected, so a typo'd key is caught rather than silently ignored.
func decodeStrict(m map[string]any) (*Config, error) {
	b, err := yaml.Marshal(m)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}
	return &cfg, nil
}

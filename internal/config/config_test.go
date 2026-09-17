package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-corral/corral/internal/providers/env"
	"github.com/go-corral/corral/internal/providers/kubernetes"
)

// loadFrom is a test helper: write the given layer contents (empty = absent) and
// load with everything pointed at temp paths so the real ~/.config is untouched.
func loadFrom(t *testing.T, home, global, project, local string, profiles ...string) (*Config, []Source, error) {
	t.Helper()
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "global.yml")
	projDir := filepath.Join(dir, "proj")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if global != "" {
		writeFile(t, globalPath, global)
	}
	if project != "" {
		writeFile(t, filepath.Join(projDir, ".corral.yml"), project)
	}
	if local != "" {
		writeFile(t, filepath.Join(projDir, ".corral.local.yml"), local)
	}
	if home == "" {
		home = dir
	}
	return Load(LoadOptions{Home: home, GlobalPath: globalPath, ProjectDir: projDir, Profiles: profiles})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadDefaults(t *testing.T) {
	cfg, _, err := loadFrom(t, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Net != NetOpen {
		t.Errorf("default net = %q, want open", cfg.Net)
	}
	if cfg.Hostname != "corral" {
		t.Errorf("default hostname = %q", cfg.Hostname)
	}
	if !containsStr(cfg.Providers.Env.Passthrough, "TERM") {
		t.Errorf("default passthrough missing TERM: %v", cfg.Providers.Env.Passthrough)
	}
}

func TestAlwaysBlockedPathsEnforced(t *testing.T) {
	home := "/home/u"
	cfg, _, err := loadFrom(t, home, "", "providers: {block: {directories: [/data/secrets]}}", "")
	if err != nil {
		t.Fatal(err)
	}
	eff := cfg.EffectiveBlockedPaths(home)
	for _, must := range []string{home + "/.ssh", home + "/.gnupg", home + "/.aws"} {
		if !containsStr(eff, must) {
			t.Errorf("always-blocked path %q missing from %v", must, eff)
		}
	}
	if !containsStr(eff, "/data/secrets") {
		t.Errorf("config blocked path not added: %v", eff)
	}
}

func TestAlwaysBlockedDedupAndExpansion(t *testing.T) {
	home := "/home/alice"
	// Config replicates floor paths in mixed notation (tilde + expanded).
	cfg, _, err := loadFrom(t, home, "", "providers: {block: {directories: [~/.ssh, /home/alice/.gnupg]}}", "")
	if err != nil {
		t.Fatal(err)
	}
	eff := cfg.EffectiveBlockedPaths(home)
	if len(eff) != 6 {
		t.Errorf("expected 6 deduped paths (always-blocked set only), got %d: %v", len(eff), eff)
	}
}

func TestScalarOverrideAndListMerge(t *testing.T) {
	home := "/home/u"
	global := "hostname: global-host\nproviders:\n  paths:\n    ro: [/a, /b]\n"
	project := "hostname: proj-host\n"
	local := "providers:\n  paths:\n    ro: [/c, /a]\n" // /a repeated — must de-dupe
	cfg, _, err := loadFrom(t, home, global, project, local)
	if err != nil {
		t.Fatal(err)
	}
	// Scalars: the later layer wins.
	if cfg.Hostname != "proj-host" {
		t.Errorf("hostname = %q, want proj-host (project overrides global)", cfg.Hostname)
	}
	// Lists: append-unique across layers (base order first, new entries appended,
	// duplicates dropped). paths.ro defaults to [], so this is clean.
	if strings.Join(cfg.Providers.Paths.RO, ",") != "/a,/b,/c" {
		t.Errorf("paths.ro = %v, want [/a /b /c] (append-unique merge)", cfg.Providers.Paths.RO)
	}
}

func TestEnvPassthroughAppendUnique(t *testing.T) {
	home := "/home/u"
	global := "providers:\n  env:\n    passthrough: [FOO_GLOBAL]\n"
	local := "providers:\n  env:\n    passthrough: [BAR_LOCAL, FOO_GLOBAL]\n" // FOO_GLOBAL repeated
	cfg, _, err := loadFrom(t, home, global, "", local)
	if err != nil {
		t.Fatal(err)
	}
	// Both layers' vars are present (append-unique union).
	if !containsStr(cfg.Providers.Env.Passthrough, "FOO_GLOBAL") || !containsStr(cfg.Providers.Env.Passthrough, "BAR_LOCAL") {
		t.Errorf("passthrough should union all layers: %v", cfg.Providers.Env.Passthrough)
	}
	// The built-in defaults still apply (additive — defaults are never dropped).
	if !containsStr(cfg.Providers.Env.Passthrough, "TERM") {
		t.Errorf("default passthrough TERM must persist under append-unique merge: %v", cfg.Providers.Env.Passthrough)
	}
	// De-duplicated: FOO_GLOBAL appears once despite being in two layers.
	n := 0
	for _, p := range cfg.Providers.Env.Passthrough {
		if p == "FOO_GLOBAL" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("append-unique must de-dupe FOO_GLOBAL, got %d copies: %v", n, cfg.Providers.Env.Passthrough)
	}
}

func TestEnvPassthroughNameValidation(t *testing.T) {
	// Names that cannot be real env vars are rejected at load time (else they would
	// silently never match and never forward).
	bad := []string{
		"providers:\n  env:\n    passthrough: [\"MY VAR\"]\n", // embedded space
		"providers:\n  env:\n    passthrough: [AWS_*]\n",      // wildcard
		"providers:\n  env:\n    passthrough: [\"1ABC\"]\n",   // leading digit
		"providers:\n  env:\n    passthrough: [\"\"]\n",       // empty
	}
	for _, g := range bad {
		if _, _, err := loadFrom(t, "/home/u", g, "", ""); err == nil {
			t.Errorf("expected validation error for invalid passthrough name in %q", g)
		}
	}
	// A valid name (and the digits-after-first case) passes.
	if _, _, err := loadFrom(t, "/home/u", "providers:\n  env:\n    passthrough: [MY_VAR2]\n", "", ""); err != nil {
		t.Errorf("valid passthrough name rejected: %v", err)
	}
}

func TestEnvSetDecode(t *testing.T) {
	cfg, _, err := loadFrom(t, "/home/u", "providers:\n  env:\n    set:\n      - {name: FOO, value: bar}\n      - {name: BAZ, value: qux}\n", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers.Env.Set) != 2 {
		t.Fatalf("env.set should decode 2 entries, got %d: %v", len(cfg.Providers.Env.Set), cfg.Providers.Env.Set)
	}
	if cfg.Providers.Env.Set[0] != (env.Var{Name: "FOO", Value: "bar"}) || cfg.Providers.Env.Set[1] != (env.Var{Name: "BAZ", Value: "qux"}) {
		t.Errorf("env.set decoded wrong: %+v", cfg.Providers.Env.Set)
	}
}

func TestEnvSetNameValidation(t *testing.T) {
	bad := []string{
		"providers:\n  env:\n    set:\n      - {name: \"MY VAR\", value: x}\n", // embedded space
		"providers:\n  env:\n    set:\n      - {name: \"1ABC\", value: x}\n",   // leading digit
		"providers:\n  env:\n    set:\n      - {name: \"\", value: x}\n",       // empty
	}
	for _, g := range bad {
		if _, _, err := loadFrom(t, "/home/u", g, "", ""); err == nil {
			t.Errorf("expected validation error for invalid env.set name in %q", g)
		}
	}
	if _, _, err := loadFrom(t, "/home/u", "providers:\n  env:\n    set:\n      - {name: MY_VAR2, value: x}\n", "", ""); err != nil {
		t.Errorf("valid env.set name rejected: %v", err)
	}
}

func TestEnvSetReservedRejected(t *testing.T) {
	// corral-controlled vars must not be settable, so a config typo can never unset the
	// sandbox marker or flip the connector kill switch.
	for _, name := range []string{"CORRAL_SANDBOX", "CORRAL_GLOBAL_CONFIG", "CORRAL_PROVIDER_NOTES", "CORRAL_BACKEND_NOTES", "ENABLE_CLAUDEAI_MCP_SERVERS"} {
		g := "providers:\n  env:\n    set:\n      - {name: " + name + ", value: x}\n"
		if _, _, err := loadFrom(t, "/home/u", g, "", ""); err == nil {
			t.Errorf("expected reserved env.set name %q to be rejected", name)
		}
	}
}

func TestEnvSetPassthroughConflict(t *testing.T) {
	// A name may be forwarded or set, never both.
	g := "providers:\n  env:\n    passthrough: [MY_VAR]\n    set:\n      - {name: MY_VAR, value: x}\n"
	if _, _, err := loadFrom(t, "/home/u", g, "", ""); err == nil {
		t.Error("expected conflict error when a name is in both env.passthrough and env.set")
	}
	// Conflict with a default passthrough name (TERM) is caught too — the default list is
	// always merged in.
	g2 := "providers:\n  env:\n    set:\n      - {name: TERM, value: x}\n"
	if _, _, err := loadFrom(t, "/home/u", g2, "", ""); err == nil {
		t.Error("expected conflict error against the default passthrough (TERM)")
	}
}

func TestEnvSetDuplicateRejected(t *testing.T) {
	// Same name twice in one layer.
	g := "providers:\n  env:\n    set:\n      - {name: FOO, value: a}\n      - {name: FOO, value: b}\n"
	if _, _, err := loadFrom(t, "/home/u", g, "", ""); err == nil {
		t.Error("expected duplicate env.set name to be rejected")
	}
	// Same name, conflicting value across layers: unionAny keeps both entries → duplicate.
	global := "providers:\n  env:\n    set:\n      - {name: FOO, value: a}\n"
	local := "providers:\n  env:\n    set:\n      - {name: FOO, value: b}\n"
	if _, _, err := loadFrom(t, "/home/u", global, "", local); err == nil {
		t.Error("expected conflicting same-name env.set values across layers to be rejected")
	}
}

func TestEnvSetLayeredMerge(t *testing.T) {
	home := "/home/u"
	// Identical entry in two layers collapses to one (no duplicate error); a second layer
	// adds a new entry.
	global := "providers:\n  env:\n    set:\n      - {name: FOO, value: bar}\n"
	local := "providers:\n  env:\n    set:\n      - {name: FOO, value: bar}\n      - {name: BAZ, value: qux}\n"
	cfg, _, err := loadFrom(t, home, global, "", local)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers.Env.Set) != 2 {
		t.Fatalf("identical entry should collapse and the new one append: got %v", cfg.Providers.Env.Set)
	}
	var foo, baz int
	for _, e := range cfg.Providers.Env.Set {
		switch e.Name {
		case "FOO":
			foo++
		case "BAZ":
			baz++
		}
	}
	if foo != 1 || baz != 1 {
		t.Errorf("merged env.set should be FOO=1,BAZ=1, got FOO=%d,BAZ=%d: %v", foo, baz, cfg.Providers.Env.Set)
	}
}

func TestProfileCanAddEnvSet(t *testing.T) {
	home := "/home/u"
	global := "profiles:\n  stub:\n    providers:\n      env:\n        set:\n          - {name: API_URL, value: http://stub}\n"
	cfg, _, err := loadFrom(t, home, global, "", "", "stub")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers.Env.Set) != 1 || cfg.Providers.Env.Set[0] != (env.Var{Name: "API_URL", Value: "http://stub"}) {
		t.Errorf("profile should add the env.set entry: %v", cfg.Providers.Env.Set)
	}
}

func TestClaudeaiConnectorsDefaultsOff(t *testing.T) {
	cfg, _, err := loadFrom(t, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agents.Claude.ClaudeaiConnectors {
		t.Error("claude.ai connectors must default to false (deny-by-default)")
	}
}

func TestClaudeaiConnectorsOptIn(t *testing.T) {
	cfg, _, err := loadFrom(t, "/home/u", "agents:\n  claude:\n    claudeaiConnectors: true", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Agents.Claude.ClaudeaiConnectors {
		t.Error("agents.claude.claudeaiConnectors: true should enable connectors")
	}
}

// The phone-home knobs default to the hardened (disabled) value; attributionHeader defaults on
// (Claude's own default). AgentEnv must mirror the config, so the sandbox sets the right kill
// switches: hardened defaults set the three DISABLE_* vars and omit CLAUDE_CODE_ATTRIBUTION_HEADER.
func TestClaudePrivacyDefaults(t *testing.T) {
	cfg, _, err := loadFrom(t, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Agents.Claude
	if c.Telemetry || c.ErrorReporting || c.FeedbackSurvey {
		t.Errorf("phone-home knobs must default false (hardened), got telemetry=%v errorReporting=%v feedbackSurvey=%v",
			c.Telemetry, c.ErrorReporting, c.FeedbackSurvey)
	}
	if !c.AttributionHeader {
		t.Error("attributionHeader must default true (Claude's own default)")
	}
	env := cfg.AgentEnv()
	for _, name := range []string{"DISABLE_TELEMETRY", "DISABLE_ERROR_REPORTING", "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY"} {
		if env[name] != "1" {
			t.Errorf("AgentEnv must carry the hardened phone-home defaults, got %+v", env)
		}
	}
	if _, ok := env["CLAUDE_CODE_ATTRIBUTION_HEADER"]; ok {
		t.Error("AgentEnv must omit CLAUDE_CODE_ATTRIBUTION_HEADER for the true attributionHeader default")
	}
}

func TestClaudePrivacyOptIn(t *testing.T) {
	cfg, _, err := loadFrom(t, "/home/u",
		"agents:\n  claude:\n    telemetry: true\n    errorReporting: true\n    feedbackSurvey: true\n    attributionHeader: false", "", "")
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Agents.Claude
	if !c.Telemetry || !c.ErrorReporting || !c.FeedbackSurvey {
		t.Errorf("privacy knobs set true must decode true, got %+v", c)
	}
	if c.AttributionHeader {
		t.Error("attributionHeader: false must decode false")
	}
}

// A config that predates the providers clean break (top-level paths/block/env/aiignore)
// fails strict decode with a migration hint that names the offending file and the exact
// renames — the yaml error's line numbers refer to the merged document, so the file
// attribution is what makes the message actionable.
func TestMovedProviderKeysHintNamesFileAndRenames(t *testing.T) {
	old := "block:\n  directories: [/data/secrets]\npaths:\n  rw: [~/work]\n"
	_, _, err := loadFrom(t, "/home/u", "", old, "")
	if err == nil {
		t.Fatal("old-schema top-level keys should fail closed, got nil error")
	}
	for _, want := range []string{
		".corral.yml",                  // the offending file is named (project layer)
		"block \u2192 providers.block", // exact rename, per key
		"paths \u2192 providers.paths", //
		"merged config, not the files", // the line numbers are explained
		"docs/reference/config.md",     // and the config reference is pointed at
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("migration hint missing %q; got:\n%v", want, err)
		}
	}
}

// The same stale keys inside a profile are attributed with their profile path.
func TestMovedProviderKeysHintCoversProfiles(t *testing.T) {
	old := "profiles:\n  k8s:\n    env:\n      passthrough: [FOO]\n"
	_, _, err := loadFrom(t, "/home/u", old, "", "")
	if err == nil {
		t.Fatal("old-schema profile keys should fail closed, got nil error")
	}
	if !strings.Contains(err.Error(), "profiles.k8s.env \u2192 profiles.k8s.providers.env") {
		t.Errorf("hint should name the profile-nested rename; got:\n%v", err)
	}
}

// The local layer gets the same per-file attribution — in practice the likeliest
// stale file (.corral.local.yml is gitignored, so no repo migration commit fixes it).
func TestMovedProviderKeysHintNamesLocalFile(t *testing.T) {
	old := "env:\n  passthrough: [FOO]\n"
	_, _, err := loadFrom(t, "/home/u", "", "", old)
	if err == nil {
		t.Fatal("old-schema local keys should fail closed, got nil error")
	}
	if !strings.Contains(err.Error(), ".corral.local.yml") ||
		!strings.Contains(err.Error(), "env \u2192 providers.env") {
		t.Errorf("hint should name the local file and the rename; got:\n%v", err)
	}
}

// global-file top-level keys are attributed to the global path (not a project file).
func TestMovedProviderKeysHintNamesGlobalFile(t *testing.T) {
	old := "aiignore:\n  sources: [.gitignore]\n"
	_, _, err := loadFrom(t, "/home/u", old, "", "")
	if err == nil {
		t.Fatal("old-schema global keys should fail closed, got nil error")
	}
	if !strings.Contains(err.Error(), "global.yml") ||
		!strings.Contains(err.Error(), "aiignore \u2192 providers.aiignore") {
		t.Errorf("hint should name the global file and the rename; got:\n%v", err)
	}
}

// A plain typo'd key gets the bare strict-decode error — no misleading migration hint.
func TestUnknownKeyGetsNoMigrationHint(t *testing.T) {
	_, _, err := loadFrom(t, "/home/u", "blocky: true\n", "", "")
	if err == nil {
		t.Fatal("unknown key should fail closed, got nil error")
	}
	if strings.Contains(err.Error(), "hint:") {
		t.Errorf("a typo'd key must not get a migration hint; got:\n%v", err)
	}
}

func TestClaudeaiConnectorsLegacyKeyRejected(t *testing.T) {
	_, _, err := loadFrom(t, "/home/u", "claudeaiConnectors: true", "", "")
	if err == nil {
		t.Fatal("legacy top-level claudeaiConnectors should fail closed, got nil error")
	}
	if !strings.Contains(err.Error(), "agents.claude.claudeaiConnectors") {
		t.Errorf("error should name the new key path; got: %v", err)
	}
}

func TestProfileCanOptInExtraEnv(t *testing.T) {
	// With append-unique merge, a profile only needs to list the extra var; it
	// unions with the base passthrough rather than replacing it.
	home := "/home/u"
	global := "profiles:\n  vault:\n    providers:\n      env:\n        passthrough: [ANSIBLE_VAULT_PASSWORD]\n"
	cfg, _, err := loadFrom(t, home, global, "", "", "vault")
	if err != nil {
		t.Fatal(err)
	}
	if !containsStr(cfg.Providers.Env.Passthrough, "ANSIBLE_VAULT_PASSWORD") {
		t.Errorf("profile should add the vault var to passthrough: %v", cfg.Providers.Env.Passthrough)
	}
	if !containsStr(cfg.Providers.Env.Passthrough, "TERM") {
		t.Errorf("profile must extend (not replace) the base passthrough: %v", cfg.Providers.Env.Passthrough)
	}
}

func TestProfileOverlay(t *testing.T) {
	home := "/home/u"
	global := "hostname: base\nprofiles:\n  alt:\n    hostname: alt-host\n"
	cfg, srcs, err := loadFrom(t, home, global, "", "", "alt")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "alt-host" {
		t.Errorf("profile not applied: hostname = %q", cfg.Hostname)
	}
	if cfg.Profiles != nil {
		t.Errorf("effective config should not carry profiles: %v", cfg.Profiles)
	}
	if !hasSource(srcs, "profile") {
		t.Errorf("profile source not recorded: %v", srcs)
	}
}

// Repeating --profile stacks the named profiles as successive merge layers in CLI order:
// a scalar takes the last profile that set it, a list append-uniques across the base and
// every profile, and each profile is recorded as its own source in application order.
func TestProfileStacking(t *testing.T) {
	home := "/home/u"
	global := "hostname: base\n" +
		"providers:\n  paths:\n    ro: [/base]\n" +
		"profiles:\n" +
		"  one:\n    hostname: one-host\n    providers:\n      paths:\n        ro: [/one]\n" +
		"  two:\n    hostname: two-host\n    providers:\n      paths:\n        ro: [/two, /base]\n"
	cfg, srcs, err := loadFrom(t, home, global, "", "", "one", "two")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "two-host" {
		t.Errorf("later profile must win the scalar: hostname = %q, want two-host", cfg.Hostname)
	}
	if got := strings.Join(cfg.Providers.Paths.RO, ","); got != "/base,/one,/two" {
		t.Errorf("paths.ro = %v, want [/base /one /two] (append-unique across base + both profiles)", cfg.Providers.Paths.RO)
	}
	var applied []string
	for _, s := range srcs {
		if s.Kind == "profile" {
			applied = append(applied, s.Path)
		}
	}
	if strings.Join(applied, ",") != "one,two" {
		t.Errorf("profile sources = %v, want [one two] in selection order", applied)
	}
}

// A bad name anywhere in the stack fails the whole load, naming the offender.
func TestProfileStackingUnknownName(t *testing.T) {
	global := "profiles:\n  one:\n    hostname: one-host\n"
	_, _, err := loadFrom(t, "/home/u", global, "", "", "one", "nope")
	if err == nil || !strings.Contains(err.Error(), "not found") || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("expected not-found error naming \"nope\", got %v", err)
	}
}

// Selecting the same profile twice is a mistake, not a no-op: a repeated name means the
// user expected two different overlays.
func TestProfileStackingDuplicate(t *testing.T) {
	global := "profiles:\n  one:\n    hostname: one-host\n"
	_, _, err := loadFrom(t, "/home/u", global, "", "", "one", "one")
	if err == nil || !strings.Contains(err.Error(), "selected more than once") {
		t.Fatalf("expected duplicate-selection error, got %v", err)
	}
}

func TestProfileNotFound(t *testing.T) {
	_, _, err := loadFrom(t, "/home/u", "hostname: base", "", "", "nope")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected profile-not-found error, got %v", err)
	}
}

func TestUnknownKeyFailsClosed(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "hsotname: typo", "", ""); err == nil {
		t.Fatal("expected error on unknown key (fail-closed), got nil")
	}
}

func TestYAMLListAtRootRejected(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "- a\n- b\n", "", ""); err == nil {
		t.Fatal("expected error when a config layer is a YAML list, got nil")
	}
}

func TestNetValidation(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "net: bogus", "", ""); err == nil {
		t.Error("expected error for invalid net value")
	}
	if _, _, err := loadFrom(t, "/home/u", "net: none", "", ""); err == nil {
		t.Error("expected error for net: none (not implemented)")
	}
}

func TestMachValidation(t *testing.T) {
	const base = "sandbox:\n  seatbelt:\n    mach:\n      "
	if _, _, err := loadFrom(t, "/home/u", base+"lookup: strict\n", "", ""); err != nil {
		t.Errorf("mach.lookup: strict should be valid, got %v", err)
	}
	if _, _, err := loadFrom(t, "/home/u", base+"lookup: bogus\n", "", ""); err == nil {
		t.Error("expected error for invalid mach.lookup value")
	}
	if _, _, err := loadFrom(t, "/home/u", base+"allow: [\"com.apple.foo\", \"bad name\"]\n", "", ""); err == nil {
		t.Error("expected error for mach.allow entry with whitespace")
	}
	if _, _, err := loadFrom(t, "/home/u", base+"allow: [\"*\"]\n", "", ""); err == nil {
		t.Error("expected error for bare '*' mach.allow entry (matches every Mach service)")
	}
	if _, _, err := loadFrom(t, "/home/u", base+"allow: [\"com.apple.foo\", \"com.apple.bar.*\"]\n", "", ""); err != nil {
		t.Errorf("valid mach.allow should pass, got %v", err)
	}
}

// The default (no config) mach posture is strict — deny-default mach-lookup. An explicit
// lookup: open is the opt-out.
func TestMachDefaultsToStrict(t *testing.T) {
	cfg, _, err := loadFrom(t, "/home/u", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sandbox.Seatbelt.Mach.Strict() {
		t.Errorf("default mach posture should be strict, got lookup=%q", cfg.Sandbox.Seatbelt.Mach.Lookup)
	}

	open, _, err := loadFrom(t, "/home/u", "sandbox:\n  seatbelt:\n    mach:\n      lookup: open\n", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if open.Sandbox.Seatbelt.Mach.Strict() {
		t.Error("lookup: open must opt out of strict")
	}
}

func TestMountOverlapAlwaysBlockedRejected(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "providers:\n  paths:\n    rw: [~/.ssh]\n", "", ""); err == nil ||
		!strings.Contains(err.Error(), "always-blocked path") {
		t.Fatalf("expected always-blocked overlap rejection, got %v", err)
	}
	// A nested path under a floor dir is also rejected.
	if _, _, err := loadFrom(t, "/home/u", "providers:\n  paths:\n    ro: [~/.ssh/sub]\n", "", ""); err == nil {
		t.Fatal("expected rejection of a mount under an always-blocked path")
	}
	// Mounting an ancestor of the floor (the home dir) is allowed (re-masked).
	if _, _, err := loadFrom(t, "/home/u", "providers:\n  paths:\n    rw: [/home/u]\n", "", ""); err != nil {
		t.Errorf("mounting an ancestor of the floor should be allowed, got %v", err)
	}
}

func TestPolicySecretScanDefaults(t *testing.T) {
	cfg, _, err := loadFrom(t, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.SecretScan.EntropyThreshold != 0 {
		t.Errorf("default entropyThreshold = %v, want 0 (off)", cfg.Policy.SecretScan.EntropyThreshold)
	}
	if len(cfg.Policy.SecretScan.SkipPaths) != 0 {
		t.Errorf("default skipPaths = %v, want empty", cfg.Policy.SecretScan.SkipPaths)
	}
}

func TestPolicySecretScanConfig(t *testing.T) {
	home := "/home/alice"
	global := "policy:\n  secretScan:\n    entropyThreshold: 4.3\n    skipPaths: [~/vault, /srv/secrets]\n"
	cfg, _, err := loadFrom(t, home, global, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy.SecretScan.EntropyThreshold != 4.3 {
		t.Errorf("entropyThreshold = %v, want 4.3", cfg.Policy.SecretScan.EntropyThreshold)
	}
	if cfg.Policy.SecretScan.SkipPaths[0] != "/home/alice/vault" {
		t.Errorf("skipPaths[0] = %q, want ~ expanded", cfg.Policy.SecretScan.SkipPaths[0])
	}
}

func TestPolicySkipPathsRelativeRejected(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "policy:\n  secretScan:\n    skipPaths: [rel/dir]\n", "", ""); err == nil ||
		!strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative skipPaths must be rejected, got %v", err)
	}
}

func TestPolicyNegativeEntropyRejected(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "policy:\n  secretScan:\n    entropyThreshold: -1\n", "", ""); err == nil {
		t.Fatal("negative entropyThreshold must be rejected")
	}
}

func TestKubernetesConfigParsesPermissions(t *testing.T) {
	yml := `providers:
  kubernetes:
    enabled: true
    tokenLifetime: 10h
    as: cluster-admin
    serviceAccountNamespace: my-ns
    permissions:
      - clusterWide: true
        clusterRole: view
      - namespaceSelector:
          matchLabels: {team: platform}
          matchExpressions:
            - {key: env, operator: In, values: [staging, dev]}
        clusterRole: edit
      - namespaceSelector:
          matchLabels: {kubernetes.io/metadata.name: app}
        role: deployer
`
	cfg, _, err := loadFrom(t, "/home/u", yml, "", "")
	if err != nil {
		t.Fatal(err)
	}
	k := cfg.Providers.Kubernetes
	if !k.Enabled || k.As != "cluster-admin" || k.ServiceAccountNamespace != "my-ns" {
		t.Errorf("kubernetes scalars wrong: %+v", k)
	}
	if k.EffectiveTokenLifetime() != 10*time.Hour {
		t.Errorf("tokenLifetime = %v, want 10h", k.EffectiveTokenLifetime())
	}
	perms := k.EffectivePermissions()
	if len(perms) != 3 {
		t.Fatalf("want 3 permissions, got %d", len(perms))
	}
	if !perms[0].ClusterWide || perms[0].ClusterRole != "view" {
		t.Errorf("perm[0] wrong: %+v", perms[0])
	}
	if perms[1].NamespaceSelector == nil || perms[1].NamespaceSelector.MatchLabels["team"] != "platform" {
		t.Errorf("perm[1] selector wrong: %+v", perms[1])
	}
	if len(perms[1].NamespaceSelector.MatchExpressions) != 1 ||
		perms[1].NamespaceSelector.MatchExpressions[0].Operator != "In" {
		t.Errorf("perm[1] matchExpressions wrong: %+v", perms[1].NamespaceSelector)
	}
	if perms[2].Role != "deployer" || perms[2].NamespaceSelector == nil {
		t.Errorf("perm[2] wrong: %+v", perms[2])
	}
}

func TestKubernetesDefaultsApplyInCode(t *testing.T) {
	// Enabled with no explicit permissions/tokenLifetime → in-code defaults.
	cfg, _, err := loadFrom(t, "/home/u", "providers:\n  kubernetes:\n    enabled: true\n", "", "")
	if err != nil {
		t.Fatal(err)
	}
	perms := cfg.Providers.Kubernetes.EffectivePermissions()
	if len(perms) != 1 || !perms[0].ClusterWide || perms[0].ClusterRole != "view" {
		t.Errorf("default permissions = one cluster-wide bind to view, got %+v", perms)
	}
	if cfg.Providers.Kubernetes.EffectiveTokenLifetime() != 8*time.Hour {
		t.Errorf("default tokenLifetime = %v, want 8h (from defaultsYAML)", cfg.Providers.Kubernetes.EffectiveTokenLifetime())
	}
	// mode and serviceAccountNamespace are deliberately absent from defaultsYAML so
	// preProvisioned mode can require the namespace explicitly: the raw key stays empty
	// after the merge, while the in-code accessors still default.
	k := cfg.Providers.Kubernetes
	if k.Mode != "" || k.ServiceAccountNamespace != "" {
		t.Errorf("defaultsYAML must not set mode/serviceAccountNamespace (an unset namespace must stay detectable), got mode=%q ns=%q", k.Mode, k.ServiceAccountNamespace)
	}
	if k.EffectiveMode() != kubernetes.ModeManaged || k.EffectiveServiceAccountNamespace() != "corral" {
		t.Errorf("in-code defaults must still apply: mode=%q ns=%q", k.EffectiveMode(), k.EffectiveServiceAccountNamespace())
	}
}

// The preProvisioned mode config contract, through the real config layers: the key parses,
// and its two honesty rules are enforced by config.Validate even with the provider off.
func TestKubernetesPreProvisionedMode(t *testing.T) {
	cfg, _, err := loadFrom(t, "/home/u", "providers:\n  kubernetes:\n    enabled: true\n    mode: preProvisioned\n    serviceAccountNamespace: corral-team-a\n", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Providers.Kubernetes.EffectiveMode(); got != kubernetes.ModePreProvisioned {
		t.Errorf("mode should parse as preProvisioned, got %q", got)
	}

	for _, tc := range []struct {
		name string
		yml  string
	}{
		{"permissions are not corral's to manage", "providers:\n  kubernetes:\n    enabled: true\n    mode: preProvisioned\n    serviceAccountNamespace: corral-team-a\n    permissions:\n      - clusterWide: true\n        clusterRole: view\n"},
		{"the namespace must be explicit", "providers:\n  kubernetes:\n    enabled: true\n    mode: preProvisioned\n"},
		{"unknown mode", "providers:\n  kubernetes:\n    enabled: true\n    mode: managed-ish\n"},
		// Strict validation regardless of enabled (as for tokenLifetime): a malformed
		// block is caught before it is switched on.
		{"disabled still validates", "providers:\n  kubernetes:\n    mode: preProvisioned\n"},
	} {
		if _, _, err := loadFrom(t, "/home/u", tc.yml, "", ""); err == nil {
			t.Errorf("%s: config should be rejected", tc.name)
		}
	}
}

func TestKubernetesTokenLifetimeBounds(t *testing.T) {
	for _, tc := range []struct {
		lifetime string
		ok       bool
	}{
		{"8h", true}, {"24h", true}, {"90m", true},
		{"24h1m", false}, {"48h", false}, {"0h", false}, {"banana", false},
	} {
		yml := "providers:\n  kubernetes:\n    enabled: true\n    tokenLifetime: " + tc.lifetime + "\n"
		_, _, err := loadFrom(t, "/home/u", yml, "", "")
		if tc.ok && err != nil {
			t.Errorf("tokenLifetime %q should be accepted, got %v", tc.lifetime, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("tokenLifetime %q should be rejected", tc.lifetime)
		}
	}
}

func TestGitlabValidation(t *testing.T) {
	for _, yml := range []string{
		"providers:\n  gitlab:\n    enabled: true\n    role: superuser\n",                      // not a GitLab role
		"providers:\n  gitlab:\n    enabled: true\n    expiryDays: 7\n",                        // removed knob → rejected as unknown key
		"providers:\n  gitlab:\n    enabled: true\n    type: group\n",                          // not a token type (project|personal)
		"providers:\n  gitlab:\n    enabled: true\n    type: personal\n    role: maintainer\n", // role is meaningless for a PAT → rejected, not silently ignored
	} {
		if _, _, err := loadFrom(t, "/home/u", yml, "", ""); err == nil {
			t.Errorf("config should be rejected:\n%s", yml)
		}
	}
	yml := "providers:\n  gitlab:\n    enabled: true\n    type: project\n    host: gl.example.com\n    project: g/p\n    scopes: [read_repository, write_repository]\n    role: maintainer\n"
	cfg, _, err := loadFrom(t, "/home/u", yml, "", "")
	if err != nil {
		t.Fatal(err)
	}
	gl := cfg.Providers.Gitlab
	if gl.Host != "gl.example.com" || gl.Project != "g/p" || gl.Role != "maintainer" || gl.EffectiveAccessLevel() != 40 || len(gl.Scopes) != 2 {
		t.Errorf("gitlab config not parsed correctly: %+v", gl)
	}
}

// --- session hooks (providers.hooks) layer merge ---
//
// The session-hooks maps must deep-merge across config layers so .corral.local.yml can
// override a single field of a repo-defined entry — the reason the feature uses a named map
// rather than the append-unique [{name,…}] list convention. These pin the locked semantics
// against the merge machinery (mergeMap recurses into nested maps field-by-field).

// A later layer overrides one field of an entry while the rest survive from the earlier layer.
func TestHooksLayerFieldLevelOverride(t *testing.T) {
	repo := "providers:\n  hooks:\n    preStart:\n      10-a:\n        exec: ./repo.sh\n        optional: false\n"
	local := "providers:\n  hooks:\n    preStart:\n      10-a:\n        optional: true\n" // only optional
	cfg, _, err := loadFrom(t, "/home/u", "", repo, local)
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Providers.Hooks.PreStart["10-a"]
	if h.Exec != "./repo.sh" {
		t.Errorf("script must survive from the repo layer, got %q (deep field-level merge broken)", h.Exec)
	}
	if !h.Optional {
		t.Errorf("the local layer must override only optional, got optional=%v", h.Optional)
	}
}

// The tombstone: .corral.local.yml disables a repo-defined hook with just enabled:false, and
// the repo layer's run survives (a map merge can never remove the key).
func TestHooksLayerEnabledFalseTombstone(t *testing.T) {
	repo := "providers:\n  hooks:\n    preStart:\n      10-a:\n        exec: ./repo.sh\n"
	local := "providers:\n  hooks:\n    preStart:\n      10-a:\n        enabled: false\n"
	cfg, _, err := loadFrom(t, "/home/u", "", repo, local)
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Providers.Hooks.PreStart["10-a"]
	if h.Exec != "./repo.sh" {
		t.Errorf("script must survive the tombstone merge, got %q", h.Exec)
	}
	if h.IsEnabled() {
		t.Error("enabled: false in the local layer must disable the repo-defined hook")
	}
	if cfg.Providers.Hooks.Enabled() {
		t.Error("a config whose only hook is tombstoned must be inert")
	}
}

// A later layer appends a new key without disturbing the earlier layer's entries.
func TestHooksLayerNewKeyAppend(t *testing.T) {
	repo := "providers:\n  hooks:\n    preStart:\n      10-a:\n        exec: ./a.sh\n"
	local := "providers:\n  hooks:\n    preStart:\n      20-b:\n        exec: ./b.sh\n"
	cfg, _, err := loadFrom(t, "/home/u", "", repo, local)
	if err != nil {
		t.Fatal(err)
	}
	pre := cfg.Providers.Hooks.PreStart
	if len(pre) != 2 || pre["10-a"].Exec != "./a.sh" || pre["20-b"].Exec != "./b.sh" {
		t.Errorf("a new-key append must keep both entries, got %+v", pre)
	}
}

// An explicit enabled:false must survive a merge with a layer that does not mention enabled —
// the nil-vs-false distinction must not silently re-enable a disabled hook (the reason Enabled
// is a *bool). Here the repo layer disables the hook and the local layer only edits run.
func TestHooksLayerExplicitFalseSurvivesNilOther(t *testing.T) {
	repo := "providers:\n  hooks:\n    preStart:\n      10-a:\n        exec: ./repo.sh\n        enabled: false\n"
	local := "providers:\n  hooks:\n    preStart:\n      10-a:\n        exec: ./local.sh\n" // no enabled key
	cfg, _, err := loadFrom(t, "/home/u", "", repo, local)
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Providers.Hooks.PreStart["10-a"]
	if h.Exec != "./local.sh" {
		t.Errorf("the local layer must override script, got %q", h.Exec)
	}
	if h.IsEnabled() {
		t.Error("an explicit enabled:false must survive a merge with a nil-Enabled layer (no silent re-enable)")
	}
}

// Args lists merge append-unique across layers like every config list (unionAny): a local
// layer can add args to a repo-defined hook but can never replace or remove one. That is a
// deliberate, documented consequence of the shared list-merge rule — to change a repo hook's
// args, disable the entry (enabled: false) and define your own. This test characterizes the
// behavior so a merge-machinery change cannot alter it silently.
func TestHooksLayerArgsAppendUnique(t *testing.T) {
	repo := "providers:\n  hooks:\n    preStart:\n      10-a:\n        exec: ./a.sh\n        args: [--fast, --v1]\n"
	local := "providers:\n  hooks:\n    preStart:\n      10-a:\n        args: [--v1, --local]\n" // --v1 duplicate
	cfg, _, err := loadFrom(t, "/home/u", "", repo, local)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cfg.Providers.Hooks.PreStart["10-a"].Args, " ")
	if got != "--fast --v1 --local" {
		t.Errorf("args = %q, want the append-unique union %q", got, "--fast --v1 --local")
	}
}

// A hook script's ~ expands at load — so the trust gate and the provider hash and exec the
// same file — while relative paths stay relative: they resolve against the session workdir
// (hooks.ResolveExec), which config does not know.
func TestHooksExecTildeExpansion(t *testing.T) {
	global := "providers:\n  hooks:\n    postEnd:\n      report:\n        exec: ~/bin/report.sh\n"
	repo := "providers:\n  hooks:\n    preStart:\n      10-a:\n        exec: ./scripts/a.sh\n"
	cfg, _, err := loadFrom(t, "/home/u", global, repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Providers.Hooks.PostEnd["report"].Exec; got != "/home/u/bin/report.sh" {
		t.Errorf("~ must expand at load, got %q", got)
	}
	if got := cfg.Providers.Hooks.PreStart["10-a"].Exec; got != "./scripts/a.sh" {
		t.Errorf("a relative script must stay relative (workdir-resolved later), got %q", got)
	}
}

// A typo'd field inside a hook entry must be rejected by strict decode (KnownFields), not
// silently ignored — the same fail-closed rule the rest of the config enforces.
func TestHooksUnknownEntryFieldRejected(t *testing.T) {
	bad := "providers:\n  hooks:\n    preStart:\n      10-a:\n        exec: ./a.sh\n        optionel: true\n" // typo
	if _, _, err := loadFrom(t, "/home/u", bad, "", ""); err == nil {
		t.Fatal("an unknown field inside a hook entry must fail closed (KnownFields)")
	}
}

// A malformed hooks block (empty run on an enabled entry) is caught at load via config.Validate.
func TestHooksValidateWiredIntoLoad(t *testing.T) {
	bad := "providers:\n  hooks:\n    preStart:\n      10-a:\n        optional: true\n" // enabled, no run
	if _, _, err := loadFrom(t, "/home/u", bad, "", ""); err == nil ||
		!strings.Contains(err.Error(), "providers.hooks.preStart.10-a") {
		t.Fatalf("config.Validate must reject an enabled hook with no run, got %v", err)
	}
}

func TestEnvBlockNoLongerSupported(t *testing.T) {
	// env.block was removed (the env model is allowlist-only). A config still using
	// it must fail closed as an unknown key, not be silently ignored.
	if _, _, err := loadFrom(t, "/home/u", "providers:\n  env:\n    block: [FOO]\n", "", ""); err == nil {
		t.Fatal("env.block must be rejected as an unknown key now that it is removed")
	}
}

func TestTildeExpansion(t *testing.T) {
	home := "/home/alice"
	cfg, _, err := loadFrom(t, home, "providers:\n  paths:\n    rw: [~/work, /abs]\n", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Providers.Paths.RW[0] != "/home/alice/work" {
		t.Errorf("~ not expanded: %v", cfg.Providers.Paths.RW)
	}
	if cfg.Providers.Paths.RW[1] != "/abs" {
		t.Errorf("absolute path altered: %v", cfg.Providers.Paths.RW)
	}
}

func TestTrailingSlashCleaned(t *testing.T) {
	cfg, _, err := loadFrom(t, "/home/u", "providers: {block: {directories: [/data/vault/]}}", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Providers.Block.Directories[0] != "/data/vault" {
		t.Errorf("trailing slash not cleaned: %q", cfg.Providers.Block.Directories[0])
	}
}

func TestFindProjectFilesWalksUp(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".corral.yml"), []byte("hostname: x"), 0o644); err != nil {
		t.Fatal(err)
	}
	deep := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	dir, proj, _ := findProjectFiles(deep)
	if dir != root || proj == "" {
		t.Errorf("walk-up failed: dir=%q proj=%q (root=%q)", dir, proj, root)
	}
}

func TestCloneMapSliceAliasing(t *testing.T) {
	base := map[string]any{"env": map[string]any{"passthrough": []any{"TERM"}}}
	clone := cloneMap(base)
	clone["env"].(map[string]any)["passthrough"].([]any)[0] = "CHANGED"
	if got := base["env"].(map[string]any)["passthrough"].([]any)[0]; got != "TERM" {
		t.Errorf("cloneMap aliased the slice; base mutated to %q", got)
	}
}

// --- helpers ---

func containsStr(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func hasSource(srcs []Source, kind string) bool {
	for _, s := range srcs {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

func sourceByKind(srcs []Source, kind string) (Source, bool) {
	for _, s := range srcs {
		if s.Kind == kind {
			return s, true
		}
	}
	return Source{}, false
}

// TestSourceSHA256MatchesParsedBytes pins the trust-gate provenance: each file layer's
// Source carries the hex sha256 of the exact bytes on disk, and non-file layers carry
// none. The gate keys approval on this hash, so drift here would silently mis-key it.
func TestSourceSHA256MatchesParsedBytes(t *testing.T) {
	project := "hostname: proj-host\n"
	local := "net: open\n"
	_, srcs, err := loadFrom(t, "/home/u", "", project, local)
	if err != nil {
		t.Fatal(err)
	}

	want := func(content string) string {
		sum := sha256.Sum256([]byte(content))
		return hex.EncodeToString(sum[:])
	}
	for _, tc := range []struct{ kind, content string }{
		{"project", project},
		{"local", local},
	} {
		s, ok := sourceByKind(srcs, tc.kind)
		if !ok {
			t.Fatalf("%s source missing: %v", tc.kind, srcs)
		}
		if s.SHA256 != want(tc.content) {
			t.Errorf("%s SHA256 = %q, want %q", tc.kind, s.SHA256, want(tc.content))
		}
	}

	// The defaults layer is not a file — no hash to key on.
	if s, ok := sourceByKind(srcs, "defaults"); !ok || s.SHA256 != "" {
		t.Errorf("defaults source must carry no SHA256, got %+v (ok=%v)", s, ok)
	}
}

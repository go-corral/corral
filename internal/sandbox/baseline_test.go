package sandbox

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "regenerate golden files")

// TestEmbeddedBaselineValid confirms the embedded file parses, validates, and is
// non-empty (init would already have panicked otherwise; this makes it explicit).
func TestEmbeddedBaselineValid(t *testing.T) {
	rules, err := loadBaseline(baselineJSON)
	if err != nil {
		t.Fatalf("embedded baseline failed to load: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("embedded baseline has no rules")
	}
	if err := validateLinuxTokens(rules); err != nil {
		t.Fatalf("embedded baseline has unexpandable Linux tokens: %v", err)
	}
}

// TestEmbeddedBaselineValidMacOSTokens confirms every macOS rule in the embedded
// baseline references only known macOS tokens (init would have panicked otherwise).
// validateMacOSTokens lives in this package (it runs at baseline load), so its test
// does too — the Seatbelt backend just consumes the validated rules.
func TestEmbeddedBaselineValidMacOSTokens(t *testing.T) {
	if err := validateMacOSTokens(baselineRules); err != nil {
		t.Fatalf("embedded baseline has unexpandable macOS tokens: %v", err)
	}
}

// TestRulesForUnionsAgentRules confirms RulesFor returns the embedded baseline followed by
// the spec's agent-contributed rules, and never mutates the shared baseline backing array —
// the contract the backends and the home-symlink farm rely on to compile claude's
// ~/.claude.json (an agent rule) exactly like an embedded rule, while `corral run pi` (no
// agent rules) compiles the baseline unchanged.
func TestRulesForUnionsAgentRules(t *testing.T) {
	base := BaselineRules()

	// No agent rules: identical contents to the baseline, and the baseline is untouched.
	if got := RulesFor(SandboxSpec{}); len(got) != len(base) {
		t.Fatalf("RulesFor with no agent rules = %d rules, want baseline len %d", len(got), len(base))
	}

	agentRule := Rule{Path: "$HOME/.agent-only", Description: "agent rule", Writeable: true}
	got := RulesFor(SandboxSpec{AgentRules: []Rule{agentRule}})
	if len(got) != len(base)+1 {
		t.Fatalf("RulesFor with 1 agent rule = %d rules, want %d", len(got), len(base)+1)
	}
	if got[len(got)-1].Path != agentRule.Path {
		t.Errorf("agent rule must come last (after the baseline), got last=%q", got[len(got)-1].Path)
	}
	// The shared baseline must be unchanged (RulesFor returns a fresh slice).
	if len(BaselineRules()) != len(base) {
		t.Errorf("RulesFor mutated the shared baseline: len now %d, was %d", len(BaselineRules()), len(base))
	}
}

// TestStrictDecodeRejectsWhenGate is the regression test that the removed `when`
// gate stays gone: a rule carrying it must fail the load (fail-closed), not be
// silently ignored.
func TestStrictDecodeRejectsWhenGate(t *testing.T) {
	bad := `{"rules":[{"path":"/var/run/docker.sock","description":"d","when":"docker"}]}`
	if _, err := loadBaseline([]byte(bad)); err == nil {
		t.Fatal("a rule with a `when` gate must be rejected (the gate was removed)")
	}
}

func TestStrictDecodeRejectsUnknownKey(t *testing.T) {
	bad := `{"rules":[{"path":"/x","description":"d","readOnly":true}]}`
	if _, err := loadBaseline([]byte(bad)); err == nil {
		t.Fatal("unknown rule key must be rejected (fail-closed)")
	}
}

func TestLoadBaselineValidations(t *testing.T) {
	cases := map[string]string{
		"no rules":        `{"rules":[]}`,
		"missing desc":    `{"rules":[{"path":"/x"}]}`,
		"missing path":    `{"rules":[{"description":"d"}]}`,
		"bad arch":        `{"rules":[{"path":"/x","description":"d","archs":["windows"]}]}`,
		"newline in path": `{"rules":[{"path":"/x\ny","description":"d"}]}`,
		"unknown top key": `{"rules":[{"path":"/x","description":"d"}],"bogus":1}`,
	}
	for name, js := range cases {
		if _, err := loadBaseline([]byte(js)); err == nil {
			t.Errorf("%s: expected load error, got nil", name)
		}
	}
}

func TestArchMatch(t *testing.T) {
	if !ArchMatch(Rule{}, "linux") || !ArchMatch(Rule{}, "macos") {
		t.Error("empty archs must match both platforms (schema default)")
	}
	if ArchMatch(Rule{Archs: []string{"macos"}}, "linux") {
		t.Error("macos-only rule must not match linux")
	}
	if !ArchMatch(Rule{Archs: []string{"linux", "macos"}}, "linux") {
		t.Error("[linux,macos] must match linux")
	}
}

func TestValidateLinuxTokensRejectsUnknown(t *testing.T) {
	// A linux rule referencing a macOS-only token must be caught.
	rules := []Rule{{Path: "$SESSION_TMPDIR/x", Description: "d", Archs: []string{"linux"}}}
	if err := validateLinuxTokens(rules); err == nil {
		t.Fatal("expected unknown-token error for a linux rule using $SESSION_TMPDIR")
	}
	// The same token on a macOS-only rule is fine (expanded by the Seatbelt backend).
	ok := []Rule{{Path: "$SESSION_TMPDIR/x", Description: "d", Archs: []string{"macos"}}}
	if err := validateLinuxTokens(ok); err != nil {
		t.Fatalf("macOS-only token must not be validated for Linux: %v", err)
	}
}

func TestValidateMacOSTokensRejectsUnknown(t *testing.T) {
	// A macOS rule referencing a Linux-only / unknown token must be caught.
	bad := []Rule{{Path: "$XDG_RUNTIME_DIR/x", Description: "d", Archs: []string{"macos"}}}
	if err := validateMacOSTokens(bad); err == nil {
		t.Fatal("expected unknown-token error for a macOS rule using $XDG_RUNTIME_DIR")
	}
	// The same token on a Linux-only rule is fine (not validated for macOS).
	ok := []Rule{{Path: "$XDG_RUNTIME_DIR/x", Description: "d", Archs: []string{"linux"}}}
	if err := validateMacOSTokens(ok); err != nil {
		t.Fatalf("Linux-only token must not be validated for macOS: %v", err)
	}
}

// TestExpandPath proves the shared token-expansion fail-safe both backends rely on:
// a present token expands; a missing or empty token yields ok=false so the caller
// skips the rule rather than compiling a partially-resolved path.
func TestExpandPath(t *testing.T) {
	tok := map[string]string{"HOME": "/home/u", "EMPTY": ""}
	if got, ok := ExpandPath("$HOME/.cache", tok); !ok || got != "/home/u/.cache" {
		t.Errorf("ExpandPath($HOME/.cache) = (%q, %v), want (/home/u/.cache, true)", got, ok)
	}
	if _, ok := ExpandPath("$MISSING/x", tok); ok {
		t.Error("a missing token must yield ok=false")
	}
	if _, ok := ExpandPath("$EMPTY/x", tok); ok {
		t.Error("an empty-valued token must yield ok=false")
	}
	if got, ok := ExpandPath("/usr", tok); !ok || got != "/usr" {
		t.Errorf("a token-free path must expand unchanged; got (%q, %v)", got, ok)
	}
}

// TestNoFeatureMountsInBaseline asserts the policy carries no feature-tied mounts
// (docker/ssh/kubeconfig) — those are Providers' job.
func TestNoFeatureMountsInBaseline(t *testing.T) {
	for _, r := range baselineRules {
		low := strings.ToLower(r.Path)
		for _, banned := range []string{"docker", "ssh_auth_sock", "ssh-agent", "kubeconfig", "kube"} {
			if strings.Contains(low, banned) {
				t.Errorf("baseline must hold no feature mounts; rule %q looks feature-tied (%q)", r.Path, banned)
			}
		}
	}
}

// TestNoSecretPathsInBaseline asserts no baseline rule exposes an always-blocked
// secret dir (defense-in-depth; the masks land last regardless).
func TestNoSecretPathsInBaseline(t *testing.T) {
	for _, r := range baselineRules {
		low := strings.ToLower(r.Path)
		for _, secret := range []string{".ssh", ".gnupg", ".aws"} {
			if strings.Contains(low, secret) {
				t.Errorf("baseline must not expose a secret dir; rule %q contains %q", r.Path, secret)
			}
		}
	}
}

// TestMacOSRulesCarriedAsData: macOS rules must be present (for the Seatbelt backend)
// and must be distinguishable from the Linux-applicable set.
func TestMacOSRulesCarriedAsData(t *testing.T) {
	var macOnly int
	for _, r := range baselineRules {
		if ArchMatch(r, "macos") && !ArchMatch(r, "linux") {
			macOnly++
		}
	}
	if macOnly == 0 {
		t.Error("expected macOS-only rules carried as data for the Seatbelt backend")
	}
}

// TestPermissionsDocInSync guards the generated permissions reference against
// drift: it must equal RenderPermissionsDoc(baseline). Run `go test
// ./internal/sandbox -update` after editing the baseline.
func TestPermissionsDocInSync(t *testing.T) {
	got := RenderPermissionsDoc(baselineRules)
	path := filepath.Join("..", "..", "docs", "reference", "sandbox-permissions.md")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read permissions doc (run `go test ./internal/sandbox -update`): %v", err)
	}
	if got != string(want) {
		t.Errorf("permissions reference out of sync with the baseline; run `go test ./internal/sandbox -update`")
	}
}

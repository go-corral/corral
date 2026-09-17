package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/pathutil"
)

// TestInsideCorralWhenEnvSet verifies that when CORRAL_SANDBOX is set to "1",
// InsideCorral returns true, so in-sandbox hooks can detect a sandboxed session.
func TestInsideCorralWhenEnvSet(t *testing.T) {
	t.Setenv(SandboxEnvVar, "1")
	if !InsideCorral() {
		t.Error("InsideCorral() must return true when CORRAL_SANDBOX is set")
	}
}

// TestInsideCorralWhenEnvUnset verifies that when CORRAL_SANDBOX is unset,
// InsideCorral returns false, so claude running outside the sandbox needs no marker.
func TestInsideCorralWhenEnvUnset(t *testing.T) {
	t.Setenv(SandboxEnvVar, "")
	if InsideCorral() {
		t.Error("InsideCorral() must return false when CORRAL_SANDBOX is unset")
	}
}

// TestDefaultSpecAgentConfigDirOverride verifies DefaultSpec carries the supplied
// AgentConfigDir straight through as the $AGENT_CONFIG_DIR baseline token.
func TestDefaultSpecAgentConfigDirOverride(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	custom := "/custom/claude"
	spec := DefaultSpec(DefaultParams{
		Home:           home,
		ProjectDir:     proj,
		AgentConfigDir: custom,
	})

	if got := spec.Tokens["AGENT_CONFIG_DIR"]; got != custom {
		t.Errorf("AGENT_CONFIG_DIR token = %q, want %q", got, custom)
	}
}

// TestMountTargetWithDst verifies that when Mount has a non-empty Dst,
// MountTarget returns the Dst (the in-sandbox path).
func TestMountTargetWithDst(t *testing.T) {
	m := Mount{Src: "/a", Dst: "/b"}
	if got := MountTarget(m); got != "/b" {
		t.Errorf("MountTarget with Dst = %q, want /b", got)
	}
}

// TestMountTargetNoDst verifies that when Mount Dst is empty,
// MountTarget returns the Src (defaulting to the host path).
func TestMountTargetNoDst(t *testing.T) {
	m := Mount{Src: "/a", Dst: ""}
	if got := MountTarget(m); got != "/a" {
		t.Errorf("MountTarget with empty Dst = %q, want /a", got)
	}
}

// TestWithinPrefixSafety verifies the reachability containment check
// (pathutil.AtOrUnder) does not treat "/usr-local/bin" as within "/usr"
// (a substring false-positive); it requires an actual directory-separator boundary.
func TestWithinPrefixSafety(t *testing.T) {
	if pathutil.AtOrUnder("/usr-local/bin", "/usr") {
		t.Error("containment must be prefix-safe; /usr-local/bin is not truly within /usr")
	}
}

// TestWithinRootSpecialCase verifies everything is within root "/", so the
// containment check returns true for any path and "/".
func TestWithinRootSpecialCase(t *testing.T) {
	cases := []string{"/any/path", "/", "/usr/bin", "/home"}
	for _, path := range cases {
		if !pathutil.AtOrUnder(path, "/") {
			t.Errorf("AtOrUnder(%q, /) must be true; everything is under root", path)
		}
	}
}

// BaselineRules() returns the shared package global directly (no copy), so there is
// no immutability contract to lock; asserting the shared backing array would only
// cement a footgun.

// config paths.rw/ro grants do not flow through DefaultSpec: the built-in paths
// provider contributes them via the engine's grant channels, and their Optional +
// collision-exempt semantics are covered in internal/providers.

// TestDefaultSpecNoProjectDir verifies that when ProjectDir is empty,
// DefaultSpec does not include a project mount.
func TestDefaultSpecNoProjectDir(t *testing.T) {
	home := t.TempDir()

	spec := DefaultSpec(DefaultParams{
		Home:       home,
		ProjectDir: "",
	})

	// With no ProjectDir, Mounts should be empty.
	if len(spec.Mounts) != 0 {
		t.Errorf("DefaultSpec with empty ProjectDir must not create project mount; got %v", spec.Mounts)
	}
}

// TestDefaultSpecNetDefault verifies that when Net is empty,
// DefaultSpec defaults to NetOpen (0.1 full network).
func TestDefaultSpecNetDefault(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	spec := DefaultSpec(DefaultParams{
		Home:       home,
		ProjectDir: proj,
		Net:        "",
	})

	if spec.Net != NetOpen {
		t.Errorf("Net default = %q, want %q", spec.Net, NetOpen)
	}
}

// TestDefaultSpecHostnameDefault verifies that when Hostname is empty,
// DefaultSpec defaults to "corral".
func TestDefaultSpecHostnameDefault(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	spec := DefaultSpec(DefaultParams{
		Home:       home,
		ProjectDir: proj,
		Hostname:   "",
	})

	if spec.Hostname != "corral" {
		t.Errorf("Hostname default = %q, want corral", spec.Hostname)
	}
}

// TestExpandPathLiteral verifies that when ExpandPath is given a path
// with no tokens, it returns the path unchanged with ok=true.
func TestExpandPathLiteral(t *testing.T) {
	path := "/usr/bin"
	got, ok := ExpandPath(path, map[string]string{})
	if !ok || got != path {
		t.Errorf("ExpandPath(%q, {}) = (%q, %v), want (%q, true)", path, got, ok, path)
	}
}

// TestArchForGOOSUnsupported verifies that for an unsupported OS
// like "windows", archForGOOS returns "" (fail-safe: no backend).
func TestArchForGOOSUnsupported(t *testing.T) {
	if got := archForGOOS("windows"); got != "" {
		t.Errorf("archForGOOS(windows) = %q, want empty string", got)
	}
}

// TestArchForGOOSLinux verifies archForGOOS maps "linux" to "linux".
func TestArchForGOOSLinux(t *testing.T) {
	if got := archForGOOS("linux"); got != "linux" {
		t.Errorf("archForGOOS(linux) = %q, want linux", got)
	}
}

// TestArchForGOOSDarwin verifies archForGOOS maps "darwin" to "macos"
// (the baseline arch name, not the Go runtime name).
func TestArchForGOOSDarwin(t *testing.T) {
	if got := archForGOOS("darwin"); got != "macos" {
		t.Errorf("archForGOOS(darwin) = %q, want macos", got)
	}
}

// TestRenderPermissionsDocEmptyFlags verifies that when a rule has no
// optional/recursive/regex/create/resolveSymlinks flags, the Flags column
// in the rendered table shows "—" (em-dash).
func TestRenderPermissionsDocEmptyFlags(t *testing.T) {
	rules := []Rule{
		{
			Path:            "/bin",
			Description:     "system binaries",
			Writeable:       false,
			Optional:        false,
			Recursive:       nil, // not set
			Regex:           false,
			Create:          false,
			ResolveSymlinks: false,
		},
	}

	doc := RenderPermissionsDoc(rules)

	// The em-dash should appear in the Flags column for this rule.
	// The table row format is: | `path` | access | flags | description |
	// Note: RenderPermissionsDoc renders the rule for each arch, so search the entire doc.
	expectedRow := "| `" + rules[0].Path + "` | ro | — | system binaries |"
	if !stringInLines(splitLines(doc), expectedRow) {
		t.Errorf("RenderPermissionsDoc with no flags must show em-dash (—) in row %q; not found in doc", expectedRow)
	}
}

// TestRenderPermissionsDocMultipleFlags verifies that when a rule has
// optional=true and recursive=false and create=true, the Flags column
// shows "optional, node, create" (comma-space-separated).
func TestRenderPermissionsDocMultipleFlags(t *testing.T) {
	falseVal := false
	rules := []Rule{
		{
			Path:            "/var/run/example",
			Description:     "test rule",
			Writeable:       false,
			Optional:        true,
			Recursive:       &falseVal, // false => "node"
			Regex:           false,
			Create:          true,
			ResolveSymlinks: false,
		},
	}

	doc := RenderPermissionsDoc(rules)

	// The Flags column must contain "optional, node, create" in that order.
	// Note: RenderPermissionsDoc renders the rule for each arch, so search the entire doc.
	expectedRow := "| `" + rules[0].Path + "` | ro | optional, node, create | test rule |"
	if !stringInLines(splitLines(doc), expectedRow) {
		t.Errorf("RenderPermissionsDoc with optional+node+create must show comma-separated flags in row %q; not found in doc", expectedRow)
	}
}

// TestDefaultSpecCreatesAgentConfigDir verifies DefaultSpec creates
// the AgentConfigDir (with mode 0o700) if it does not exist, so a first run
// with a non-existent ~/.claude does not fail the bind.
func TestDefaultSpecCreatesAgentConfigDir(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	// Use a nested non-existent dir under a writable parent.
	configDir := filepath.Join(home, "nonexistent", "nested", ".claude")

	spec := DefaultSpec(DefaultParams{
		Home:           home,
		ProjectDir:     proj,
		AgentConfigDir: configDir,
	})

	// The directory must now exist with the correct mode.
	fi, err := os.Stat(configDir)
	if err != nil {
		t.Fatalf("DefaultSpec must create AgentConfigDir; stat failed: %v", err)
	}
	if !fi.IsDir() {
		t.Errorf("AgentConfigDir must be a directory")
	}
	mode := fi.Mode().Perm()
	if mode != 0o700 {
		t.Errorf("AgentConfigDir mode = 0o%o, want 0o700", mode)
	}

	// The AGENT_CONFIG_DIR token must point to the created dir.
	if spec.Tokens["AGENT_CONFIG_DIR"] != configDir {
		t.Errorf("AGENT_CONFIG_DIR token = %q, want %q", spec.Tokens["AGENT_CONFIG_DIR"], configDir)
	}
}

// TestBaselineRulesNonEmpty verifies BaselineRules returns
// a non-empty slice; the embedded baseline must have rules.
func TestBaselineRulesNonEmpty(t *testing.T) {
	rules := BaselineRules()
	if len(rules) == 0 {
		t.Fatal("BaselineRules must return a non-empty slice")
	}
}

// === Helper functions ===

// stringInLines checks if any line in lines equals want (for matching table rows).
func stringInLines(lines []string, want string) bool {
	for _, line := range lines {
		if line == want {
			return true
		}
	}
	return false
}

// splitLines splits the rendered doc into lines for table row matching.
func splitLines(doc string) []string {
	var lines []string
	var current string
	for _, ch := range doc {
		if ch == '\n' {
			lines = append(lines, current)
			current = ""
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	return lines
}

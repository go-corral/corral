package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
)

// Path separators and special chars in the presence-marker ID are sanitized.
func TestPresenceMarkerPathSanitization(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	cases := []struct {
		sessionID string
		name      string
	}{
		{"sess/with/slashes", "path separators"},
		{"sess:with:colons", "colons"},
		{"sess with spaces", "spaces"},
		{"sess\twith\ttabs", "tabs"},
		{"sess<with>special!@#$%^&*()", "special chars"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := presenceMarkerPath(c.sessionID)
			// Verify it's a valid filesystem path under TMPDIR
			if !strings.HasPrefix(path, tmpDir) {
				t.Errorf("marker path not under TMPDIR: %q", path)
			}
			// The filename must carry the expected prefix and contain only safe
			// characters: presenceMarkerPath maps every other rune (path separators,
			// spaces, shell metacharacters) to '_', so a stray unsafe rune is a regression.
			filename := filepath.Base(path)
			if !strings.HasPrefix(filename, "corral-unsandboxed-") {
				t.Errorf("marker filename missing expected prefix: %q", filename)
			}
			for _, r := range filename {
				safe := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
					(r >= '0' && r <= '9') || r == '-' || r == '_'
				if !safe {
					t.Errorf("marker filename contains unsafe char %q: %q", r, filename)
				}
			}
		})
	}
}

// An empty ID returns a shared marker.
func TestPresenceMarkerPathEmptyID(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	path := presenceMarkerPath("")
	if !strings.HasPrefix(path, tmpDir) {
		t.Errorf("empty ID marker not under TMPDIR: %q", path)
	}
	// Empty ID should produce a stable shared marker containing "corral-unsandboxed-"
	if !strings.Contains(filepath.Base(path), "corral-unsandboxed-") {
		t.Errorf("empty ID must produce a shared marker, got %q", path)
	}
}

// A very long ID is truncated to 128 chars.
func TestPresenceMarkerPathLongID(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)

	longID := strings.Repeat("a", 200) // > 128 chars
	path := presenceMarkerPath(longID)

	filename := filepath.Base(path)
	// After sanitization and truncation, safe is at most 128 chars.
	// The prefix "corral-unsandboxed-" is then prepended, making the total filename
	// at most 128 + 19 = 147 chars.
	// The part after the prefix must be exactly 128 chars (since the input was > 128).
	safePart := strings.TrimPrefix(filename, "corral-unsandboxed-")
	if len(safePart) > 128 {
		t.Errorf("marker filename safe part too long: %q (truncation failed, len=%d)", safePart, len(safePart))
	}
	if len(safePart) != 128 {
		t.Errorf("marker filename safe part should be truncated to exactly 128 chars, got %d", len(safePart))
	}
}

// A loadConfig error is returned: an invalid .corral.yml in the project directory causes a
// YAML parse error (a missing config file is not an error, defaults apply).
func TestLocalEngineInputsConfigLoadError(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte("invalid: yaml: [syntax"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	if _, err := localEngineInputs(); err == nil || !strings.Contains(err.Error(), "load config") {
		t.Errorf("localEngineInputs with an invalid config: got %v, want a load config error", err)
	}
}

// An os.UserHomeDir failure returns an error.
func TestLocalEngineInputsHomeLookupError(t *testing.T) {
	// os.UserHomeDir() reads $HOME and errors when it is empty on unix; t.Setenv restores it.
	t.Setenv("HOME", "")

	if _, err := localEngineInputs(); err == nil || !strings.Contains(err.Error(), "home") {
		t.Errorf("localEngineInputs with no HOME: got %v, want a home resolution error", err)
	}
}

// The always-blocked paths and config block.directories/block.files each deny under their own
// rule name. A config entry equal to an always-blocked directory reports always-blocked. newEngine builds from its inputs alone: the process HOME and cwd point elsewhere.
func TestNewEngineAlwaysBlockedUnion(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())

	home := t.TempDir()
	projDir := filepath.Join(home, "proj")
	customBlocked := filepath.Join(home, "custom-blocked")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".aws"), projDir, customBlocked} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &config.Config{}
	cfg.Providers.Block.Directories = []string{customBlocked, filepath.Join(home, ".aws")}

	in := engineInputs{
		cfg:       cfg,
		home:      home,
		env:       map[string]string{"HOME": home},
		workDir:   projDir,
		auditPath: filepath.Join(home, ".claude", "corral-audit.jsonl"),
	}
	eng, err := newEngine(in, readPolicyFiles(in), policy.OSFS{})
	if err != nil {
		t.Fatalf("newEngine must succeed with a valid config and home; got %v", err)
	}

	for _, tc := range []struct {
		file string
		rule string
	}{
		{filepath.Join(home, ".ssh", "id_rsa"), "always-blocked"},
		{filepath.Join(customBlocked, "file.txt"), "blocked-path"},
		{filepath.Join(home, ".aws", "credentials"), "always-blocked"},
	} {
		event, _ := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       "Read",
			"tool_input":      map[string]any{"file_path": tc.file},
			"cwd":             home,
		})
		var stderr strings.Builder
		if code := policy.RunHook(eng, strings.NewReader(string(event)), &stderr); code != policy.ExitBlock {
			t.Errorf("%s must be blocked, got code %d (want %d)", tc.file, code, policy.ExitBlock)
		}
		if want := "[hook:" + tc.rule + "]"; !strings.Contains(stderr.String(), want) {
			t.Errorf("%s: deny must carry %s, got %q", tc.file, want, stderr.String())
		}
	}
}

// Every rule of the engine has a fix.
func TestEveryRuleHasAFix(t *testing.T) {
	home := t.TempDir()
	in := engineInputs{
		cfg:       &config.Config{},
		home:      home,
		env:       map[string]string{"HOME": home},
		workDir:   home,
		auditPath: filepath.Join(home, "corral-audit.jsonl"),
	}
	eng, err := newEngine(in, readPolicyFiles(in), policy.OSFS{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range eng.RuleNames() {
		if _, ok := policy.Fixes[name]; !ok {
			t.Errorf("rule %q has no entry in policy.Fixes", name)
		}
	}
}

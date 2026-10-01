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

// The always-blocked paths are unioned with config block.directories/block.files. newEngine
// builds from its inputs alone: the process HOME and cwd point elsewhere.
func TestNewEngineAlwaysBlockedUnion(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())

	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	projDir := filepath.Join(home, "proj")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}

	customBlocked := filepath.Join(home, "custom-blocked")
	cfg := &config.Config{}
	cfg.Providers.Block.Directories = []string{customBlocked}

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

	// Test 1: Verify that the always-blocked path ~/.ssh/id_rsa is blocked
	// Create a PreToolUse event targeting a file in the always-blocked set
	sshKeyPath := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(sshKeyPath, []byte("fake-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Use the correct event format: hook_event_name, tool_name, tool_input with file_path key
	eventData1 := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": sshKeyPath},
		"cwd":             home,
	}
	eventBytes1, _ := json.Marshal(eventData1)
	var stderr1 strings.Builder

	code1 := policy.RunHook(eng, strings.NewReader(string(eventBytes1)), &stderr1)
	if code1 != policy.ExitBlock {
		t.Errorf("always-blocked path ~/.ssh/id_rsa must be blocked, got code %d (want %d)", code1, policy.ExitBlock)
	}

	// Test 2: Verify that the custom blocked path is also blocked
	customPath := filepath.Join(customBlocked, "file.txt")
	if err := os.MkdirAll(customBlocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(customPath, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	eventData2 := map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": customPath},
		"cwd":             home,
	}
	eventBytes2, _ := json.Marshal(eventData2)
	var stderr2 strings.Builder

	code2 := policy.RunHook(eng, strings.NewReader(string(eventBytes2)), &stderr2)
	if code2 != policy.ExitBlock {
		t.Errorf("custom blocked path must be blocked, got code %d (want %d)", code2, policy.ExitBlock)
	}
}

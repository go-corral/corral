package claudecfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSyncErrorSettingsPathRequired asserts Sync rejects an empty SettingsPath.
func TestSyncErrorSettingsPathRequired(t *testing.T) {
	_, _, err := Sync(SyncOptions{BinaryPath: testBinary})
	if err == nil || !strings.Contains(err.Error(), "claudecfg: SettingsPath is required") {
		t.Errorf("expected error about SettingsPath required, got: %v", err)
	}
}

// TestSyncErrorBinaryPathRequired asserts Sync rejects an empty BinaryPath.
func TestSyncErrorBinaryPathRequired(t *testing.T) {
	dir := t.TempDir()
	_, _, err := Sync(SyncOptions{SettingsPath: filepath.Join(dir, "settings.json")})
	if err == nil || !strings.Contains(err.Error(), "claudecfg: BinaryPath is required") {
		t.Errorf("expected error about BinaryPath required, got: %v", err)
	}
}

// TestRemoveNeedsNoBinaryPath checks that BinaryPath is required only for a
// registration (it goes into the hook command). A removal identifies corral's entries by shape,
// so it must work without one — `corral sync --remove` cannot depend on resolving the binary
// that installed the hooks (it may be long gone).
func TestRemoveNeedsNoBinaryPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/some/other/bin/corral"}); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatalf("removal without BinaryPath must not error: %v", err)
	}
	if !changed {
		t.Error("removal should have stripped the registration")
	}
	if strings.Contains(string(rendered), "/some/other/bin/corral") {
		t.Errorf("removal must strip entries registered by ANY corral binary:\n%s", rendered)
	}
	// SettingsPath is still required in removal mode — there is no default to fall back on.
	if _, _, err := Sync(SyncOptions{Remove: true}); err == nil || !strings.Contains(err.Error(), "claudecfg: SettingsPath is required") {
		t.Errorf("expected SettingsPath to stay required for a removal, got: %v", err)
	}
}

// TestSyncErrorReadSettingsPermissionDenied covers a settings file that exists but
// is not readable (permission denied).
func TestSyncErrorReadSettingsPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses filesystem permission checks")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")

	// Create a file and make it unreadable.
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(path, 0o644) // restore for cleanup
	})

	_, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err == nil {
		t.Fatal("expected error reading unreadable settings file")
	}
	if !strings.Contains(err.Error(), "read settings:") {
		t.Errorf("expected error starting with 'read settings:', got: %v", err)
	}
}

// TestSyncErrorCreateSettingsDirPermissionDenied covers a parent directory that
// cannot be created because mkdir is permission-denied.
func TestSyncErrorCreateSettingsDirPermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses filesystem permission checks")
	}
	// Create a read-only parent directory to prevent creating the settings directory.
	baseDir := t.TempDir()
	readOnlyDir := filepath.Join(baseDir, "readonly")
	settingsDir := filepath.Join(readOnlyDir, "config")
	settingsPath := filepath.Join(settingsDir, "settings.json")

	if err := os.Mkdir(readOnlyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(readOnlyDir, 0o755) // restore for cleanup
	})

	_, _, err := Sync(SyncOptions{SettingsPath: settingsPath, BinaryPath: testBinary})
	if err == nil {
		t.Fatal("expected error creating settings directory")
	}
	if !strings.Contains(err.Error(), "create settings dir:") {
		t.Errorf("expected error starting with 'create settings dir:', got: %v", err)
	}

	// The settings directory should not have been created.
	if _, err := os.Stat(settingsDir); !os.IsNotExist(err) {
		t.Errorf("settings directory was created despite error")
	}
}

// TestSyncDefaultSettingsPathWithEnvVar covers the CLAUDE_CONFIG_DIR environment variable.
func TestSyncDefaultSettingsPathWithEnvVar(t *testing.T) {
	customDir := "/custom/config"
	t.Setenv("CLAUDE_CONFIG_DIR", customDir)
	result := DefaultSettingsPath("/home/user")
	expected := "/custom/config/settings.json"
	if result != expected {
		t.Errorf("DefaultSettingsPath with CLAUDE_CONFIG_DIR: got %q, want %q", result, expected)
	}
}

// TestSyncDefaultSettingsPathWithoutEnvVar covers the home-based default when
// CLAUDE_CONFIG_DIR is unset.
func TestSyncDefaultSettingsPathWithoutEnvVar(t *testing.T) {
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	result := DefaultSettingsPath("/home/user")
	expected := "/home/user/.claude/settings.json"
	if result != expected {
		t.Errorf("DefaultSettingsPath without CLAUDE_CONFIG_DIR: got %q, want %q", result, expected)
	}
}

// TestIsCorralEntryUnmarshalableJSON covers a hook entry with unmarshalable JSON.
func TestIsCorralEntryUnmarshalableJSON(t *testing.T) {
	malformedRaw := json.RawMessage(`{"type": "command", "command": 123}`) // number instead of string
	result := isCorralEntry(malformedRaw)
	if result {
		t.Error("isCorralEntry should return false for unmarshalable JSON")
	}
}

// TestIsCorralEntryNonCommandType covers a hook entry with type != 'command'.
func TestIsCorralEntryNonCommandType(t *testing.T) {
	httpHook := json.RawMessage(`{"type": "http", "url": "https://example.test/hook"}`)
	result := isCorralEntry(httpHook)
	if result {
		t.Error("isCorralEntry should return false for non-command type")
	}
}

// TestUpsertCorralHookInvalidArrayJSON covers an existing hooks[event] that is not
// a valid JSON array (e.g., a string or object instead of array).
func TestUpsertCorralHookInvalidArrayJSON(t *testing.T) {
	hooks := map[string]json.RawMessage{
		"PreToolUse": json.RawMessage(`"not an array"`),
	}
	err := upsertCorralHook(hooks, "PreToolUse", "Bash", "corral hook pre-tool-use", 10)
	if err == nil {
		t.Fatal("expected error for non-array hooks")
	}
	if !strings.Contains(err.Error(), "settings.json hooks.PreToolUse is not an array:") {
		t.Errorf("expected error about hooks not being an array, got: %v", err)
	}
}

// TestSyncDryRunDoesNotWrite covers DryRun=true returning rendered content without
// writing the file or creating the parent directory.
func TestSyncDryRunDoesNotWrite(t *testing.T) {
	// Use a path with a non-existent parent directory.
	dir := t.TempDir()
	nonExistentParent := filepath.Join(dir, "parent", "child")
	settingsPath := filepath.Join(nonExistentParent, "settings.json")

	rendered, changed, err := Sync(SyncOptions{
		SettingsPath: settingsPath,
		BinaryPath:   testBinary,
		DryRun:       true,
	})
	if err != nil {
		t.Fatalf("Sync with DryRun=true failed: %v", err)
	}
	if !changed {
		t.Error("fresh DryRun sync should report changed=true")
	}
	if len(rendered) == 0 {
		t.Error("Sync should return rendered content even in DryRun mode")
	}

	// The parent directory should not be created.
	if _, err := os.Stat(nonExistentParent); !os.IsNotExist(err) {
		t.Errorf("parent directory was created in DryRun mode")
	}

	// The file should not be created.
	if _, err := os.Stat(settingsPath); !os.IsNotExist(err) {
		t.Errorf("settings file was created in DryRun mode")
	}
}

// TestSyncRenderAllThreeHookEvents covers multiple upsertCorralHook calls
// (PreToolUse, SessionStart, UserPromptSubmit) appearing in output with correct
// commands and timeout values.
func TestSyncRenderAllThreeHookEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	timeout := 15 // custom timeout to verify it's used

	rendered, _, err := Sync(SyncOptions{
		SettingsPath: path,
		BinaryPath:   testBinary,
		TimeoutSecs:  timeout,
	})
	if err != nil {
		t.Fatal(err)
	}

	s := string(rendered)
	// Verify all three events are present.
	for _, event := range []string{"PreToolUse", "SessionStart", "UserPromptSubmit"} {
		if !strings.Contains(s, `"`+event+`"`) {
			t.Errorf("missing hook event %s", event)
		}
	}

	// Verify correct commands.
	if !strings.Contains(s, hookSubcommand) {
		t.Error("PreToolUse command not found")
	}
	if !strings.Contains(s, hookSubcommandSessionStart) {
		t.Error("SessionStart command not found")
	}
	if !strings.Contains(s, hookSubcommandUserPromptSubmit) {
		t.Error("UserPromptSubmit command not found")
	}

	// Verify custom timeout is used in all hooks.
	// Custom timeout (15) should appear multiple times (once per hook type).
	// Note: JSON marshaling adds spaces after colons: "timeout": 15
	count := strings.Count(s, `"timeout": 15`)
	if count < 3 {
		t.Errorf("custom timeout not used in all hooks: found %d occurrences, want at least 3\nRendered:\n%s", count, s)
	}
}

// TestSyncCustomMatcher covers a custom Matcher override, and custom TimeoutSecs across all
// hooks.
func TestSyncCustomMatcher(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	customMatcher := "MyCustomTool|AnotherTool"
	customTimeout := 20

	rendered, _, err := Sync(SyncOptions{
		SettingsPath: path,
		BinaryPath:   testBinary,
		Matcher:      customMatcher,
		TimeoutSecs:  customTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}

	s := string(rendered)
	// PreToolUse should have the custom matcher.
	if !strings.Contains(s, customMatcher) {
		t.Errorf("custom matcher not found in PreToolUse: %s", s)
	}

	// All hooks should use custom timeout.
	count := strings.Count(s, `"timeout": 20`)
	if count < 3 {
		t.Errorf("custom timeout not used: found %d occurrences, want at least 3", count)
	}
}

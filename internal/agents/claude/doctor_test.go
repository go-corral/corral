package claude

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/claude/claudecfg"
	"github.com/go-corral/corral/internal/agents/spec"
	"github.com/go-corral/corral/internal/health"
)

// TestClaudeDoctor exercises every branch of claude's settings.json readiness check: file
// absent, present without the corral hook, present with it, partial, and unreadable. claude's
// whole enforcement story is whether the hook is registered, so this is the load-bearing report.
func TestClaudeDoctor(t *testing.T) {
	claude := New()
	check := func(home, self string) health.Check {
		t.Helper()
		checks := claude.Doctor(spec.StatusInput{Home: home, Host: map[string]string{}, Self: self})
		if len(checks) != 1 || checks[0].Label != "hooks" {
			t.Fatalf("Doctor must return one hooks check; got %+v", checks)
		}
		return checks[0]
	}
	const fix = "corral sync claude"

	// Absent → not registered, naming the missing file.
	absent := t.TempDir()
	path := filepath.Join(absent, ".claude", "settings.json")
	want := health.Check{State: health.Warn, Label: "hooks", Value: "not registered", Reason: path + " not present", Fix: fix}
	if got := check(absent, ""); got != want {
		t.Errorf("absent settings.json: got %+v, want %+v", got, want)
	}

	// Present but no hook → not registered.
	noHook := t.TempDir()
	writeSettings(t, noHook, `{"foo":"bar"}`)
	want = health.Check{State: health.Warn, Label: "hooks", Value: "not registered", Reason: "claude runs unhooked unless started with corral run", Fix: fix}
	if got := check(noHook, ""); got != want {
		t.Errorf("settings without hook: got %+v, want %+v", got, want)
	}

	// Present with the corral hooks, asked about that binary → registered.
	withHook := t.TempDir()
	settings := filepath.Join(withHook, ".claude", "settings.json")
	const seedBinary = "/usr/local/bin/corral"
	if _, _, err := claudecfg.Sync(claudecfg.SyncOptions{SettingsPath: settings, BinaryPath: seedBinary}); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	want = health.Check{Label: "hooks", Value: "registered for this binary"}
	if got := check(withHook, seedBinary); got != want {
		t.Errorf("synced settings: got %+v, want %+v", got, want)
	}
	// Same file, but this corral is a different binary → stale, not registered.
	if got := check(withHook, "/opt/elsewhere/corral"); got.State != health.Warn || !strings.HasPrefix(got.Value, "stale for ") ||
		got.Reason != "an older shape, or a different corral binary" || got.Fix != fix {
		t.Errorf("registration naming another binary: got %+v, want a stale warning", got)
	}
	// An unguarded registration is stale even though it still runs.
	legacy := t.TempDir()
	writeSettings(t, legacy, `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"`+seedBinary+` hook pre-tool-use","timeout":10}]}]}}`)
	if got := check(legacy, ""); got.State != health.Warn || !strings.HasPrefix(got.Value, "stale for PreToolUse; missing for ") || got.Fix != fix {
		t.Errorf("legacy bare registration: got %+v, want a stale warning", got)
	}

	// Current for some events, missing for the rest → missing only, reason is the file.
	partial := t.TempDir()
	partialSettings := filepath.Join(partial, ".claude", "settings.json")
	if _, _, err := claudecfg.Sync(claudecfg.SyncOptions{SettingsPath: partialSettings, BinaryPath: seedBinary}); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	dropHook(t, partialSettings, "PreToolUse")
	want = health.Check{State: health.Warn, Label: "hooks", Value: "missing for PreToolUse", Reason: partialSettings, Fix: fix}
	if got := check(partial, seedBinary); got != want {
		t.Errorf("partial registration: got %+v, want %+v", got, want)
	}

	// Unreadable (a directory at the settings.json path) → unreadable, not a crash, no fix.
	unreadable := t.TempDir()
	if err := os.MkdirAll(filepath.Join(unreadable, ".claude", "settings.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := check(unreadable, ""); got.State != health.Warn || got.Value != "unreadable" || got.Reason == "" || got.Fix != "" {
		t.Errorf("unreadable settings.json: got %+v, want an unreadable warning", got)
	}
}

// dropHook deletes one event's hooks from a settings.json.
func dropHook(t *testing.T, path, event string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	delete(doc["hooks"], event)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeSettings writes raw bytes to <home>/.claude/settings.json, creating the dir.
func writeSettings(t *testing.T, home, content string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

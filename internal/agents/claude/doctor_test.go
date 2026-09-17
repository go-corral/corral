package claude

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/agents/claude/claudecfg"
	"github.com/go-corral/corral/internal/agents/spec"
)

// doctorStatuses flattens a DoctorReport into "label: status" lines so containsLine can assert on
// them.
func doctorStatuses(rep spec.DoctorReport) []string {
	out := make([]string, len(rep.Lines))
	for i, l := range rep.Lines {
		out[i] = l.Label + ": " + l.Status
	}
	return out
}

// TestClaudeDoctor exercises every branch of claude's settings.json readiness check: file
// absent, present without the corral hook, present with it, and unreadable. claude's whole
// enforcement story is whether the hook is registered, so this is the load-bearing report.
func TestClaudeDoctor(t *testing.T) {
	claude := New()
	report := func(home string) []string {
		return doctorStatuses(claude.Doctor(spec.StatusInput{Home: home, Host: map[string]string{}}))
	}

	// Absent → "not present".
	if got := report(t.TempDir()); !containsLine(got, "settings") || !containsLine(got, "not present") {
		t.Errorf("absent settings.json: got %v, want a settings/not-present line", got)
	}

	// Present but no hook → "not registered".
	noHook := t.TempDir()
	writeSettings(t, noHook, `{"foo":"bar"}`)
	if got := report(noHook); !containsLine(got, "NOT registered") {
		t.Errorf("settings without hook: got %v, want NOT-registered", got)
	}

	// Present with the corral hooks, asked about that binary → "registered".
	withHook := t.TempDir()
	settings := filepath.Join(withHook, ".claude", "settings.json")
	const seedBinary = "/usr/local/bin/corral"
	if _, _, err := claudecfg.Sync(claudecfg.SyncOptions{SettingsPath: settings, BinaryPath: seedBinary}); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	registered := doctorStatuses(claude.Doctor(spec.StatusInput{Home: withHook, Host: map[string]string{}, Self: seedBinary}))
	if !containsLine(registered, "registered") || containsLine(registered, "NOT registered") {
		t.Errorf("synced settings: got %v, want hooks-registered", registered)
	}
	// Same file, but this corral is a different binary → stale, not "registered".
	other := doctorStatuses(claude.Doctor(spec.StatusInput{Home: withHook, Host: map[string]string{}, Self: "/opt/elsewhere/corral"}))
	if !containsLine(other, "stale") {
		t.Errorf("registration naming another binary: got %v, want a stale report", other)
	}
	// An unguarded registration is stale even though it still runs.
	legacy := t.TempDir()
	writeSettings(t, legacy, `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"`+seedBinary+` hook pre-tool-use","timeout":10}]}]}}`)
	if got := report(legacy); !containsLine(got, "stale") {
		t.Errorf("legacy bare registration: got %v, want a stale report", got)
	}

	// Unreadable (a directory at the settings.json path) → "unreadable", not a crash.
	unreadable := t.TempDir()
	if err := os.MkdirAll(filepath.Join(unreadable, ".claude", "settings.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := report(unreadable); !containsLine(got, "unreadable") {
		t.Errorf("unreadable settings.json: got %v, want an unreadable status", got)
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

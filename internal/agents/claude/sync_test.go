package claude

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/claude/claudecfg"
	"github.com/go-corral/corral/internal/agents/spec"
)

// TestClaudeSyncRegistersHook pins claude's Sync: a fresh settings.json is created with the hook
// (a real change → a diff), and a second run is up to date.
func TestClaudeSyncRegistersHook(t *testing.T) {
	home := t.TempDir()
	a := New()
	in := spec.SyncInput{Home: home, Host: map[string]string{}, BinaryPath: "/usr/local/bin/corral"}

	rep, err := a.Sync(in)
	if err != nil {
		t.Fatalf("claude Sync: %v", err)
	}
	if rep.Diff == nil {
		t.Errorf("claude Sync on a fresh file should produce a diff to render")
	}
	data, err := os.ReadFile(filepath.Join(home, ".claude", "settings.json"))
	if err != nil {
		t.Fatalf("claude Sync should write settings.json: %v", err)
	}
	if !strings.Contains(string(data), "hook pre-tool-use") {
		t.Errorf("claude Sync should register the corral hook:\n%s", data)
	}

	rep, err = a.Sync(in)
	if err != nil {
		t.Fatalf("claude Sync (2nd): %v", err)
	}
	if rep.Diff != nil {
		t.Errorf("claude Sync (2nd) should be up to date, got a diff")
	}
	if !containsLine(rep.Messages, "already up to date") {
		t.Errorf("claude Sync (2nd) messages = %v, want already-up-to-date", rep.Messages)
	}
}

// TestClaudeLaunchWarningsSyncState pins claude's settings-sync advisory: it fires exactly when
// settings.json does not register corral's hooks in the current shape for this binary (missing
// or stale) and stays silent when it does. Reformatting cannot affect it — the check parses the
// registration rather than diffing bytes. The fullscreen-banner warning rides in the same
// LaunchWarnings result, so each case asserts the sync warning by substring rather than total
// emptiness.
func TestClaudeLaunchWarningsSyncState(t *testing.T) {
	home := t.TempDir()
	claude := New()
	settings := filepath.Join(home, ".claude", "settings.json")
	bin := "/usr/local/bin/corral"
	warns := func(self string) []string {
		return checkValues(claude.LaunchWarnings(spec.StatusInput{Home: home, Host: map[string]string{}, Self: self}))
	}

	// Missing settings.json → unregistered.
	if !containsLine(warns(bin), "not registered for this binary") {
		t.Error("missing settings.json should warn (hooks not registered)")
	}
	// Seed a fully-synced file → silent.
	if _, _, err := claudecfg.Sync(claudecfg.SyncOptions{SettingsPath: settings, BinaryPath: bin}); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	if containsLine(warns(bin), "not registered for this binary") {
		t.Error("a synced settings.json must not warn about registration")
	}
	// A pure reformat (whitespace/key order) is no policy change → still silent.
	reindent(t, settings)
	if containsLine(warns(bin), "not registered for this binary") {
		t.Error("a reformat-only difference must not warn about registration")
	}
	// A registration naming a different corral is stale → warn again.
	if !containsLine(warns("/some/other/path/corral"), "not registered for this binary") {
		t.Error("a re-pointed hook binary should warn (stale registration)")
	}
	// Best-effort: an empty Self omits the check (no binary to compare against).
	if containsLine(warns(""), "not registered for this binary") {
		t.Error("empty Self must yield no registration warning")
	}
}

// TestClaudeSyncDryRun pins claude's Sync preview paths: a dry-run never writes, and reports the
// right headline for each of the three states — a real policy change (with a diff), an
// already-synced file, and a reformat-only difference.
func TestClaudeSyncDryRun(t *testing.T) {
	claude := New()
	bin := "/usr/local/bin/corral"

	// Fresh file: a dry-run would register the hook (a real change → a diff) but write nothing.
	fresh := t.TempDir()
	rep, err := claude.Sync(spec.SyncInput{Home: fresh, Host: map[string]string{}, BinaryPath: bin, DryRun: true})
	if err != nil {
		t.Fatalf("claude Sync dry-run: %v", err)
	}
	if !containsLine(rep.Messages, "would change (dry-run, not written)") {
		t.Errorf("fresh dry-run messages = %v, want a would-change line", rep.Messages)
	}
	if rep.Diff == nil {
		t.Error("fresh dry-run should still produce a diff to preview")
	}
	if _, err := os.Stat(filepath.Join(fresh, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("dry-run must not write settings.json (stat err = %v)", err)
	}

	// Already synced: a dry-run reports up-to-date with no changes.
	synced := t.TempDir()
	settings := filepath.Join(synced, ".claude", "settings.json")
	if _, _, err := claudecfg.Sync(claudecfg.SyncOptions{SettingsPath: settings, BinaryPath: bin}); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	rep, err = claude.Sync(spec.SyncInput{Home: synced, Host: map[string]string{}, BinaryPath: bin, DryRun: true})
	if err != nil {
		t.Fatalf("claude Sync dry-run (synced): %v", err)
	}
	if !containsLine(rep.Messages, "already up to date — no changes") || rep.Diff != nil {
		t.Errorf("synced dry-run = %v (diff=%v), want up-to-date and no diff", rep.Messages, rep.Diff)
	}

	// Reformat-only: cosmetic reindent is no policy change.
	reindent(t, settings)
	rep, err = claude.Sync(spec.SyncInput{Home: synced, Host: map[string]string{}, BinaryPath: bin, DryRun: true})
	if err != nil {
		t.Fatalf("claude Sync dry-run (reformat): %v", err)
	}
	if !containsLine(rep.Messages, "would only be reformatted") || rep.Diff != nil {
		t.Errorf("reformat-only dry-run = %v (diff=%v), want reformat-only and no diff", rep.Messages, rep.Diff)
	}
}

// TestClaudeSyncRemove pins claude's de-registration reporting, which has three distinct answers
// the user must be able to tell apart: no settings.json at all, a settings.json holding nothing of
// corral's, and a real removal (the only case with a diff). It also checks the file-level
// outcomes: nothing is ever created, and the corral hooks are actually gone.
func TestClaudeSyncRemove(t *testing.T) {
	claude := New()
	bin := "/usr/local/bin/corral"

	// No settings.json: nothing to remove, and removal must not create the file.
	absent := t.TempDir()
	rep, err := claude.Sync(spec.SyncInput{Home: absent, Host: map[string]string{}, Remove: true})
	if err != nil {
		t.Fatalf("claude Sync --remove (absent): %v", err)
	}
	if !containsLine(rep.Messages, "not present — nothing to remove") || rep.Diff != nil {
		t.Errorf("absent removal = %v (diff=%v), want not-present and no diff", rep.Messages, rep.Diff)
	}
	if _, err := os.Stat(filepath.Join(absent, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Errorf("removal must not create settings.json (stat err = %v)", err)
	}

	// A settings.json with only the user's own hooks: nothing of corral's to remove.
	foreign := t.TempDir()
	settings := filepath.Join(foreign, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	userOnly := `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/audit.sh"}]}]}}`
	if err := os.WriteFile(settings, []byte(userOnly), 0o644); err != nil {
		t.Fatal(err)
	}
	rep, err = claude.Sync(spec.SyncInput{Home: foreign, Host: map[string]string{}, Remove: true})
	if err != nil {
		t.Fatalf("claude Sync --remove (no corral hooks): %v", err)
	}
	if !containsLine(rep.Messages, "no corral hooks in") || rep.Diff != nil {
		t.Errorf("hookless removal = %v (diff=%v), want nothing-to-remove and no diff", rep.Messages, rep.Diff)
	}
	if after, _ := os.ReadFile(settings); string(after) != userOnly {
		t.Errorf("a removal with nothing to strip must leave the file byte-identical, got:\n%s", after)
	}

	// A registered settings.json: the removal is reported with the summary headline and a diff,
	// and the hooks are gone from disk.
	home := t.TempDir()
	registered := filepath.Join(home, ".claude", "settings.json")
	in := spec.SyncInput{Home: home, Host: map[string]string{}, BinaryPath: bin}
	if _, err := claude.Sync(in); err != nil {
		t.Fatalf("seed sync: %v", err)
	}

	// Dry-run first: it reports the same change but must not touch the file.
	before, err := os.ReadFile(registered)
	if err != nil {
		t.Fatal(err)
	}
	rep, err = claude.Sync(spec.SyncInput{Home: home, Host: map[string]string{}, Remove: true, DryRun: true})
	if err != nil {
		t.Fatalf("claude Sync --remove --dry-run: %v", err)
	}
	if !containsLine(rep.Messages, "would change (dry-run, not written)") || !containsLine(rep.Messages, "removed hooks: PreToolUse") {
		t.Errorf("dry-run removal = %v, want a would-change line naming the removed hooks", rep.Messages)
	}
	if rep.Diff == nil {
		t.Fatal("dry-run removal should produce a diff to preview")
	}
	if rep.Diff.ToLabel != registered+" (after removal)" {
		t.Errorf("diff ToLabel = %q, want the after-removal label", rep.Diff.ToLabel)
	}
	if after, _ := os.ReadFile(registered); string(after) != string(before) {
		t.Error("dry-run removal must not rewrite settings.json")
	}

	// Real run: the same headline, and the hooks actually go.
	rep, err = claude.Sync(spec.SyncInput{Home: home, Host: map[string]string{}, Remove: true})
	if err != nil {
		t.Fatalf("claude Sync --remove: %v", err)
	}
	if !containsLine(rep.Messages, "updated "+registered) || !containsLine(rep.Messages, "removed hooks: PreToolUse") {
		t.Errorf("removal messages = %v, want an updated line naming the removed hooks", rep.Messages)
	}
	if rep.Diff == nil {
		t.Error("a real removal should produce a diff to render")
	}
	data, err := os.ReadFile(registered)
	if err != nil {
		t.Fatalf("removal must not delete settings.json: %v", err)
	}
	if strings.Contains(string(data), "hook pre-tool-use") {
		t.Errorf("corral's hook survived the removal:\n%s", data)
	}

	// Doctor's reporting is unchanged by removal — it simply sees an unregistered file again,
	// which is exactly the state `corral sync` fixes.
	doc := claude.Doctor(spec.StatusInput{Home: home, Host: map[string]string{}, Self: bin})
	if len(doc) == 0 || doc[0].Value != "not registered" || doc[0].Fix != "corral sync claude" {
		t.Errorf("after a removal doctor should report not registered, got %+v", doc)
	}
}

// reindent rewrites settings to 4-space indent: byte-different, semantically identical to
// corral's 2-space output — the formatting churn the sync state should treat as no change.
func reindent(t *testing.T, settings string) {
	t.Helper()
	orig, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, orig, "", "    "); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, append(buf.Bytes(), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

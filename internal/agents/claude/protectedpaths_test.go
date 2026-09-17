package claude

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

// TestProtectedPaths covers claude's hook-script self-protection discovery: all three merged
// settings files are read, corral's own entries are filtered, and paths are returned raw —
// de-duplication across files is deliberately the caller's job.
func TestProtectedPaths(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// settings.json: one non-corral hook plus corral's own entry (filtered out).
	write("settings.json", `{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
		{"type":"command","command":"/opt/guard/a.sh --strict"},
		{"type":"command","command":"/opt/corral/bin/corral hook pre-tool-use"}
	]}]}}`)
	// settings.local.json: a fresh hook and a duplicate of a.sh — the duplicate survives here
	// because ProtectedPaths returns paths raw (the caller canonicalizes and dedups).
	write("settings.local.json", `{"hooks":{"SessionStart":[{"hooks":[
		{"type":"command","command":"/opt/guard/b.sh"},
		{"type":"command","command":"/opt/guard/a.sh --strict"}
	]}]}}`)
	// managed-settings.json intentionally absent: a missing file degrades to nothing.

	got := New().ProtectedPaths(dir)
	sort.Strings(got)
	want := []string{"/opt/guard/a.sh", "/opt/guard/a.sh", "/opt/guard/b.sh"}
	if !slices.Equal(got, want) {
		t.Errorf("ProtectedPaths = %v, want %v (all three files read; corral entry filtered; raw, un-deduped across files)", got, want)
	}
}

// TestProtectedPathsDegrades asserts the best-effort contract: an empty configDir and a dir with
// no readable settings both yield no paths (the static self-protect rules still stand).
func TestProtectedPathsDegrades(t *testing.T) {
	if got := New().ProtectedPaths(""); got != nil {
		t.Errorf("ProtectedPaths(\"\") = %v, want nil", got)
	}
	if got := New().ProtectedPaths(t.TempDir()); len(got) != 0 {
		t.Errorf("ProtectedPaths(empty dir) = %v, want none (no settings files to read)", got)
	}
}

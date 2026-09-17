package claudecfg

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CanonicalBaseline runs a file through the same serializer as a real sync but adds
// nothing, so re-indenting a synced file and canonicalizing it reproduces the synced
// output byte-for-byte. This is the property that lets `corral sync` diff against a
// canonical baseline and show only real changes — pure reformatting cancels out.
func TestCanonicalBaselineCancelsReindent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// Seed an existing permissions block so the round-trip exercises a preserved key, then
	// sync (which registers hooks and leaves permissions untouched).
	pre := `{"permissions":{"deny":["Read(/custom/**)"]}}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}

	// Re-indent the synced output to 4 spaces: same JSON, different bytes, key order
	// untouched (json.Indent only rewrites whitespace).
	var buf bytes.Buffer
	if err := json.Indent(&buf, rendered, "", "    "); err != nil {
		t.Fatal(err)
	}
	reindented := append(buf.Bytes(), '\n')
	if bytes.Equal(reindented, rendered) {
		t.Fatal("re-indent produced identical bytes; test is moot")
	}

	base, err := CanonicalBaseline(reindented)
	if err != nil {
		t.Fatal(err)
	}
	if string(base) != string(rendered) {
		t.Errorf("canonical baseline of a re-indented sync should equal the synced output\n--- baseline ---\n%s\n--- rendered ---\n%s", base, rendered)
	}
}

// Top-level key order must not survive into the canonical form: two inputs that differ
// only in key order canonicalize to identical bytes (so a re-order shows as no diff).
func TestCanonicalBaselineCancelsKeyReorder(t *testing.T) {
	a := []byte(`{"model":"opus","env":{"X":"1"}}`)
	b := []byte(`{"env":{"X":"1"},"model":"opus"}`)
	ca, err := CanonicalBaseline(a)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := CanonicalBaseline(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca) != string(cb) {
		t.Errorf("differing key order should canonicalize identically:\n--- a ---\n%s\n--- b ---\n%s", ca, cb)
	}
}

// CanonicalBaseline must not add corral's hooks — it is the "before" side of the diff,
// representing the current config without corral's contribution.
func TestCanonicalBaselineAddsNoCorralHooks(t *testing.T) {
	base, err := CanonicalBaseline([]byte(`{"model":"opus"}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(base), hookSubcommand) {
		t.Errorf("baseline must not contain corral hooks:\n%s", base)
	}
}

// A fresh sync registers all four corral hooks.
func TestSummarizeSyncFreshRegistersAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	rendered, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	s, err := SummarizeSync(nil, rendered) // baseline of an empty (new) file
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Hooks) != 4 {
		t.Fatalf("expected 4 hook changes, got %d (%v)", len(s.Hooks), s.Hooks)
	}
	for _, h := range s.Hooks {
		if h.Update {
			t.Errorf("fresh sync should register (not update) %s", h.Event)
		}
	}
	if s.Empty() {
		t.Error("a fresh sync summary must not be empty")
	}
	if !strings.Contains(s.String(), "registered hooks: PreToolUse") {
		t.Errorf("headline missing registration: %q", s.String())
	}
}

// Re-pointing the binary path is an update (not a fresh registration).
func TestSummarizeSyncRepointIsUpdate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	first, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/old/bin/corral"})
	if err != nil {
		t.Fatal(err)
	}
	base, err := CanonicalBaseline(first)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := render(first, renderAdd, "/new/bin/corral", DefaultMatcher, DefaultTimeoutSecs)
	if err != nil {
		t.Fatal(err)
	}
	s, err := SummarizeSync(base, second)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Hooks) != 4 {
		t.Fatalf("expected 4 updated hooks, got %d (%v)", len(s.Hooks), s.Hooks)
	}
	for _, h := range s.Hooks {
		if !h.Update {
			t.Errorf("re-point should mark %s as updated, not registered", h.Event)
		}
	}
	if !strings.Contains(s.String(), "updated hooks:") {
		t.Errorf("headline should say updated: %q", s.String())
	}
}

// A removal is summarized from the same two renderings as a registration, with the sides'
// roles reversed: the canonical baseline still holds corral's entries, the stripped output no
// longer does, so every event reports as Removed and the headline says so.
func TestSummarizeSyncRemovalReportsRemoved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	synced, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	base, err := CanonicalBaseline(synced)
	if err != nil {
		t.Fatal(err)
	}
	stripped, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("removal should have stripped the registration")
	}
	s, err := SummarizeSync(base, stripped)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Hooks) != 4 {
		t.Fatalf("expected 4 removed hooks, got %d (%v)", len(s.Hooks), s.Hooks)
	}
	for _, h := range s.Hooks {
		if !h.Removed {
			t.Errorf("removal should mark %s as removed, got %+v", h.Event, h)
		}
		if h.Update {
			t.Errorf("a removed hook is not an update: %+v", h)
		}
	}
	if s.Empty() {
		t.Error("a removal summary must not be empty")
	}
	want := "removed hooks: PreToolUse, PostToolUse, SessionStart, UserPromptSubmit"
	if got := s.String(); got != want {
		t.Errorf("headline = %q, want %q", got, want)
	}
}

// A summary over two settings that hold no corral hooks at all is empty in both directions —
// the "nothing to remove" state, which must not be mistaken for a change.
func TestSummarizeSyncNoCorralHooksEitherSide(t *testing.T) {
	hookless := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/audit.sh"}]}]}}`)
	base, err := CanonicalBaseline(hookless)
	if err != nil {
		t.Fatal(err)
	}
	s, err := SummarizeSync(base, base)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Empty() {
		t.Errorf("no corral hooks on either side should summarize empty, got %v", s.Hooks)
	}
	if s.String() != "" {
		t.Errorf("empty summary should render no headline, got %q", s.String())
	}
}

// A no-op re-sync summarizes empty, and canonical(rendered) == rendered (the baseline is
// idempotent on render's own output — the invariant that makes reformat-only detectable).
func TestSummarizeSyncNoChangeIsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	rendered, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	base, err := CanonicalBaseline(rendered)
	if err != nil {
		t.Fatal(err)
	}
	if string(base) != string(rendered) {
		t.Fatalf("canonical(rendered) must equal rendered\n--- base ---\n%s\n--- rendered ---\n%s", base, rendered)
	}
	s, err := SummarizeSync(base, rendered)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Empty() {
		t.Errorf("a no-op re-sync should summarize empty, got hooks=%v", s.Hooks)
	}
}

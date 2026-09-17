package aiignore

import (
	"context"
	"encoding/json"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers/spec"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeIgnoreFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Discovery walks up from a subdir, reads both .aiignore and .aiexclude, and strips
// comments/blank lines.
func TestDiscoverAIIgnoreWalksUp(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "# comment\n\nsecrets.env\n*.pem\n")
	writeIgnoreFile(t, filepath.Join(repo, ".aiexclude"), "build/\n")
	sub := filepath.Join(repo, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	ai := Discover(sub, []string{".aiignore", ".aiexclude"})
	if ai.Root == "" {
		t.Fatal("expected to discover ignore files by walking up")
	}
	if len(ai.Patterns) != 3 {
		t.Errorf("patterns = %v, want 3 (secrets.env, *.pem, build/)", ai.Patterns)
	}
	if len(ai.Files) != 2 {
		t.Errorf("want both ignore files discovered, got %v", ai.Files)
	}
	// Both defaults are native, so both are self-protected.
	if len(ai.ProtectFiles) != 2 {
		t.Errorf("want both native sources self-protected, got %v", ai.ProtectFiles)
	}
}

// The upward search stops at the repo boundary (a .git dir): an .aiignore above the repo
// must not be picked up.
func TestDiscoverAIIgnoreStopsAtRepoBoundary(t *testing.T) {
	outer := t.TempDir()
	writeIgnoreFile(t, filepath.Join(outer, ".aiignore"), "secret\n")
	repo := filepath.Join(outer, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(repo, "x")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}

	if ai := Discover(sub, []string{".aiignore", ".aiexclude"}); ai.Root != "" || len(ai.Patterns) != 0 {
		t.Errorf(".git boundary must stop the search before the outer .aiignore; got root=%q patterns=%v", ai.Root, ai.Patterns)
	}
}

// Configurable sources: an extra source (e.g. .gitignore) is discovered and its patterns
// enforced, but it is borrowed — present in files (so it is masked/enforced) yet absent
// from protectFiles, so the agent stays free to edit it. Native sources are protected.
func TestDiscoverAIIgnoreConfigurableSources(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "secrets.env\n")
	writeIgnoreFile(t, filepath.Join(repo, ".gitignore"), "node_modules\n!keep.txt\n")

	ai := Discover(repo, []string{".aiignore", ".aiexclude", ".gitignore"})
	if !containsSuffix(ai.Patterns, "node_modules") || !containsSuffix(ai.Patterns, "secrets.env") {
		t.Errorf("expected patterns from both .aiignore and the borrowed .gitignore, got %v", ai.Patterns)
	}
	if len(ai.Files) != 2 {
		t.Fatalf("want .aiignore + .gitignore discovered, got %v", ai.Files)
	}
	// .gitignore is borrowed → not self-protected; .aiignore is native → protected.
	if len(ai.ProtectFiles) != 1 || filepath.Base(ai.ProtectFiles[0]) != ".aiignore" {
		t.Errorf("only the native .aiignore should be self-protected, got %v", ai.ProtectFiles)
	}
	// The borrowed .gitignore carries a "!" negation corral drops → over-block warning fires.
	if n := NegationCount(ai.Patterns); n != 1 {
		t.Errorf("negation count = %d, want 1 (the !keep.txt in .gitignore)", n)
	}
}

func containsSuffix(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// The launch-time mask splits matches by kind: directories ride spec.BlockedPaths
// (tmpfs/subpath) and files ride spec.BlockedFiles (stub bind / literal deny). A file
// already covered by a matched ancestor directory is not returned separately.
func TestAIIgnoreConcreteMasksSplitsDirsAndFiles(t *testing.T) {
	repo := t.TempDir()
	root, err := policy.CanonicalizeRoot(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeIgnoreFile(t, filepath.Join(repo, "cert.pem"), "x")
	// A .pem inside the masked node_modules dir must not also appear as a file (the whole
	// dir subtree is already masked; the walk skips into it).
	writeIgnoreFile(t, filepath.Join(repo, "node_modules", "inner.pem"), "x")

	dirs, files := ConcreteMasks(root, []string{"node_modules", "*.pem"})
	if len(dirs) != 1 || filepath.Base(dirs[0]) != "node_modules" {
		t.Fatalf("want exactly the node_modules directory masked, got %v", dirs)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "cert.pem" {
		t.Fatalf("want exactly cert.pem masked as a file (inner.pem covered by the dir), got %v", files)
	}
}

// Hook/launcher parity: every path the launcher FS-masks (matched dirs + files) must also
// be denied by the hook matcher, so the FS mask and the hook can never disagree about an
// aiignore-excluded path. The hook may deny more (e.g. paths created after launch) but must
// never deny less than the mask hides — both run policy.MatchAIIgnore over the same patterns.
func TestAIIgnoreMaskHookParity(t *testing.T) {
	repo := t.TempDir()
	root, err := policy.CanonicalizeRoot(repo, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join("node_modules", "pkg"), "src"} {
		if err := os.MkdirAll(filepath.Join(repo, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeIgnoreFile(t, filepath.Join(repo, "cert.pem"), "x")
	writeIgnoreFile(t, filepath.Join(repo, "src", "key.pem"), "x")
	writeIgnoreFile(t, filepath.Join(repo, "src", "main.go"), "x") // not ignored

	patterns := []string{"node_modules", "*.pem"}
	dirs, files := ConcreteMasks(root, patterns)
	if len(dirs) == 0 || len(files) == 0 {
		t.Fatalf("expected both dirs and files masked, got dirs=%v files=%v", dirs, files)
	}
	for _, p := range append(append([]string{}, dirs...), files...) {
		if _, hit := policy.MatchAIIgnore(root, p, patterns); !hit {
			t.Errorf("launcher masks %q but the hook matcher does NOT deny it (parity broken)", p)
		}
	}
	// A non-ignored file must be neither masked nor hook-denied.
	if _, hit := policy.MatchAIIgnore(root, filepath.Join(root, "src", "main.go"), patterns); hit {
		t.Errorf("hook denies a non-ignored file src/main.go")
	}
}

// The discovered ignore files are self-protected: a Write/Edit to .aiignore is denied via
// policy's self-protect extra-paths seam, so the agent cannot edit away its own exclusions.
func TestAIIgnoreFilesSelfProtected(t *testing.T) {
	repo := t.TempDir()
	f := filepath.Join(repo, ".aiignore")
	writeIgnoreFile(t, f, "secrets.env\n")

	prot := ProtectedPaths([]string{f})
	canon, err := policy.CanonicalizeRoot(f, "")
	if err != nil {
		t.Fatal(err)
	}
	if prot[canon] != "a repo AI ignore file" {
		t.Fatalf("ignore file not registered as protected: %v", prot)
	}

	pp := &policy.PathPatternRule{ExtraProtectedPaths: prot}
	ti, _ := json.Marshal(map[string]string{"file_path": f, "content": "secrets.env\n!keep\n"})
	d, matched, err := pp.Evaluate(&policy.HookEvent{ToolName: "Write", ToolInput: ti})
	if err != nil || !matched || d.Action != policy.Deny {
		t.Errorf("Write to .aiignore must be denied (self-protect); matched=%v action=%v err=%v", matched, d.Action, err)
	}
}

func TestParseIgnoreLines(t *testing.T) {
	got := parseIgnoreLines([]byte("# c\n\n  secrets.env  \r\n*.key\n"))
	want := []string{"secrets.env", "*.key"}
	if len(got) != len(want) {
		t.Fatalf("parseIgnoreLines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// --- the built-in provider (Mint contract) ---

func TestProviderMintContributesMasksAndNote(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "secrets/\n")
	if err := os.MkdirAll(filepath.Join(repo, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}

	c, err := New([]string{".aiignore", ".aiexclude"}).Mint(context.Background(), spec.Session{WorkDir: repo}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || len(c.BlockedDirs) != 1 || filepath.Base(c.BlockedDirs[0]) != "secrets" {
		t.Fatalf("expected the matched dir in BlockedDirs, got %+v", c)
	}
	if len(c.Status) == 0 || !strings.Contains(c.Status[0], "1 pattern(s)") {
		t.Errorf("Status = %v", c.Status)
	}
	// The Status line is the operator's only view of what aiignore masked (the
	// banner's blocked line lists config blocks only), so it must name the paths.
	// Match on the suffix: Discover canonicalizes the root (macOS /var -> /private/var).
	if len(c.Status) > 0 && !strings.Contains(c.Status[0], string(filepath.Separator)+"secrets") {
		t.Errorf("Status must name the masked path, got %v", c.Status)
	}
	if len(c.AgentNotes) != 1 || !strings.Contains(c.AgentNotes[0], "repo AI-ignore is active") {
		t.Errorf("AgentNotes = %v", c.AgentNotes)
	}
}

// No discovered sources → nil contribution (the provider stays silent, no note).
func TestProviderMintNilWithoutSources(t *testing.T) {
	repo := t.TempDir()
	// .git marks the repo boundary so the walk cannot escape into the host tree.
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	c, err := New([]string{".aiignore"}).Mint(context.Background(), spec.Session{WorkDir: repo}, false)
	if err != nil || c != nil {
		t.Fatalf("no sources must contribute nothing: c=%+v err=%v", c, err)
	}
}

// Mint is pure: dryRun and real return identical contributions (the built-in
// contract that allows pre-gate resolution).
func TestProviderMintDryRunIdentical(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "!keep\nvault/\n")
	p := New([]string{".aiignore"})
	real, err := p.Mint(context.Background(), spec.Session{WorkDir: repo}, false)
	if err != nil {
		t.Fatal(err)
	}
	dry, err := p.Mint(context.Background(), spec.Session{WorkDir: repo}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(real, dry) {
		t.Errorf("dry-run must equal real: %+v vs %+v", real, dry)
	}
	// The "!" negation is surfaced as a status line (warn-and-allow, over-mask risk).
	found := false
	for _, l := range real.Status {
		if strings.Contains(l, `"!" re-include`) {
			found = true
		}
	}
	if !found {
		t.Errorf("negation status line missing: %v", real.Status)
	}
}

// EffectiveSources falls back to the built-in defaults for a hand-built Config that never
// loaded internal/config's defaultsYAML.
func TestEffectiveSourcesFallback(t *testing.T) {
	got := Config{}.EffectiveSources()
	if len(got) != 2 || got[0] != ".aiignore" || got[1] != ".aiexclude" {
		t.Errorf("EffectiveSources fallback = %v, want the built-in defaults", got)
	}
	if got := (Config{Sources: []string{".gitignore"}}).EffectiveSources(); len(got) != 1 || got[0] != ".gitignore" {
		t.Errorf("configured sources must win: %v", got)
	}
}

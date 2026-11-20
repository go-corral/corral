package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The minimal gitignore-flavored matcher: bare names match at any depth (and their
// subtree), an embedded/leading slash anchors to the repo root, * and ? apply within a
// segment, ** spans segments, and a path outside the root never matches.
func TestMatchAIIgnore(t *testing.T) {
	const root = "/repo"
	cases := []struct {
		name     string
		patterns []string
		path     string
		want     bool
	}{
		{"basename at any depth", []string{"secrets.env"}, "/repo/a/b/secrets.env", true},
		{"basename at root", []string{"secrets.env"}, "/repo/secrets.env", true},
		{"basename no partial match", []string{"secrets.env"}, "/repo/mysecrets.env", false},
		{"glob extension", []string{"*.pem"}, "/repo/certs/key.pem", true},
		{"glob extension non-match", []string{"*.pem"}, "/repo/certs/key.pemx", false},
		{"anchored top-level only", []string{"/config"}, "/repo/config", true},
		{"anchored not nested", []string{"/config"}, "/repo/sub/config", false},
		{"embedded slash anchors", []string{"build/out"}, "/repo/build/out/app", true},
		{"embedded slash not deep", []string{"build/out"}, "/repo/sub/build/out", false},
		{"directory subtree", []string{"node_modules"}, "/repo/a/node_modules/x/y", true},
		{"trailing slash dir", []string{"dist/"}, "/repo/dist/app.js", true},
		{"globstar suffix", []string{"**/secret"}, "/repo/a/b/secret", true},
		{"globstar prefix", []string{"secrets/**"}, "/repo/secrets/deep/k", true},
		{"question mark", []string{"key?.pem"}, "/repo/key1.pem", true},
		{"outside the repo", []string{"secrets.env"}, "/etc/secrets.env", false},
		{"negation unsupported (ignored)", []string{"!keep.env"}, "/repo/keep.env", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := MatchAIIgnore(root, tc.path, tc.patterns); got != tc.want {
				t.Errorf("MatchAIIgnore(%q, %v) = %v, want %v", tc.path, tc.patterns, got, tc.want)
			}
		})
	}
}

// The `**` segment consumes zero or more whole segments, so a run of them means exactly
// the same as one; `*`/`?`/character classes stay inside a segment; and a malformed glob
// segment matches nothing rather than panicking or matching everything.
func TestMatchAIIgnoreGlobstarSemantics(t *testing.T) {
	const root = "/repo"
	cases := []struct {
		name     string
		patterns []string
		path     string
		want     bool
	}{
		{"consecutive globstars consume zero", []string{"a/**/**/b"}, "/repo/a/b", true},
		{"consecutive globstars consume one", []string{"a/**/**/b"}, "/repo/a/x/b", true},
		{"consecutive globstars consume many", []string{"a/**/**/b"}, "/repo/a/x/y/b", true},
		{"consecutive globstars still need the tail", []string{"a/**/**/b"}, "/repo/a/x/y/c", false},
		{"leading globstar run", []string{"**/**/**/k"}, "/repo/a/b/c/k", true},
		{"single globstar consumes zero", []string{"a/**/b"}, "/repo/a/b", true},
		{"trailing globstar consumes zero", []string{"a/**"}, "/repo/a", true},
		{"globstar with glob tail", []string{"**/*.pem"}, "/repo/a/b/key.pem", true},
		{"globstar with question tail", []string{"**/key?.pem"}, "/repo/a/key1.pem", true},
		{"question needs exactly one char", []string{"**/key?.pem"}, "/repo/a/key.pem", false},
		{"globstar with character class", []string{"src/**/[abc]?.go"}, "/repo/src/x/y/a1.go", true},
		{"character class excludes", []string{"src/**/[abc]?.go"}, "/repo/src/x/y/z1.go", false},
		{"star does not cross a separator", []string{"/x*y"}, "/repo/xa/by", false},
		{"globstar does not split a segment", []string{"a/**/b"}, "/repo/a/xby", false},
		{"malformed class matches nothing", []string{"**/[a"}, "/repo/sub/[a", false},
		{"malformed class after globstar run", []string{"a/**/**/[z-"}, "/repo/a/b/[z-", false},
		{"malformed segment does not block the rest", []string{"[a", "real.env"}, "/repo/real.env", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := MatchAIIgnore(root, tc.path, tc.patterns); got != tc.want {
				t.Errorf("MatchAIIgnore(%q, %v) = %v, want %v", tc.path, tc.patterns, got, tc.want)
			}
		})
	}
}

// A repo-supplied pattern must not be able to stall the matcher: the hook runs it on
// every tool call and the launcher runs it once per walked file (up to WalkCap). The
// original recursion was exponential in the number of `**` segments — the first case
// below took ~27s. The bound is deliberately generous: this is a blowup detector, not a
// benchmark.
func TestMatchAIIgnoreNoBacktrackingBlowup(t *testing.T) {
	deepPath := "/repo/" + strings.TrimSuffix(strings.Repeat("a/", 30), "/")
	cases := []struct {
		name    string
		pattern string
	}{
		{"consecutive globstars", strings.Repeat("**/", 10) + "x"},
		{"globstars split by literals", strings.Repeat("**/a/", 10) + "x"},
		{"globstars split by wildcards", strings.Repeat("**/*/", 10) + "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			if _, hit := MatchAIIgnore("/repo", deepPath, []string{tc.pattern}); hit {
				t.Fatalf("pattern %q must not match %q", tc.pattern, deepPath)
			}
			if elapsed := time.Since(start); elapsed > 2*time.Second {
				t.Errorf("matching %q against a depth-30 path took %v, want well under 2s", tc.pattern, elapsed)
			}
		})
	}
}

// AIIgnoreRule denies a tool call touching an excluded path (built-in tools here), allows
// the rest, ignores paths outside the repo, and is a no-op when no ignore file was found.
func TestAIIgnoreRuleEvaluate(t *testing.T) {
	r := &AIIgnoreRule{Root: "/repo", Patterns: []string{"secrets.env", "config/prod/"}}

	if d, matched, err := r.Evaluate(toolEvent(t, "Read", map[string]any{"file_path": "/repo/sub/secrets.env"})); err != nil || !matched || d.Action != Deny {
		t.Errorf("excluded file must be denied; matched=%v action=%v err=%v", matched, d.Action, err)
	}
	if d, matched, _ := r.Evaluate(toolEvent(t, "Write", map[string]any{"file_path": "/repo/config/prod/db.yaml", "content": "x"})); !matched || d.Action != Deny {
		t.Errorf("file under an excluded directory must be denied")
	}
	if _, matched, err := r.Evaluate(toolEvent(t, "Read", map[string]any{"file_path": "/repo/src/main.go"})); err != nil || matched {
		t.Errorf("non-excluded file must be allowed; matched=%v err=%v", matched, err)
	}
	if _, matched, _ := r.Evaluate(toolEvent(t, "Read", map[string]any{"file_path": "/etc/hosts"})); matched {
		t.Errorf("a path outside the repo must not match an ai-ignore rule")
	}
	if _, matched, _ := (&AIIgnoreRule{}).Evaluate(toolEvent(t, "Read", map[string]any{"file_path": "/repo/secrets.env"})); matched {
		t.Errorf("an empty-root rule must be a no-op")
	}
}

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

	ai := DiscoverAIIgnore(sub, []string{".aiignore", ".aiexclude"})
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

	if ai := DiscoverAIIgnore(sub, []string{".aiignore", ".aiexclude"}); ai.Root != "" || len(ai.Patterns) != 0 {
		t.Errorf(".git boundary must stop the search before the outer .aiignore; got root=%q patterns=%v", ai.Root, ai.Patterns)
	}
}

// Configurable sources: an extra source (e.g. .gitignore) is discovered and its patterns
// enforced, but it is borrowed — present in files (so it is masked/enforced) yet absent
// from protectFiles, so the agent stays free to edit it. Native sources are protected.
func TestDiscoverAIIgnoreConfigurableSources(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "secrets.env\n")
	writeIgnoreFile(t, filepath.Join(repo, ".gitignore"), "node_modules\n")

	ai := DiscoverAIIgnore(repo, []string{".aiignore", ".aiexclude", ".gitignore"})
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
}

func containsSuffix(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
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

// The discovered ignore files are self-protected: a Write/Edit to .aiignore is denied via
// policy's self-protect extra-paths seam, so the agent cannot edit away its own exclusions.
func TestAIIgnoreFilesSelfProtected(t *testing.T) {
	repo := t.TempDir()
	f := filepath.Join(repo, ".aiignore")
	writeIgnoreFile(t, f, "secrets.env\n")

	prot := AIIgnoreProtectedPaths([]string{f}, OSFS{})
	canon, err := CanonicalizeRoot(f, "")
	if err != nil {
		t.Fatal(err)
	}
	if prot[canon] != "a repo AI ignore file" {
		t.Fatalf("ignore file not registered as protected: %v", prot)
	}

	pp := &PathPatternRule{SelfProtect: SelfProtect{ExtraPaths: prot}}
	ti, _ := json.Marshal(map[string]string{"file_path": f, "content": "secrets.env\n!keep\n"})
	d, matched, err := pp.Evaluate(&HookEvent{ToolName: "Write", ToolInput: ti})
	if err != nil || !matched || d.Action != Deny {
		t.Errorf("Write to .aiignore must be denied (self-protect); matched=%v action=%v err=%v", matched, d.Action, err)
	}
}

package policy

import (
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

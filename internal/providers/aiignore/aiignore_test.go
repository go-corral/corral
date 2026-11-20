package aiignore

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/policy"
)

func TestNegationCountBorrowedGitignore(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "secrets.env\n")
	writeIgnoreFile(t, filepath.Join(repo, ".gitignore"), "node_modules\n!keep.txt\n")

	ai := policy.DiscoverAIIgnore(repo, []string{".aiignore", ".aiexclude", ".gitignore"})
	// The borrowed .gitignore carries a "!" negation corral drops → over-block warning fires.
	if n := NegationCount(ai.Patterns); n != 1 {
		t.Errorf("negation count = %d, want 1 (the !keep.txt in .gitignore)", n)
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

// --- Mask ---

func TestMaskContributesMasksAndNote(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "secrets/\n")
	if err := os.MkdirAll(filepath.Join(repo, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}

	c := Mask(repo, []string{".aiignore", ".aiexclude"})
	if len(c.Dirs) != 1 || filepath.Base(c.Dirs[0]) != "secrets" || len(c.Files) != 0 {
		t.Fatalf("expected the matched dir in Dirs, got %+v", c)
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
	if len(c.AgentNotes) != 1 || !strings.Contains(c.AgentNotes[0], "exclude paths from AI tools") {
		t.Errorf("AgentNotes = %v", c.AgentNotes)
	}
}

// No discovered sources → nothing to mask and no note.
func TestMaskEmptyWithoutSources(t *testing.T) {
	repo := t.TempDir()
	// .git marks the repo boundary so the walk cannot escape into the host tree.
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if c := Mask(repo, []string{".aiignore"}); !reflect.DeepEqual(c, Masks{}) {
		t.Fatalf("no sources must contribute nothing: %+v", c)
	}
}

// A "!" negation is surfaced as a banner row (warn-and-allow, over-mask risk).
func TestMaskNegationStatus(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "!keep\nvault/\n")
	m := Mask(repo, []string{".aiignore"})
	if len(m.Status) != 2 || !strings.Contains(m.Status[1], `"!" re-include`) {
		t.Errorf("negation status line missing: %v", m.Status)
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

func mintNote(t *testing.T, repo string, sources []string) string {
	t.Helper()
	c := Mask(repo, sources)
	if len(c.AgentNotes) != 1 {
		t.Fatalf("Mask = %+v", c)
	}
	return c.AgentNotes[0]
}

func TestMintNoteOneSource(t *testing.T) {
	repo := t.TempDir()
	src := filepath.Join(repo, ".aiignore")
	writeIgnoreFile(t, src, "secrets/\n")
	note := mintNote(t, repo, []string{".aiignore", ".aiexclude"})
	for _, want := range []string{"the patterns `secrets/` in `" + src + "`", "Read the ignore files to check a path", "change these files."} {
		if !strings.Contains(note, want) {
			t.Errorf("note lacks %q: %s", want, note)
		}
	}
}

func TestMintNoteTwoSources(t *testing.T) {
	repo := t.TempDir()
	a, b := filepath.Join(repo, ".aiignore"), filepath.Join(repo, ".aiexclude")
	writeIgnoreFile(t, a, "a/\n")
	writeIgnoreFile(t, b, "b/\n")
	note := mintNote(t, repo, []string{".aiignore", ".aiexclude"})
	if want := "the patterns `a/`, `b/` in `" + a + "`, `" + b + "`"; !strings.Contains(note, want) {
		t.Errorf("note lacks %q: %s", want, note)
	}
}

func TestMintNoteManyPatterns(t *testing.T) {
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "p1/\np2/\np3/\np4/\np5/\np6/\np7/\np8/\n")
	note := mintNote(t, repo, []string{".aiignore"})
	if !strings.Contains(note, "`p6/` (+2 more)") || strings.Contains(note, "`p7/`") {
		t.Errorf("note must list six patterns and count the rest: %s", note)
	}
}

func TestMintNoteNegationSentence(t *testing.T) {
	const sentence = "Corral ignores `!` lines, so a `!` line does not open a path."
	repo := t.TempDir()
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "vault/\n")
	if note := mintNote(t, repo, []string{".aiignore"}); strings.Contains(note, sentence) {
		t.Errorf("unexpected negation sentence: %s", note)
	}
	writeIgnoreFile(t, filepath.Join(repo, ".aiignore"), "!keep\nvault/\n")
	if note := mintNote(t, repo, []string{".aiignore"}); !strings.HasSuffix(note, " "+sentence) {
		t.Errorf("missing negation sentence: %s", note)
	}
}

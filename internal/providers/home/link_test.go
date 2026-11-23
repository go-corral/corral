package home

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// mustWriteFile creates a file (and parents) with some content.
func mustWriteFile(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func isSymlink(t *testing.T, p string) bool {
	t.Helper()
	fi, err := os.Lstat(p)
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeSymlink != 0
}

// TestLinkHomeBehaviors exercises the symlink farm: it links existing allowed-under-home
// paths back to the real host path, skips missing targets, retargets a stale symlink,
// never clobbers a real file (but reports it as a shadow warning), skips a child once its
// parent dir is redirected, and skips the workdir and any mount outside the real home. The
// detect-only pass must report the same shadows while leaving the disk untouched.
func TestLinkHomeBehaviors(t *testing.T) {
	realHome := t.TempDir()
	fakeHome := filepath.Join(realHome, ".cache", "corral", "home")
	if err := os.MkdirAll(fakeHome, 0o700); err != nil {
		t.Fatal(err)
	}

	// Baseline home target that exists → must be symlinked. (~/.gitconfig is a stable
	// shared baseline rule.) ~/.claude.json is supplied as an agent rule below but left absent
	// on disk → must be skipped (and proves homeCandidates folds in agent rules, not just the
	// embedded baseline).
	mustWriteFile(t, filepath.Join(realHome, ".gitconfig"))

	// Nesting: ~/.config/corral (baseline dir) + a child file supplied as a mount. Only the
	// dir is linked; the child is reached through it and must not be linked separately.
	corralDir := filepath.Join(realHome, ".config", "corral")
	mustWriteFile(t, filepath.Join(corralDir, "config.yml"))

	// A config paths.rw grant under home → linked. One outside home → never linked.
	workSrc := filepath.Join(realHome, "work")
	mustWriteFile(t, filepath.Join(workSrc, "f"))
	outside := t.TempDir() // a sibling temp dir, not under realHome

	// The project workdir is under home but reached by absolute path → must be skipped.
	proj := filepath.Join(realHome, "proj")
	mustWriteFile(t, filepath.Join(proj, "main.go"))

	// Pre-existing private-home state: a stale symlink (wrong target) must be retargeted;
	// a real dir and a real file must be left untouched but reported as shadows.
	stale := filepath.Join(fakeHome, ".gitconfig")
	if err := os.Symlink("/nonexistent/wrong", stale); err != nil {
		t.Fatal(err)
	}
	realKeep := filepath.Join(fakeHome, "work")
	mustWriteFile(t, filepath.Join(realKeep, "preexisting"))
	notesSrc := filepath.Join(realHome, "notes.txt")
	mustWriteFile(t, notesSrc)
	mustWriteFile(t, filepath.Join(fakeHome, "notes.txt"))

	spec := &sandbox.SandboxSpec{
		Tokens: map[string]string{"HOME": realHome, "AGENT_CONFIG_DIR": filepath.Join(realHome, ".claude")},
		// An agent ConfigPath (claude's ~/.claude.json): homeCandidates must consider it via
		// sandbox.RulesFor, exactly like an embedded baseline rule. Absent on disk → skipped.
		AgentRules: []sandbox.Rule{{Path: "$HOME/.claude.json", Description: "agent rule", Writeable: true, Optional: true}},
		WorkDir:    proj,
		Mounts: []sandbox.Mount{
			{Src: filepath.Join(corralDir, "config.yml"), ReadOnly: true, Optional: true},
			{Src: workSrc},
			{Src: notesSrc},
			{Src: outside},
			{Src: proj}, // the workdir mount — must be skipped
		},
	}

	// Detect-only first: nothing on disk may change, yet the shadow set must match the linking pass.
	detected, err := Link(spec, realHome, fakeHome, "linux", nil, filepath.Join(realHome, ".claude"), false)
	if err != nil {
		t.Fatalf("Link (detect): %v", err)
	}
	if tgt, _ := os.Readlink(stale); tgt != "/nonexistent/wrong" {
		t.Errorf("detect-only pass must not retarget a stale symlink, got %q", tgt)
	}
	if _, err := os.Lstat(filepath.Join(fakeHome, ".config")); err == nil {
		t.Error("detect-only pass must not create anything in the private home")
	}

	shadows, err := Link(spec, realHome, fakeHome, "linux", nil, filepath.Join(realHome, ".claude"), true)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if strings.Join(detected, "\n") != strings.Join(shadows, "\n") {
		t.Errorf("detect-only and linking passes disagree:\n%q\n%q", detected, shadows)
	}

	// Existing baseline target linked, and the stale symlink retargeted to the real path.
	if tgt, _ := os.Readlink(stale); tgt != filepath.Join(realHome, ".gitconfig") {
		t.Errorf(".gitconfig must be (re)linked to the real path, got %q", tgt)
	}
	// Missing agent-rule target skipped (it is a candidate via RulesFor, but absent on disk).
	if _, err := os.Lstat(filepath.Join(fakeHome, ".claude.json")); err == nil {
		t.Error("missing ~/.claude.json must not be linked")
	}
	// Nesting: the dir is a symlink; the child is not linked separately.
	if !isSymlink(t, filepath.Join(fakeHome, ".config", "corral")) {
		t.Error("~/.config/corral must be linked as a dir symlink")
	}
	if isSymlink(t, filepath.Join(fakeHome, ".config", "corral", "config.yml")) {
		t.Error("a child under an already-symlinked parent must not be linked separately")
	}
	// A real pre-existing dir in the private home must be left untouched (not replaced).
	if isSymlink(t, realKeep) {
		t.Error("a real pre-existing dir must never be replaced by a symlink")
	}
	if _, err := os.Stat(filepath.Join(realKeep, "preexisting")); err != nil {
		t.Errorf("pre-existing private-home data must be preserved: %v", err)
	}
	// Both untouched entries must be reported as shadows (real node kind named, both paths
	// present); the retargeted symlink, missing targets, and symlinked-parent skips must not.
	if len(shadows) != 2 {
		t.Fatalf("want exactly 2 shadow warnings, got %d: %q", len(shadows), shadows)
	}
	wantShadow := func(link, target, kind string) {
		t.Helper()
		for _, s := range shadows {
			if strings.Contains(s, link) && strings.Contains(s, target) && strings.Contains(s, "real "+kind) {
				return
			}
		}
		t.Errorf("no shadow warning names %s as a real %s shadowing %s: %q", link, kind, target, shadows)
	}
	wantShadow(realKeep, workSrc, "directory")
	wantShadow(filepath.Join(fakeHome, "notes.txt"), notesSrc, "file")
	// The workdir and the out-of-home mount must be skipped.
	if _, err := os.Lstat(filepath.Join(fakeHome, "proj")); err == nil {
		t.Error("the project workdir must not be linked into the private home")
	}
	if _, err := os.Lstat(filepath.Join(fakeHome, filepath.Base(outside))); err == nil {
		t.Error("a mount outside the real home must not be linked")
	}
}

// TestLinkHomeKeepSilencesShadow pins the opt-out: a real private-home entry named by keep, or
// lying under a kept directory, stays untouched and is not reported; an unlisted one still is,
// with the $HOME-relative path and the keep hint in the message.
func TestLinkHomeKeepSilencesShadow(t *testing.T) {
	realHome := t.TempDir()
	fakeHome := filepath.Join(realHome, ".cache", "corral", "home")

	// Three host paths granted as mounts, each shadowed by a real entry in the private home.
	var mounts []sandbox.Mount
	for _, rel := range []string{"work", "notes.txt", filepath.Join(".local", "share", "uv")} {
		mustWriteFile(t, filepath.Join(realHome, rel, "f"))
		mustWriteFile(t, filepath.Join(fakeHome, rel, "private"))
		mounts = append(mounts, sandbox.Mount{Src: filepath.Join(realHome, rel)})
	}
	spec := &sandbox.SandboxSpec{
		Tokens: map[string]string{"HOME": realHome, "AGENT_CONFIG_DIR": filepath.Join(realHome, ".claude")},
		Mounts: mounts,
	}

	// "work" is kept by name; ".local" keeps everything under it; notes.txt is not kept.
	shadows, err := Link(spec, realHome, fakeHome, "linux", []string{"work", ".local"}, filepath.Join(realHome, ".claude"), true)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if len(shadows) != 1 {
		t.Fatalf("want exactly 1 shadow warning (notes.txt), got %d: %q", len(shadows), shadows)
	}
	for _, want := range []string{filepath.Join(fakeHome, "notes.txt"), filepath.Join(realHome, "notes.txt"), "$HOME/notes.txt", `"notes.txt" under providers.home.keep`} {
		if !strings.Contains(shadows[0], want) {
			t.Errorf("shadow warning should mention %q: %q", want, shadows[0])
		}
	}
	// Kept entries are still never clobbered.
	for _, rel := range []string{"work", filepath.Join(".local", "share", "uv")} {
		if isSymlink(t, filepath.Join(fakeHome, rel)) {
			t.Errorf("kept entry %s must not be replaced by a symlink", rel)
		}
	}
}

// shadowedConfigDir builds a private home whose .claude is a real dir shadowing the host's, and
// the spec that makes the host dir a candidate via the $AGENT_CONFIG_DIR baseline rule.
func shadowedConfigDir(t *testing.T) (realHome, fakeHome, configDir string, spec *sandbox.SandboxSpec) {
	t.Helper()
	realHome = t.TempDir()
	fakeHome = filepath.Join(realHome, ".cache", "corral", "home")
	configDir = filepath.Join(realHome, ".claude")
	mustWriteFile(t, filepath.Join(configDir, "settings.json"))
	mustWriteFile(t, filepath.Join(fakeHome, ".claude", "settings.json"))
	spec = &sandbox.SandboxSpec{
		Tokens: map[string]string{"HOME": realHome, "AGENT_CONFIG_DIR": configDir},
	}
	return realHome, fakeHome, configDir, spec
}

// TestLinkHomeConfigDirShadowIgnoresKeep pins the enforcement case: the guarded config dir is
// reported with its own text even when listed under keep.
func TestLinkHomeConfigDirShadowIgnoresKeep(t *testing.T) {
	realHome, fakeHome, configDir, spec := shadowedConfigDir(t)
	shadows, err := Link(spec, realHome, fakeHome, "linux", []string{".claude"}, configDir, true)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if len(shadows) != 1 {
		t.Fatalf("want exactly 1 shadow warning for the config dir, got %d: %q", len(shadows), shadows)
	}
	for _, want := range []string{"$HOME/.claude", filepath.Join(fakeHome, ".claude"), "agent config dir " + configDir, "corral sync", "does not cover the agent config dir"} {
		if !strings.Contains(shadows[0], want) {
			t.Errorf("config-dir shadow warning should mention %q: %q", want, shadows[0])
		}
	}
	if isSymlink(t, filepath.Join(fakeHome, ".claude")) {
		t.Error("the real config dir must not be replaced by a symlink")
	}
}

// TestLinkHomeConfigDirUnguarded pins the other side: with no guard dir (a bridge agent, or a
// relocated dir the agent reaches without $HOME) the same real config dir is an ordinary shadow,
// reported with the keep hint and silenced by keep.
func TestLinkHomeConfigDirUnguarded(t *testing.T) {
	realHome, fakeHome, configDir, spec := shadowedConfigDir(t)
	shadows, err := Link(spec, realHome, fakeHome, "linux", nil, "", true)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if len(shadows) != 1 {
		t.Fatalf("want exactly 1 shadow warning, got %d: %q", len(shadows), shadows)
	}
	for _, want := range []string{"host path " + configDir, `".claude" under providers.home.keep`} {
		if !strings.Contains(shadows[0], want) {
			t.Errorf("unguarded config-dir shadow should read as an ordinary shadow mentioning %q: %q", want, shadows[0])
		}
	}
	if strings.Contains(shadows[0], "corral sync") {
		t.Errorf("unguarded config-dir shadow must not claim an enforcement loss: %q", shadows[0])
	}
	kept, err := Link(spec, realHome, fakeHome, "linux", []string{".claude"}, "", true)
	if err != nil {
		t.Fatalf("Link (kept): %v", err)
	}
	if len(kept) != 0 {
		t.Errorf("keep must silence an unguarded config-dir shadow, got %q", kept)
	}
}

// TestLinkHomeFailsClosedOnUnreadableEntry pins that a Lstat error other than not-exist fails
// the pass instead of counting as absent: a file where a parent dir belongs would otherwise
// pass the detect-only pass silently and fail the linking pass after the mint.
func TestLinkHomeFailsClosedOnUnreadableEntry(t *testing.T) {
	realHome := t.TempDir()
	fakeHome := filepath.Join(realHome, ".cache", "corral", "home")
	src := filepath.Join(realHome, ".config", "gh")
	mustWriteFile(t, filepath.Join(src, "hosts.yml"))
	mustWriteFile(t, filepath.Join(fakeHome, ".config")) // a file where the parent dir belongs

	spec := &sandbox.SandboxSpec{
		Tokens: map[string]string{"HOME": realHome},
		Mounts: []sandbox.Mount{{Src: src}},
	}
	for _, apply := range []bool{false, true} {
		_, err := Link(spec, realHome, fakeHome, "linux", nil, "", apply)
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Errorf("apply=%v: want ENOTDIR to fail the pass closed, got %v", apply, err)
		}
	}
}

// TestLinkHomeCleansPathChecks pins the clean step: trailing slashes on the homes are
// ignored, differently spelled candidates for one path dedup to the first spelling (one link,
// no shadow), and a candidate that cleans to the real home is skipped.
func TestLinkHomeCleansPathChecks(t *testing.T) {
	realHome := t.TempDir()
	fakeHome := filepath.Join(realHome, ".cache", "corral", "home")
	if err := os.MkdirAll(fakeHome, 0o700); err != nil {
		t.Fatal(err)
	}
	work := filepath.Join(realHome, "work")
	mustWriteFile(t, filepath.Join(work, "f"))
	notes := filepath.Join(realHome, "notes.txt")
	mustWriteFile(t, notes)

	spec := &sandbox.SandboxSpec{
		Tokens: map[string]string{"HOME": realHome, "AGENT_CONFIG_DIR": filepath.Join(realHome, ".claude")},
		Mounts: []sandbox.Mount{
			// The child comes first: the depth sort must still link the parent first.
			{Src: filepath.Join(work, "f")},
			{Src: work + "/"},
			{Src: realHome + "/./work"},
			{Src: work},
			{Src: realHome + "/."},
			{Src: fakeHome + "/"},
			{Src: notes},
		},
	}

	for range 2 { // the second pass finds the links in place and must stay silent
		shadows, err := Link(spec, realHome+"/", fakeHome+"/", "linux", nil, "", true)
		if err != nil {
			t.Fatalf("Link: %v", err)
		}
		if len(shadows) != 0 {
			t.Fatalf("want no shadow warnings, got %q", shadows)
		}
		if tgt, _ := os.Readlink(filepath.Join(fakeHome, "work")); tgt != work+"/" {
			t.Errorf("work must link to its first spelling %q, got %q", work+"/", tgt)
		}
		if tgt, _ := os.Readlink(filepath.Join(fakeHome, "notes.txt")); tgt != notes {
			t.Errorf("notes.txt must link to %q, got %q", notes, tgt)
		}
	}
	entries, err := os.ReadDir(fakeHome)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Errorf("want exactly the work and notes.txt links, got %d entries: %v", len(entries), entries)
	}
}

// TestLinkHomeKeepsRawPathForDotDot pins that the symlink target keeps the raw spelling:
// the kernel resolves ".." after following symlinks, so the lexically cleaned path may name
// a different (here missing) host file.
func TestLinkHomeKeepsRawPathForDotDot(t *testing.T) {
	realHome := t.TempDir()
	fakeHome := filepath.Join(realHome, ".cache", "corral", "home")
	sub := filepath.Join(realHome, "target", "sub")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(sub, filepath.Join(realHome, "dots")); err != nil {
		t.Fatal(err)
	}
	// dots/../.cfg resolves to target/.cfg; the cleaned spelling .cfg does not exist.
	mustWriteFile(t, filepath.Join(realHome, "target", ".cfg"))
	raw := filepath.Join(realHome, "dots") + "/../.cfg"

	spec := &sandbox.SandboxSpec{
		Tokens: map[string]string{"HOME": realHome, "AGENT_CONFIG_DIR": filepath.Join(realHome, ".claude")},
		Mounts: []sandbox.Mount{{Src: raw}},
	}
	shadows, err := Link(spec, realHome, fakeHome, "linux", nil, "", true)
	if err != nil {
		t.Fatalf("Link: %v", err)
	}
	if len(shadows) != 0 {
		t.Fatalf("want no shadow warnings, got %q", shadows)
	}
	if tgt, err := os.Readlink(filepath.Join(fakeHome, ".cfg")); err != nil || tgt != raw {
		t.Errorf(".cfg must link to the raw path %q, got %q (%v)", raw, tgt, err)
	}
}

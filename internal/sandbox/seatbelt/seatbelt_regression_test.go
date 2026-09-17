package seatbelt

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// requireTmpWritable skips the test when /tmp cannot be written. Prepare hardcodes
// os.MkdirTemp("/tmp", …) (no portable seam to redirect it), so inside a nested corral
// sandbox, which exposes only the session $TMPDIR rather than /tmp, MkdirTemp fails with
// EPERM and Prepare takes its fail-safe branch (empty SESSION_TMPDIR + a warning). That
// is correct sandboxed behavior, not a regression; the success-path contract these tests
// lock is verifiable wherever /tmp is writable (CI, or a dev box outside the sandbox).
// The probe mirrors Prepare's own MkdirTemp so it predicts Prepare's outcome exactly.
func requireTmpWritable(t *testing.T) {
	t.Helper()
	d, err := os.MkdirTemp("/tmp", "corral-probe-")
	if err != nil {
		t.Skipf("/tmp not writable in this environment (%v); run outside the sandbox", err)
	}
	_ = os.RemoveAll(d)
}

// TestBackendName verifies Backend.Name() returns "seatbelt".
func TestBackendName(t *testing.T) {
	b := New("", Config{})
	if got := b.Name(); got != "seatbelt" {
		t.Errorf("Backend.Name() = %q, want %q", got, "seatbelt")
	}
}

// TestBackendUnavailableHint verifies Backend.UnavailableHint() returns a non-empty string
// mentioning sandbox-exec and macOS.
func TestBackendUnavailableHint(t *testing.T) {
	b := New("", Config{})
	hint := b.UnavailableHint()
	if hint == "" {
		t.Error("UnavailableHint must return non-empty string")
	}
	if !strings.Contains(hint, "sandbox-exec") {
		t.Errorf("UnavailableHint must mention sandbox-exec; got %q", hint)
	}
	if !strings.Contains(hint, "macOS") {
		t.Errorf("UnavailableHint must mention macOS; got %q", hint)
	}
}

// TestBackendDoctor verifies Backend.Doctor(w) writes sandbox-exec tool info via
// sandbox.ReportTool.
func TestBackendDoctor(t *testing.T) {
	b := New("sandbox-exec", Config{})
	var buf bytes.Buffer
	b.Doctor(&buf)
	output := buf.String()
	// Doctor should write *something* via ReportTool (even if not found on this Linux machine)
	if output == "" {
		t.Error("Doctor must write output to w")
	}
	if !strings.Contains(output, "sandbox-exec") {
		t.Errorf("Doctor output must mention sandbox-exec; got %q", output)
	}
}

// AgentNotes surfaces the macOS Seatbelt quirks to the model — the /tmp/$TMPDIR temp-dir fact
// and the harmless SIP-tool (xcrun/git/clang) temp-cache warning. Static and secret-free; the
// launcher folds them into the sandbox note (sandbox.BackendNotesEnvVar).
func TestBackendAgentNotes(t *testing.T) {
	notes := New("", Config{}).AgentNotes()
	if len(notes) != 2 {
		t.Fatalf("seatbelt AgentNotes should return two notes (temp dir + SIP-tool warning), got %v", notes)
	}
	// First: the /tmp/$TMPDIR temp-dir fact (the Seatbelt profile denies /tmp; Prepare repoints
	// $TMPDIR at a per-session dir).
	if !strings.Contains(notes[0], "$TMPDIR") || !strings.Contains(notes[0], "/tmp") {
		t.Errorf("first seatbelt AgentNote should point at $TMPDIR and mention /tmp, got %q", notes[0])
	}
	// Second: the cosmetic SIP-tool temp-cache warning, so the model does not chase it as a real
	// failure. Names the recognizable xcrun_db marker and tells the model to ignore it.
	if !strings.Contains(notes[1], "xcrun") || !strings.Contains(notes[1], "ignore") {
		t.Errorf("second seatbelt AgentNote should name the xcrun/SIP-tool warning and say to ignore it, got %q", notes[1])
	}
}

// Strict mach-lookup adds a third AgentNote so the model recognizes an opaque Mach denial instead of
// retrying blindly; open mode omits it.
func TestBackendAgentNotesStrict(t *testing.T) {
	notes := New("", Config{Mach: Mach{Lookup: "strict"}}).AgentNotes()
	if len(notes) != 3 {
		t.Fatalf("strict seatbelt AgentNotes should return three notes, got %v", notes)
	}
	if !strings.Contains(notes[2], "mach-lookup") || !strings.Contains(notes[2], "corral-mach") {
		t.Errorf("third seatbelt AgentNote should describe the strict mach-lookup denial, got %q", notes[2])
	}
}

// TestBackendAvailableNotDarwin verifies Backend.Available() returns false when
// runtime.GOOS != "darwin".
func TestBackendAvailableNotDarwin(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this test only validates non-macOS behavior")
	}
	b := New("sandbox-exec", Config{})
	if b.Available() {
		t.Error("Backend.Available() must return false on non-macOS (current OS is " + runtime.GOOS + ")")
	}
}

// TestBinDefault verifies bin() with an empty Path returns "sandbox-exec".
func TestBinDefault(t *testing.T) {
	b := Backend{Path: ""}
	if got := b.bin(); got != "sandbox-exec" {
		t.Errorf("bin() with empty Path = %q, want %q", got, "sandbox-exec")
	}
}

// TestBinCustomPath verifies bin() with a non-empty Path returns that Path.
func TestBinCustomPath(t *testing.T) {
	b := Backend{Path: "/usr/bin/sandbox-exec"}
	if got := b.bin(); got != "/usr/bin/sandbox-exec" {
		t.Errorf("bin() with custom Path = %q, want %q", got, "/usr/bin/sandbox-exec")
	}
}

// TestPrepareOverwritesTempEnvKeys verifies Prepare overwrites the temp env keys
// (TMPDIR/TMP/TEMPDIR/CLAUDE_CODE_TMPDIR) in an existing map.
func TestPrepareOverwritesTempEnvKeys(t *testing.T) {
	requireTmpWritable(t)
	spec := sandbox.SandboxSpec{
		WorkDir:        "/Users/u/proj",
		SetEnv:         map[string]string{"TMPDIR": "/old/tmp", "OTHER": "value"},
		Tokens:         map[string]string{"HOME": "/Users/u"},
		TempEnvAliases: []string{"CLAUDE_CODE_TMPDIR"}, // agent-supplied alias (claude); the backend repoints it too
	}
	var buf bytes.Buffer
	prep, err := New("", Config{}).Prepare(&spec, &buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prep.Cleanup)

	newTmpdir := spec.SetEnv["TMPDIR"]
	if newTmpdir == "/old/tmp" {
		t.Error("Prepare must overwrite existing TMPDIR")
	}
	if spec.SetEnv["OTHER"] != "value" {
		t.Error("Prepare must not touch other env keys")
	}
	for _, k := range []string{"TMPDIR", "TMP", "TEMPDIR", "CLAUDE_CODE_TMPDIR"} {
		if spec.SetEnv[k] == "" {
			t.Errorf("Prepare must set %s to the session temp dir", k)
		}
		if spec.SetEnv[k] != newTmpdir {
			t.Errorf("%s must match TMPDIR; got %q, want %q", k, spec.SetEnv[k], newTmpdir)
		}
	}
}

// TestPrepareOverwritesSessionToken verifies Prepare overwrites SESSION_TMPDIR in existing
// Tokens (idempotent on Tokens).
func TestPrepareOverwritesSessionToken(t *testing.T) {
	requireTmpWritable(t)
	spec := sandbox.SandboxSpec{
		WorkDir: "/Users/u/proj",
		SetEnv:  map[string]string{},
		Tokens:  map[string]string{"HOME": "/Users/u", "SESSION_TMPDIR": "/old/session"},
	}
	var buf bytes.Buffer
	prep, err := New("", Config{}).Prepare(&spec, &buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(prep.Cleanup)

	newToken := spec.Tokens["SESSION_TMPDIR"]
	if newToken == "/old/session" || newToken == "" {
		t.Error("Prepare must overwrite SESSION_TMPDIR in existing Tokens map")
	}
}

// TestPrepareSuccessSetsSessionTmpdir covers the success path: Prepare sets the session
// temp dir and rewrites the temp env keys.
// note: Prepare's fail-safe branch (os.MkdirTemp failure → empty SESSION_TMPDIR + a
// warning, with no error returned) is not exercised here: Prepare hardcodes
// os.MkdirTemp("/tmp", …), which offers no portable failure seam in a unit test.
// This test locks the success contract instead.
func TestPrepareSuccessSetsSessionTmpdir(t *testing.T) {
	requireTmpWritable(t)
	spec := sandbox.SandboxSpec{
		WorkDir:        "/Users/u/proj",
		SetEnv:         map[string]string{},
		Tokens:         map[string]string{"HOME": "/Users/u"},
		TempEnvAliases: []string{"CLAUDE_CODE_TMPDIR"}, // agent-supplied alias (claude); the backend repoints it too
	}

	var buf bytes.Buffer
	prep, err := New("", Config{}).Prepare(&spec, &buf)
	if err != nil {
		t.Errorf("Prepare must not return error (fail-safe); got %v", err)
	}
	t.Cleanup(prep.Cleanup)

	// Verify the success case: SESSION_TMPDIR is set in the spec.
	sessionTmpdir := spec.Tokens["SESSION_TMPDIR"]
	if sessionTmpdir == "" {
		t.Error("Prepare must set SESSION_TMPDIR to a non-empty value on success")
	}

	// Verify that all temp env vars are set to the same value.
	for _, k := range []string{"TMPDIR", "TMP", "TEMPDIR", "CLAUDE_CODE_TMPDIR"} {
		if spec.SetEnv[k] != sessionTmpdir {
			t.Errorf("Prepare must set %s to SESSION_TMPDIR value; got %q, want %q", k, spec.SetEnv[k], sessionTmpdir)
		}
	}

	// No warning should be written on success.
	if buf.Len() > 0 {
		t.Errorf("Prepare must not write a warning on success; got %q", buf.String())
	}
}

// TestPrepareSetsTMPPREFIXForZshHeredocs covers the zsh heredoc regression: zsh writes
// here-document / here-string temp files under $TMPPREFIX (default /tmp/zsh), not
// $TMPDIR. With /tmp deny-by-default, the default makes every heredoc fail closed
// ("can't create temp file for here document") — and zsh is the default macOS shell.
// Prepare must therefore repoint $TMPPREFIX inside the session temp dir (the granted
// subpath), as a file prefix (zsh appends random chars to it), not at the bare dir or
// its default.
func TestPrepareSetsTMPPREFIXForZshHeredocs(t *testing.T) {
	requireTmpWritable(t)
	spec := sandbox.SandboxSpec{
		WorkDir: "/Users/u/proj",
		SetEnv:  map[string]string{},
		Tokens:  map[string]string{"HOME": "/Users/u"},
	}
	prep, err := New("", Config{}).Prepare(&spec, io.Discard)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(prep.Cleanup)

	sess := spec.Tokens["SESSION_TMPDIR"]
	if sess == "" {
		t.Skip("session temp dir could not be created (documented fail-safe path)")
	}
	tp := spec.SetEnv["TMPPREFIX"]
	if want := sess + "/zsh"; tp != want {
		t.Fatalf("TMPPREFIX must be the session-dir zsh prefix; got %q want %q", tp, want)
	}
	// It must resolve strictly inside the granted session subtree (never /tmp/zsh).
	if !strings.HasPrefix(tp, sess+"/") {
		t.Errorf("TMPPREFIX %q must live under the session dir %q", tp, sess)
	}
	if strings.HasPrefix(tp, "/tmp/zsh") {
		t.Errorf("TMPPREFIX must not be zsh's deny-by-default default /tmp/zsh; got %q", tp)
	}
	// The parent dir must exist so zsh can create <TMPPREFIX><random> in it.
	if fi, err := os.Stat(filepath.Dir(tp)); err != nil || !fi.IsDir() {
		t.Errorf("TMPPREFIX parent %q must be an existing dir: %v", filepath.Dir(tp), err)
	}
}

// realSymlink.resolve must fully canonicalize a path (every hop + symlinked ancestors), not resolve
// one level: seatbelt matches a rule against the kernel-canonical path of the file opened, so a
// one-level grant of a chained/symlinked-ancestor dotfile is a path the kernel never presents and the
// read EPERMs. Expected values are themselves run through EvalSymlinks so the assertions hold on
// macOS, where t.TempDir() sits under the /var -> /private/var firmlink.
func TestRealSymlinkResolveRelativeTarget(t *testing.T) {
	tmpdir := t.TempDir()
	symPath := filepath.Join(tmpdir, "sym")
	if err := os.Mkdir(filepath.Join(tmpdir, "real"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpdir, "real", "target"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real/target", symPath); err != nil { // relative target
		t.Fatal(err)
	}
	assertResolves(t, symPath, filepath.Join(tmpdir, "real", "target"))
}

func TestRealSymlinkResolveAbsoluteTarget(t *testing.T) {
	tmpdir := t.TempDir()
	symPath := filepath.Join(tmpdir, "sym")
	target := filepath.Join(tmpdir, "real", "target")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, symPath); err != nil { // absolute target
		t.Fatal(err)
	}
	assertResolves(t, symPath, target)
}

// TestRealSymlinkResolveChain covers a multi-hop chain (sym -> mid -> target): one-level resolution
// would stop at `mid` (still a symlink), granting a path the kernel resolves past.
func TestRealSymlinkResolveChain(t *testing.T) {
	tmpdir := t.TempDir()
	target := filepath.Join(tmpdir, ".dotfiles", "git", "gitconfig")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mid := filepath.Join(tmpdir, "mid")
	sym := filepath.Join(tmpdir, ".gitconfig")
	if err := os.Symlink(target, mid); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mid, sym); err != nil {
		t.Fatal(err)
	}
	assertResolves(t, sym, target, sym, mid)
}

// TestRealSymlinkResolveSymlinkedAncestor covers a target reached through a symlinked ancestor dir
// (sym -> ~/.dotfiles/git/gitconfig where ~/.dotfiles -> ~/code/dotfiles): one-level resolution
// leaves `.dotfiles` in the granted path, which the kernel canonicalizes away.
func TestRealSymlinkResolveSymlinkedAncestor(t *testing.T) {
	tmpdir := t.TempDir()
	real := filepath.Join(tmpdir, "code", "dotfiles", "git")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "gitconfig"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(tmpdir, "code", "dotfiles"), filepath.Join(tmpdir, ".dotfiles")); err != nil {
		t.Fatal(err)
	}
	sym := filepath.Join(tmpdir, ".gitconfig")
	if err := os.Symlink(filepath.Join(tmpdir, ".dotfiles", "git", "gitconfig"), sym); err != nil {
		t.Fatal(err)
	}
	assertResolves(t, sym, filepath.Join(real, "gitconfig"), sym, filepath.Join(tmpdir, ".dotfiles"))
}

// TestRealSymlinkResolveNonSymlink verifies a regular file with no symlinked ancestors resolves to
// itself unchanged (resolve must neither error nor over-normalize a plain path). The temp dir is
// canonicalized first so filePath is already lexical-canonical (folding the macOS /var -> /private/var
// firmlink), which lets the assertion compare against a literal, not against resolve's own output.
func TestRealSymlinkResolveNonSymlink(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(base, "regular_file")
	if err := os.WriteFile(filePath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, links := (realSymlink{}).resolve(filePath)
	if got != filePath {
		t.Errorf("resolve(non-symlink) = %q, want %q", got, filePath)
	}
	if len(links) != 0 {
		t.Errorf("resolve(non-symlink) crossed no link, got nodes %v", links)
	}
}

// TestRealSymlinkResolveNonExistent verifies a missing path falls back to the input unchanged, so an
// optional rule whose target is absent still compiles (to a harmless literal the kernel never hits).
func TestRealSymlinkResolveNonExistent(t *testing.T) {
	nonExistent := "/does/not/exist/file"
	got, links := (realSymlink{}).resolve(nonExistent)
	if got != nonExistent {
		t.Errorf("resolve(non-existent) = %q, want %q", got, nonExistent)
	}
	if len(links) != 0 {
		t.Errorf("resolve(non-existent) must grant no link nodes, got %v", links)
	}
}

// TestRealSymlinkResolveDanglingChain covers a chain whose endpoint is absent: the target falls back
// to the input, but the symlink nodes that do exist are still reported, so the kernel can walk the
// chain to its ENOENT instead of EPERMing at an un-granted hop.
func TestRealSymlinkResolveDanglingChain(t *testing.T) {
	tmpdir := t.TempDir()
	real := filepath.Join(tmpdir, "real")
	if err := os.MkdirAll(filepath.Join(real, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	mid := filepath.Join(tmpdir, ".dotfiles")
	if err := os.Symlink(real, mid); err != nil {
		t.Fatal(err)
	}
	sym := filepath.Join(tmpdir, ".gitignore_global")
	if err := os.Symlink(filepath.Join(mid, "git", "ignore"), sym); err != nil { // git/ignore is absent
		t.Fatal(err)
	}
	got, links := (realSymlink{}).resolve(sym)
	if got != sym {
		t.Errorf("resolve(dangling chain) = %q, want the input %q", got, sym)
	}
	for _, n := range []string{sym, mid} {
		dir, err := filepath.EvalSymlinks(filepath.Dir(n))
		if err != nil {
			t.Fatal(err)
		}
		if want := filepath.Join(dir, filepath.Base(n)); !slices.Contains(links, want) {
			t.Errorf("resolve(dangling chain) must still report existing node %q; got %v", want, links)
		}
	}
}

// assertResolves checks realSymlink.resolve(in) equals wantReal fully canonicalized (EvalSymlinks of
// the expected real target folds away any symlinked ancestor of the test's temp dir), and that every
// wantNode is reported as a crossed symlink. The node check is containment, not equality: on macOS
// the temp dir sits under the /var root symlink, so the walk legitimately reports nodes above the
// ones a test names.
func assertResolves(t *testing.T, in, wantReal string, wantNodes ...string) {
	t.Helper()
	want, err := filepath.EvalSymlinks(wantReal)
	if err != nil {
		t.Fatalf("canonicalize expected %q: %v", wantReal, err)
	}
	got, links := (realSymlink{}).resolve(in)
	if got != want {
		t.Errorf("resolve(%q) = %q, want %q", in, got, want)
	}
	for _, n := range wantNodes {
		// A node is named the way the kernel meets it, i.e. with its ancestors already resolved
		// (on macOS the temp dir sits under the /var or /tmp root symlink). Canonicalize the
		// parent, never the node itself — resolving the node would name its target instead.
		dir, err := filepath.EvalSymlinks(filepath.Dir(n))
		if err != nil {
			t.Fatalf("canonicalize parent of %q: %v", n, err)
		}
		if want := filepath.Join(dir, filepath.Base(n)); !slices.Contains(links, want) {
			t.Errorf("resolve(%q) must report crossed symlink node %q; got %v", in, want, links)
		}
	}
}

// TestProfileGitconfigChainGrantsResolvedTarget builds a real profile (real EvalSymlinks resolver)
// for a chained/symlinked-ancestor ~/.gitconfig and asserts the read-allow names the one real
// target — not an intermediate symlink the kernel resolves past (which would EPERM the read).
func TestProfileGitconfigChainGrantsResolvedTarget(t *testing.T) {
	home := t.TempDir()
	// ~/.gitconfig -> ~/.dotfiles/git/gitconfig, with ~/.dotfiles -> ~/code/dotfiles (symlinked
	// ancestor): the shape a one-level resolver gets wrong.
	real := filepath.Join(home, "code", "dotfiles", "git")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "gitconfig"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "code", "dotfiles"), filepath.Join(home, ".dotfiles")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".dotfiles", "git", "gitconfig"), filepath.Join(home, ".gitconfig")); err != nil {
		t.Fatal(err)
	}

	spec := sandbox.SandboxSpec{
		SetEnv: map[string]string{},
		Tokens: map[string]string{"HOME": home, "AGENT_CONFIG_DIR": filepath.Join(home, ".claude")},
	}
	profile, err := New("", Config{}).profile(spec) // real resolver, not noResolve
	if err != nil {
		t.Fatal(err)
	}

	canonical, err := filepath.EvalSymlinks(filepath.Join(real, "gitconfig"))
	if err != nil {
		t.Fatal(err)
	}
	want := "(literal \"" + NormalizeMacPath(canonical) + "\")"
	if !strings.Contains(profile, want) {
		t.Errorf("profile must grant the resolved gitconfig target %s\nprofile:\n%s", want, profile)
	}
	// The unresolved-ancestor path must not be what is granted (the one-level-resolver bug).
	if bad := NormalizeMacPath(filepath.Join(home, ".dotfiles", "git", "gitconfig")); strings.Contains(profile, "(literal \""+bad+"\")") {
		t.Errorf("profile must NOT grant the un-canonicalized path %q", bad)
	}
}

// TestProfileGitconfigChainGrantsCrossedSymlinkNodes locks the other half of the contract:
// granting only the resolved target is not enough, because the kernel must readlink every node on
// the way there and that read is policed too. Without a grant on ~/.gitconfig and ~/.dotfiles the
// walk EPERMs before it reaches the granted target, and git reports "unable to access" on a file
// the sandbox does allow.
func TestProfileGitconfigChainGrantsCrossedSymlinkNodes(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "code", "dotfiles", "git")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "gitconfig"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "code", "dotfiles"), filepath.Join(home, ".dotfiles")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".dotfiles", "git", "gitconfig"), filepath.Join(home, ".gitconfig")); err != nil {
		t.Fatal(err)
	}

	spec := sandbox.SandboxSpec{
		SetEnv: map[string]string{},
		Tokens: map[string]string{"HOME": home, "AGENT_CONFIG_DIR": filepath.Join(home, ".claude")},
	}
	profile, err := New("", Config{}).profile(spec) // real resolver, not noResolve
	if err != nil {
		t.Fatal(err)
	}

	for _, node := range []string{filepath.Join(home, ".gitconfig"), filepath.Join(home, ".dotfiles")} {
		want := "(literal \"" + NormalizeMacPath(node) + "\")"
		if !strings.Contains(profile, want) {
			t.Errorf("profile must grant the crossed symlink node %s\nprofile:\n%s", want, profile)
		}
		// Node-only: the grant buys traversal, never the link target's subtree.
		if bad := "(subpath \"" + NormalizeMacPath(node) + "\")"; strings.Contains(profile, bad) {
			t.Errorf("crossed symlink node must be granted as a node, not a subtree: %s", bad)
		}
	}
}

// TestProfileDanglingChainGrantsCrossedSymlinkNodes covers the optional-and-absent case behind a
// chain: ~/.gitignore_global -> ~/.dotfiles/git/ignore with the ignore file missing. The profile
// must still grant the existing nodes, or git meets EPERM at ~/.dotfiles and warns on every command
// instead of treating its excludes file as absent.
func TestProfileDanglingChainGrantsCrossedSymlinkNodes(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, "code", "dotfiles", "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "code", "dotfiles"), filepath.Join(home, ".dotfiles")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".dotfiles", "git", "ignore"), filepath.Join(home, ".gitignore_global")); err != nil {
		t.Fatal(err)
	}

	spec := sandbox.SandboxSpec{
		SetEnv: map[string]string{},
		Tokens: map[string]string{"HOME": home, "AGENT_CONFIG_DIR": filepath.Join(home, ".claude")},
	}
	profile, err := New("", Config{}).profile(spec) // real resolver, not noResolve
	if err != nil {
		t.Fatal(err)
	}

	for _, node := range []string{filepath.Join(home, ".gitignore_global"), filepath.Join(home, ".dotfiles")} {
		want := "(literal \"" + NormalizeMacPath(node) + "\")"
		if !strings.Contains(profile, want) {
			t.Errorf("profile must grant the existing symlink node %s of a dangling chain\nprofile:\n%s", want, profile)
		}
		if bad := "(subpath \"" + NormalizeMacPath(node) + "\")"; strings.Contains(profile, bad) {
			t.Errorf("crossed symlink node must be granted as a node, not a subtree: %s", bad)
		}
	}
}

// TestProfileNoBlockedPathsSectionEmpty verifies profile() with empty BlockedPaths emits
// no (deny file-read* file-write*) section.
func TestProfileNoBlockedPathsSectionEmpty(t *testing.T) {
	spec := sandbox.SandboxSpec{
		WorkDir:      "/Users/u/proj",
		BlockedPaths: []string{}, // empty
		SetEnv:       map[string]string{},
		Tokens:       macTestTokens(),
	}
	profile, err := macBackend().profile(spec)
	if err != nil {
		t.Fatal(err)
	}
	// Should not have the "(deny file-read* file-write*" section
	if strings.Contains(profile, "(deny file-read* file-write*") {
		t.Error("profile with empty BlockedPaths must not emit a (deny file-read* file-write*) section")
	}
	// Also must not have the blocked-leaf metadata allow section
	if strings.Contains(profile, ";; ...but re-allow lstat of the blocked-root leaves") {
		t.Error("profile with empty BlockedPaths must not emit blocked-leaf metadata section")
	}
}

// TestProfileBlockedPathDenyOverridesMountAllow verifies profile() with a mount at the same
// Src as a blocked path adds the mount to read/write, then lets the deny override it.
func TestProfileBlockedPathDenyOverridesMountAllow(t *testing.T) {
	blockPath := "/Users/u/.ssh"
	spec := sandbox.SandboxSpec{
		WorkDir: "/Users/u/proj",
		Mounts: []sandbox.Mount{
			{Src: blockPath}, // Mount /Users/u/.ssh
		},
		BlockedPaths: []string{blockPath}, // But block it
		SetEnv:       map[string]string{},
		Tokens:       macTestTokens(),
	}
	profile, err := macBackend().profile(spec)
	if err != nil {
		t.Fatal(err)
	}

	// Verify: the mount is added to read (and write since !ReadOnly)...
	// by checking it appears in the (allow file-read* ...) and (allow file-write* ...) sections.
	readAllowIdx := strings.Index(profile, "(allow file-read*")
	blockAllowInRead := strings.Contains(profile[readAllowIdx:], `(subpath "`+blockPath+`")`)
	if !blockAllowInRead {
		t.Error("mount at blocked path must be added to read allow set")
	}

	// ...then the blocked-path deny comes after and overrides it.
	blockDenyIdx := strings.Index(profile, "(deny file-read* file-write*")
	if blockDenyIdx < 0 {
		t.Fatal("profile must have blocked-path deny section")
	}
	blockDenyInDeny := strings.Contains(profile[blockDenyIdx:], `(subpath "`+blockPath+`")`)
	if !blockDenyInDeny {
		t.Error("blocked path must be in the deny section")
	}

	if blockDenyIdx < readAllowIdx {
		t.Error("blocked-path deny must come AFTER the read-allow set for last-match-wins override")
	}
}

// TestSbplEscapeBackslashThenQuote verifies sbplEscape escapes backslash then double-quote
// (order matters for SBPL syntax).
func TestSbplEscapeBackslashThenQuote(t *testing.T) {
	// Test the critical case: a string with both backslash and double-quote
	// sbplEscape must escape backslash first, then quote.
	// Input: a\"b (chars: a, \, ", b)
	// Step 1: ReplaceAll(\→\\): the original \ is replaced by \\
	//   chars: a, \, \, ", b (5 chars total)
	// Step 2: ReplaceAll("→\"): the original " is replaced by \"
	//   chars: a, \, \, \, ", b (6 chars total)

	input := `a\"b` // chars: a, \, ", b
	got := sbplEscape(input)
	// Expected result: a, \, \, \, ", b (a, three backslashes, quote, b)
	want := "a" + "\\" + "\\" + "\\" + "\"" + "b"
	if got != want {
		t.Errorf("sbplEscape(%q) = %q, want %q", input, got, want)
	}
}

// TestSbplEscapeNewlineTabUnescaped verifies sbplEscape leaves newline/tab characters
// unescaped.
func TestSbplEscapeNewlineTabUnescaped(t *testing.T) {
	input := "a\nb\tc"
	got := sbplEscape(input)
	if !strings.Contains(got, "\n") || !strings.Contains(got, "\t") {
		t.Errorf("sbplEscape must leave newline/tab unescaped; got %q", got)
	}
}

// TestMetadataAncestorsRootSeed verifies metadataAncestors with seed "/" returns empty
// (no ancestors at root).
func TestMetadataAncestorsRootSeed(t *testing.T) {
	seeds := []string{"/"}
	got := metadataAncestors(seeds)
	if len(got) != 0 {
		t.Errorf("metadataAncestors([\"/\"]) must return empty; got %v", got)
	}
}

// TestMetadataAncestorsDeduplicate verifies metadataAncestors with duplicate seed paths
// de-duplicates and sorts.
func TestMetadataAncestorsDeduplicate(t *testing.T) {
	seeds := []string{"/Users/u/a", "/Users/u/a", "/Users/u/b"}
	got := metadataAncestors(seeds)
	// Should have /Users, /Users/u, /Users/u/b (not duplicated /Users/u)
	seen := map[string]int{}
	for _, p := range got {
		seen[p]++
	}
	for p, count := range seen {
		if count > 1 {
			t.Errorf("metadataAncestors must de-duplicate; %q appears %d times", p, count)
		}
	}
	// Should also be sorted
	for i := 1; i < len(got); i++ {
		if got[i] < got[i-1] {
			t.Errorf("metadataAncestors must be sorted; %q comes after %q", got[i-1], got[i])
		}
	}
}

// TestReadOnlyTargetsExcludesWritable verifies ReadOnlyTargets excludes paths that are
// also writable (writeSet check).
func TestReadOnlyTargetsExcludesWritable(t *testing.T) {
	tok := macTestTokens()
	spec := sandbox.SandboxSpec{Tokens: tok}

	// compileMacOSBaseline returns read and write sets. $AGENT_CONFIG_DIR is in both (writable).
	// ReadOnlyTargets should exclude it.
	ro := macBackend().ReadOnlyTargets(spec)

	claudeDir := tok["AGENT_CONFIG_DIR"]
	for _, p := range ro {
		if p == claudeDir {
			t.Errorf("ReadOnlyTargets must exclude writable paths; %q is writable and should not appear", claudeDir)
		}
	}

	// /usr is read-only (in read but not write)
	found := false
	for _, p := range ro {
		if p == "/usr" {
			found = true
			break
		}
	}
	if !found {
		t.Error("ReadOnlyTargets must include read-only baseline paths like /usr")
	}
}

// TestReadOnlyTargetsSkipsRegex verifies ReadOnlyTargets skips regex rules (only non-regex
// paths returned).
func TestReadOnlyTargetsSkipsRegex(t *testing.T) {
	tok := macTestTokens()
	spec := sandbox.SandboxSpec{Tokens: tok}
	ro := macBackend().ReadOnlyTargets(spec)

	// Regex rules like ^/dev/ttys should not appear in the output
	for _, p := range ro {
		if strings.Contains(p, "^") || strings.Contains(p, "#") {
			t.Errorf("ReadOnlyTargets must skip regex rules; got %q", p)
		}
	}
}

// TestReadOnlyTargetsSkipsNonRecursiveNodes verifies ReadOnlyTargets skips non-recursive
// literal nodes. The baseline's traversal-only rules ("/", /etc, /var, /tmp, /dev/null …)
// expose a single node, not a subtree, so a paths.rw grant nested under one shadows
// nothing. Returning "/" in particular would make the launcher's paths.rw-overlap advisory
// fire on every grant, since every absolute path is nested under it.
func TestReadOnlyTargetsSkipsNonRecursiveNodes(t *testing.T) {
	tok := macTestTokens()
	spec := sandbox.SandboxSpec{Tokens: tok}
	ro := macBackend().ReadOnlyTargets(spec)

	for _, p := range ro {
		switch p {
		case "/", "/private/etc", "/private/var", "/private/tmp", "/dev/null":
			t.Errorf("ReadOnlyTargets must skip non-recursive traversal nodes; got %q", p)
		}
	}
}

// TestArgvSortsEnvKeys verifies Argv sorts SetEnv keys for deterministic output.
func TestArgvSortsEnvKeys(t *testing.T) {
	spec := sandbox.SandboxSpec{
		WorkDir: "/Users/u/proj",
		SetEnv: map[string]string{
			"Z": "z", "A": "a", "M": "m", "B": "b",
		},
		Tokens: macTestTokens(),
	}
	argv, err := macBackend().Argv(spec, []string{"echo", "hi"})
	if err != nil {
		t.Fatal(err)
	}

	// argv is: sandbox-exec -p <profile> /usr/bin/env -i <sorted-env> <command>
	// Find the /usr/bin/env index
	envIdx := -1
	for i, arg := range argv {
		if arg == "/usr/bin/env" {
			envIdx = i
			break
		}
	}
	if envIdx < 0 {
		t.Fatal("argv must contain /usr/bin/env")
	}

	// Env vars come after /usr/bin/env and -i
	// Extract the keys in order
	var envKeys []string
	for i := envIdx + 2; i < len(argv); i++ {
		arg := argv[i]
		if !strings.Contains(arg, "=") {
			break // reached command
		}
		key := strings.SplitN(arg, "=", 2)[0]
		envKeys = append(envKeys, key)
	}

	// Verify they are sorted
	for i := 1; i < len(envKeys); i++ {
		if envKeys[i] < envKeys[i-1] {
			t.Errorf("env keys must be sorted; %q comes after %q", envKeys[i-1], envKeys[i])
		}
	}
}

// The strict-containment check seatbelt uses for $HOME ancestor derivation
// (pathutil.Under) is locked canonically by pathutil.TestUnder — including the seatbelt
// /Users/u equal/under/sibling cases. The behavioral guarantee that only paths strictly
// under $HOME become ancestors is covered by the homePaths assertion in
// TestCompileMacOSBaselineBehavior and the golden SBPL profiles.

// TestProfileMountUnderHomeMetadata verifies a profile with a mount under $HOME includes
// the mount and its ancestors in metadata.
func TestProfileMountUnderHomeMetadata(t *testing.T) {
	home := "/Users/u"
	mountPath := "/Users/u/work/ro"
	tok := macTestTokens()
	tok["HOME"] = home

	spec := sandbox.SandboxSpec{
		WorkDir: home + "/proj",
		Mounts: []sandbox.Mount{
			{Src: mountPath, ReadOnly: true},
		},
		SetEnv: map[string]string{},
		Tokens: tok,
	}
	profile, err := macBackend().profile(spec)
	if err != nil {
		t.Fatal(err)
	}

	// The mount's ancestors should be in metadata (file-read-metadata section)
	// /Users/u/work should be a metadata ancestor
	metaSection := "(allow file-read-metadata"
	metaIdx := strings.Index(profile, metaSection)
	if metaIdx < 0 {
		t.Fatal("profile must have metadata section")
	}

	if !strings.Contains(profile[metaIdx:], `(literal "/Users/u/work")`) {
		t.Error("mount's parent directory must be in metadata-ancestors for realpath resolution")
	}
}

// TestCompileMacOSBaselinePartiallyResolvedToken verifies compileMacOSBaseline skips rules
// with missing tokens (not partially resolved).
func TestCompileMacOSBaselinePartiallyResolvedToken(t *testing.T) {
	// The scenario of "partially resolved" tokens (some expanded, some left unreplaced)
	// is impossible in practice: ExpandPath returns ok=false if any referenced token
	// ($VAR) is missing or empty, so the rule is skipped entirely — there is no
	// partial expansion. This test verifies that behavior: a rule with a missing token
	// is skipped and never emitted (even as partially resolved).
	//
	// Example: path "$HOME/$UNKNOWN/proj" where UNKNOWN is undefined.
	// ExpandPath encounters $UNKNOWN, finds it missing, returns ok=false.
	// compileMacOSBaseline skips the rule entirely — nothing is emitted for it.
	rules := []sandbox.Rule{{
		Path:        "$HOME/$UNKNOWN/proj",
		Description: "test rule with missing token",
		Archs:       []string{"macos"},
	}}
	tok := map[string]string{"HOME": "/Users/u"} // UNKNOWN is missing
	read, _, _ := compileMacOSBaseline(rules, tok, noResolve{})

	// Assertion: the path is not in the result (rule skipped, not partially emitted).
	// A regression would emit something like "/Users/u/$UNKNOWN/proj" or similar.
	for _, it := range read {
		// The rule must be completely absent; no partial matches allowed.
		if strings.Contains(it.val, "UNKNOWN") || strings.Contains(it.val, "/Users/u/") {
			t.Errorf("compileMacOSBaseline must skip rules with missing tokens; "+
				"got %q (should be absent due to missing UNKNOWN)", it.val)
		}
	}
}

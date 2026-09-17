package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/sandbox"
)

// testHomeDir resolves the default private home for agent (empty = the default agent) under
// the given host env, failing the test if the provider reports itself disabled.
func testHomeDir(t *testing.T, agent, realHome string, env map[string]string) string {
	t.Helper()
	cfg := &config.Config{Agent: agent}
	cfg.Providers.Home.Enabled = true
	dir, ok := homeDir(cfg, realHome, env)
	if !ok {
		t.Fatal("homeDir: provider unexpectedly disabled")
	}
	return dir
}

// isKeyedHome reports whether d is a ~/.cache/corral/home-<8 hex> sibling of the bare home.
func isKeyedHome(d, realHome string) bool {
	bare := filepath.Join(realHome, ".cache", "corral", "home")
	name := filepath.Base(d)
	return filepath.Dir(d) == filepath.Dir(bare) && strings.HasPrefix(name, "home-") && len(name) == len("home-")+8
}

// TestHomeDirKeyedToConfigDir pins the default private home's keying: every agent config dir,
// default or relocated, maps to its own stable ~/.cache/corral/home-<hash>, so two setups never
// share caches or dotfiles. The bare ~/.cache/corral/home is never a default.
func TestHomeDirKeyedToConfigDir(t *testing.T) {
	const realHome = "/home/u"
	got := func(env map[string]string) string { return testHomeDir(t, "", realHome, env) }

	// Unset and explicit-default CLAUDE_CONFIG_DIR both mean ~/.claude, hence one keyed home.
	def := got(nil)
	if !isKeyedHome(def, realHome) {
		t.Errorf("default config dir should yield a keyed home-<8hex>, got %q", def)
	}
	if d := got(map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(realHome, ".claude")}); d != def {
		t.Errorf("explicit default config dir: got %q, want %q", d, def)
	}

	// Distinct relocated config dirs get distinct keyed homes, none of them the default's.
	personal := got(map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(realHome, ".claude-personal")})
	work := got(map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(realHome, ".claude-work")})
	for _, d := range []string{personal, work} {
		if !isKeyedHome(d, realHome) || d == def {
			t.Errorf("relocated config dir should yield its own keyed home-<8hex>, got %q", d)
		}
	}
	if personal == work {
		t.Errorf("distinct config dirs must yield distinct homes, both got %q", personal)
	}

	// Keying is stable across calls and across spellings of the same path.
	if again := got(map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(realHome, ".claude-personal", ".")}); again != personal {
		t.Errorf("same config dir (different spelling) must be stable: got %q, want %q", again, personal)
	}

	// An explicit providers.home.path overrides the keying entirely.
	cfg := &config.Config{}
	cfg.Providers.Home.Enabled = true
	cfg.Providers.Home.Path = "/custom/home"
	if d, _ := homeDir(cfg, realHome, map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(realHome, ".claude-personal")}); d != "/custom/home" {
		t.Errorf("explicit home path must win: got %q, want /custom/home", d)
	}
}

// TestHomeDirDistinctPerAgent proves the keying separates agents: claude's default (~/.claude),
// pi's default (~/.pi), and a relocated pi dir (PI_CODING_AGENT_DIR) map to three different
// homes, so a claude session and a pi session never share one private home.
func TestHomeDirDistinctPerAgent(t *testing.T) {
	const realHome = "/home/u"
	claude := testHomeDir(t, "", realHome, nil)
	pi := testHomeDir(t, "pi", realHome, nil)
	piWork := testHomeDir(t, "pi", realHome, map[string]string{"PI_CODING_AGENT_DIR": filepath.Join(realHome, ".pi-work")})

	for _, d := range []string{claude, pi, piWork} {
		if !isKeyedHome(d, realHome) {
			t.Errorf("every default should be a keyed home-<8hex>, got %q", d)
		}
	}
	if claude == pi || pi == piWork || claude == piWork {
		t.Errorf("agents and relocated dirs must not share a home: claude=%q pi=%q pi-work=%q", claude, pi, piWork)
	}
}

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
	detected, err := linkHome(spec, realHome, fakeHome, "linux", nil, filepath.Join(realHome, ".claude"), false)
	if err != nil {
		t.Fatalf("linkHome (detect): %v", err)
	}
	if tgt, _ := os.Readlink(stale); tgt != "/nonexistent/wrong" {
		t.Errorf("detect-only pass must not retarget a stale symlink, got %q", tgt)
	}
	if _, err := os.Lstat(filepath.Join(fakeHome, ".config")); err == nil {
		t.Error("detect-only pass must not create anything in the private home")
	}

	shadows, err := linkHome(spec, realHome, fakeHome, "linux", nil, filepath.Join(realHome, ".claude"), true)
	if err != nil {
		t.Fatalf("linkHome: %v", err)
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
	shadows, err := linkHome(spec, realHome, fakeHome, "linux", []string{"work", ".local"}, filepath.Join(realHome, ".claude"), true)
	if err != nil {
		t.Fatalf("linkHome: %v", err)
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
	shadows, err := linkHome(spec, realHome, fakeHome, "linux", []string{".claude"}, configDir, true)
	if err != nil {
		t.Fatalf("linkHome: %v", err)
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
	shadows, err := linkHome(spec, realHome, fakeHome, "linux", nil, "", true)
	if err != nil {
		t.Fatalf("linkHome: %v", err)
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
	kept, err := linkHome(spec, realHome, fakeHome, "linux", []string{".claude"}, "", true)
	if err != nil {
		t.Fatalf("linkHome (kept): %v", err)
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
		_, err := linkHome(spec, realHome, fakeHome, "linux", nil, "", apply)
		if !errors.Is(err, syscall.ENOTDIR) {
			t.Errorf("apply=%v: want ENOTDIR to fail the pass closed, got %v", apply, err)
		}
	}
}

// TestHookGuardDir pins which config dir keep never covers: claude's default ~/.claude, read
// through $HOME; nothing for a relocated claude dir (forwarded absolute) or for pi (enforcement
// rides on argv).
func TestHookGuardDir(t *testing.T) {
	const realHome = "/home/u"
	for _, tc := range []struct {
		name  string
		agent string
		env   map[string]string
		want  string
	}{
		{"claude default", "claude", nil, filepath.Join(realHome, ".claude")},
		{"claude relocated", "claude", map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(realHome, "work", "claude")}, ""},
		{"pi", "pi", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hookGuardDir(&config.Config{Agent: tc.agent}, realHome, tc.env); got != tc.want {
				t.Errorf("hookGuardDir() = %q, want %q", got, tc.want)
			}
		})
	}
}

// shadowLaunchFixture prepares a launch whose host home has a real ~/.gitconfig (a baseline
// candidate) and returns the default private home cmdRun will resolve for it.
func shadowLaunchFixture(t *testing.T) (hostHome, proj, privHome string) {
	t.Helper()
	hostHome = t.TempDir()
	proj = filepath.Join(hostHome, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, hostHome, proj)
	stubUpdateCheck(t)
	mustWriteFile(t, filepath.Join(hostHome, ".gitconfig"))
	return hostHome, proj, testHomeDir(t, "", hostHome, nil)
}

const gitconfigShadow = "$HOME/.gitconfig is a real file in the private home"

// TestRunDryRunReportsPrivateHomeShadow pins that the detect pass runs on the dry run's preview:
// the banner carries the shadow warning while the private copy stays a real file.
func TestRunDryRunReportsPrivateHomeShadow(t *testing.T) {
	hostHome, proj, privHome := shadowLaunchFixture(t)
	mustWriteFile(t, filepath.Join(privHome, ".gitconfig"))

	var code int
	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			code = cmdRun([]string{"--dry-run", "--home", hostHome, "--project", proj}, "dev")
		})
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, gitconfigShadow) {
		t.Errorf("dry-run banner must warn about the shadowed .gitconfig:\n%s", stderr)
	}
	if isSymlink(t, filepath.Join(privHome, ".gitconfig")) {
		t.Error("dry-run must not run the linking pass")
	}
}

// TestRunPrivateHomeShadowGatesBeforeMint pins that the shadow warning prints above the gate: a
// declined launch shows it and never reaches the Mint seam.
func TestRunPrivateHomeShadowGatesBeforeMint(t *testing.T) {
	hostHome, proj, privHome := shadowLaunchFixture(t)
	mustWriteFile(t, filepath.Join(privHome, ".gitconfig"))

	origConfirm := confirmProceed
	t.Cleanup(func() { confirmProceed = origConfirm })
	confirmProceed = func(bool, *os.File, io.Writer, ansi) bool { return false }
	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		t.Error("a declined launch reached the Mint seam: the shadow warning must gate before any provider mints")
		return &providers.Resolved{}, nil
	}

	var code int
	stderr := captureStderr(t, func() {
		code = cmdRun([]string{"--home", hostHome, "--project", proj}, "dev")
	})
	if code == 0 {
		t.Errorf("a declined launch must abort with a non-zero code, got %d", code)
	}
	iShadow, iAbort := strings.Index(stderr, gitconfigShadow), strings.Index(stderr, "launch aborted")
	if iShadow < 0 || iAbort < 0 || iShadow > iAbort {
		t.Errorf("the shadow warning must print before the gate (shadow=%d abort=%d):\n%s", iShadow, iAbort, stderr)
	}
}

// TestRunLateShadowPrintsAfterBody pins the linking pass's report: a shadow that appears after
// the gate (here, during the mint) is printed once, below the banner body, not lost. Driven with
// the seatbelt backend, unavailable off macOS, so the launch aborts after the body but before exec.
func TestRunLateShadowPrintsAfterBody(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this test forces the seatbelt backend to be UNAVAILABLE; only deterministic off macOS")
	}
	hostHome, proj, privHome := shadowLaunchFixture(t)

	origConfirm := confirmProceed
	t.Cleanup(func() { confirmProceed = origConfirm })
	confirmProceed = func(bool, *os.File, io.Writer, ansi) bool { return true }
	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		mustWriteFile(t, filepath.Join(privHome, ".gitconfig")) // appears after the gate
		return &providers.Resolved{}, nil
	}

	var code int
	stderr := captureStderr(t, func() {
		code = cmdRun([]string{"--home", hostHome, "--project", proj, "--backend", "seatbelt"}, "dev")
	})
	if code == 0 {
		t.Fatalf("the seatbelt backend is unavailable off macOS; the launch must abort non-zero, got %d\n%s", code, stderr)
	}
	iBody, iShadow := strings.Index(stderr, "workdir"), strings.Index(stderr, gitconfigShadow)
	if iBody < 0 || iShadow < 0 || iShadow < iBody {
		t.Errorf("a late shadow must print after the banner body (body=%d shadow=%d):\n%s", iBody, iShadow, stderr)
	}
	if n := strings.Count(stderr, gitconfigShadow); n != 1 {
		t.Errorf("a late shadow must print exactly once, got %d:\n%s", n, stderr)
	}
}

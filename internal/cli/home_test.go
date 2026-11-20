package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
)

// testHomeDir resolves the default private home for agent (empty = the default agent) under
// the given host env, failing the test if the provider reports itself disabled.
func testHomeDir(t *testing.T, agent, realHome string, env map[string]string) string {
	t.Helper()
	cfg := &config.Config{Agent: agent}
	cfg.Providers.Home.Enabled = true
	dir, ok := cfg.Providers.Home.Dir(realHome, cfg.AgentConfigDir(realHome, env))
	if !ok {
		t.Fatal("home.Dir: provider unexpectedly disabled")
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
	if d, _ := cfg.Providers.Home.Dir(realHome, cfg.AgentConfigDir(realHome, map[string]string{"CLAUDE_CONFIG_DIR": filepath.Join(realHome, ".claude-personal")})); d != "/custom/home" {
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
	confirmProceed = func(bool, *os.File, io.Writer, report.Style) bool { return false }
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
	confirmProceed = func(bool, *os.File, io.Writer, report.Style) bool { return true }
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
	iBody, iShadow := strings.Index(stderr, "\nproviders "), strings.Index(stderr, gitconfigShadow)
	if iBody < 0 || iShadow < 0 || iShadow < iBody {
		t.Errorf("a late shadow must print after the banner body (body=%d shadow=%d):\n%s", iBody, iShadow, stderr)
	}
	if n := strings.Count(stderr, gitconfigShadow); n != 1 {
		t.Errorf("a late shadow must print exactly once, got %d:\n%s", n, stderr)
	}
}

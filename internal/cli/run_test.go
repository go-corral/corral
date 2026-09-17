package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/providers"
)

// cleanupProvider is a Provider whose Contribution registers a cleanup closure, so
// Resolve produces a *Resolved with HasCleanup()==true — the only way to drive the
// supervised launch path (the real socket-brokers register no cleanup).
type cleanupProvider struct {
	ran *bool
}

func (c cleanupProvider) Name() string                   { return "fake-cleanup" }
func (c cleanupProvider) Available(context.Context) bool { return true }
func (c cleanupProvider) Mint(context.Context, providers.Session, bool) (*providers.Contribution, error) {
	return &providers.Contribution{Cleanup: func(context.Context) error { *c.ran = true; return nil }}, nil
}

func resolvedWithCleanup(t *testing.T, ran *bool) *providers.Resolved {
	t.Helper()
	res, err := providers.Resolve(context.Background(), providers.Session{},
		[]providers.Active{{Provider: cleanupProvider{ran}}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !res.HasCleanup() {
		t.Fatal("expected HasCleanup() true")
	}
	return res
}

// postSessionOnlyProvider registers only a session-end hook (no cleanup), so
// HasPostSession is true while HasCleanup is false — the case that must still force the
// supervised path.
type postSessionOnlyProvider struct{}

func (postSessionOnlyProvider) Name() string                   { return "hooks" }
func (postSessionOnlyProvider) Available(context.Context) bool { return true }
func (postSessionOnlyProvider) Mint(context.Context, providers.Session, bool) (*providers.Contribution, error) {
	return &providers.Contribution{
		PostSession: func(context.Context, providers.SessionExit) error { return nil },
	}, nil
}

// postSessionRecorder registers a session-end hook that records the SessionExit it was
// handed, to assert runSupervised derives it correctly from the child's wait status.
type postSessionRecorder struct{ got *providers.SessionExit }

func (postSessionRecorder) Name() string                   { return "hooks" }
func (postSessionRecorder) Available(context.Context) bool { return true }
func (p postSessionRecorder) Mint(context.Context, providers.Session, bool) (*providers.Contribution, error) {
	return &providers.Contribution{
		PostSession: func(_ context.Context, e providers.SessionExit) error { *p.got = e; return nil },
	}, nil
}

// mustSupervise ORs HasCleanup with HasPostSession: a post-session-only config (no
// cleanup) must still take the supervised path, and a config with neither keeps the
// syscall.Exec fast path.
func TestMustSuperviseForksOnPostSessionOnly(t *testing.T) {
	res, err := providers.Resolve(context.Background(), providers.Session{},
		[]providers.Active{{Provider: postSessionOnlyProvider{}}})
	if err != nil {
		t.Fatal(err)
	}
	if res.HasCleanup() {
		t.Fatal("this provider must register no cleanup (the point of the test)")
	}
	if !mustSupervise(res) {
		t.Error("a post-session-only config must take the supervised path, not syscall.Exec")
	}

	// Neither cleanup nor a hook → the exec fast path.
	empty, err := providers.Resolve(context.Background(), providers.Session{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if mustSupervise(empty) {
		t.Error("a config with neither cleanup nor a post-session hook must keep the exec fast path")
	}
}

// runSupervised runs the session-end hooks after the child exits, handing them a
// SessionExit derived from the wait status (exit 0, exit N, or signaled) while still
// propagating the child's exit code unchanged.
func TestRunSupervisedRunsPostSessionWithDerivedExit(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantCode int
		want     providers.SessionExit
	}{
		{"exit0", []string{"sh", "-c", "exit 0"}, 0, providers.SessionExit{Started: true, Code: 0}},
		{"exitN", []string{"sh", "-c", "exit 5"}, 5, providers.SessionExit{Started: true, Code: 5}},
		{"signaled", []string{"sh", "-c", "kill -TERM $$"}, 143, providers.SessionExit{Started: true, Code: 143, Signaled: true}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got providers.SessionExit
			res, err := providers.Resolve(context.Background(), providers.Session{},
				[]providers.Active{{Provider: postSessionRecorder{got: &got}}})
			if err != nil {
				t.Fatal(err)
			}
			code := runSupervised("/bin/sh", c.args, res)
			if code != c.wantCode {
				t.Errorf("exit code = %d, want %d", code, c.wantCode)
			}
			if got != c.want {
				t.Errorf("post-session exit = %+v, want %+v", got, c.want)
			}
		})
	}
}

// failingCleanupProvider registers a failing cleanup that records whether the teardown ctx
// carried a deadline, to pin abortAfterMint's bounded-and-surfaced contract.
type failingCleanupProvider struct {
	bounded *bool
}

func (p failingCleanupProvider) Name() string                   { return "fake-minter" }
func (p failingCleanupProvider) Available(context.Context) bool { return true }
func (p failingCleanupProvider) Mint(context.Context, providers.Session, bool) (*providers.Contribution, error) {
	return &providers.Contribution{
		Cleanup: func(ctx context.Context) error {
			_, *p.bounded = ctx.Deadline()
			return errorString("revoke failed")
		},
		CleanupHint: "the minted token may still be live",
	}, nil
}

// abortAfterMint runs after a successful mint, so Cleanup must be bounded against a stuck
// endpoint and surface failures that may leave credentials live.
func TestAbortAfterMintBoundsAndSurfacesCleanup(t *testing.T) {
	bounded := false
	res, err := providers.Resolve(context.Background(), providers.Session{},
		[]providers.Active{{Provider: failingCleanupProvider{bounded: &bounded}}})
	if err != nil {
		t.Fatal(err)
	}
	stderr := captureStderr(t, func() { abortAfterMint(res) })
	if !bounded {
		t.Error("abortAfterMint must hand Cleanup a bounded context (a stuck revoke would hang the abort forever)")
	}
	if !strings.Contains(stderr, "the minted token may still be live") {
		t.Errorf("a failed revoke on the abort path must surface the CleanupHint remedy:\n%s", stderr)
	}
	if !strings.Contains(stderr, "provider cleanup") {
		t.Errorf("the joined teardown error must be reported:\n%s", stderr)
	}
	// nil-safe, like the Resolved methods it wraps (the deferred launch teardown may see nil).
	abortAfterMint(nil)
}

func TestRunSupervisedPropagatesExitCodeAndCleansUp(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"success", []string{"sh", "-c", "exit 0"}, 0},
		{"nonzero", []string{"sh", "-c", "exit 5"}, 5},
		{"signaled", []string{"sh", "-c", "kill -TERM $$"}, 143}, // 128 + SIGTERM(15)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ran := false
			res := resolvedWithCleanup(t, &ran)
			got := runSupervised("/bin/sh", c.args, res)
			if got != c.want {
				t.Errorf("exit code = %d, want %d", got, c.want)
			}
			if !ran {
				t.Error("provider cleanup must run after the supervised child exits")
			}
		})
	}
}

// TestRunSupervisedLaunchesEmptyEnv guards the /proc/1/environ leak fix: the sandbox launcher
// (bwrap) is PID 1 of the unshared PID namespace, so its environ is readable from inside the
// sandbox via /proc/1/environ. The launcher must therefore start it with an empty environment
// rather than os.Environ(). The exec'd child still gets its filtered env through --setenv.
//
// Two controls, because a single non-zero assertion can pass vacuously (a bad launcher path
// makes runSupervised return 1 via fatalf; a typo in the probe name makes `test -n ""` exit 1):
//
//   - Positive control: launch /bin/sh directly with os.Environ() and assert the probe is
//     present (exit 0). This proves /bin/sh launches as a child here and the probe name is
//     spelled right, so a non-zero result from the negative control can only mean the env was
//     actually empty — not that sh failed to start or the name was wrong.
//   - Negative control: runSupervised (empty launcher env) must exit exactly 1, the code
//     `test -n ""` returns on an unset var. exit 0 would mean the host env leaked back in.
func TestRunSupervisedLaunchesEmptyEnv(t *testing.T) {
	const probe = "CORRAL_LAUNCH_ENV_PROBE"
	t.Setenv(probe, "secret")
	// runSupervised strips argv[0] (exec.Command(launcherAbs, argv[1:]...)), so the
	// supervised call needs the launcher name as argv[0]; the bare exec.Command call does not.
	detect := `test -n "$` + probe + `"`
	supervisedArgs := []string{"sh", "-c", detect} // argv[0] stripped -> /bin/sh -c detect
	bareArgs := []string{"-c", detect}             // -> /bin/sh -c detect

	// Positive control: the detector must fire when the host env is passed through.
	pos := exec.Command("/bin/sh", bareArgs...)
	pos.Env = os.Environ()
	posErr := pos.Run()
	if posErr != nil {
		t.Fatalf("positive control: /bin/sh with os.Environ() should see %s and exit 0 (test -n true), "+
			"but got exit %d — either /bin/sh does not launch as a child here (so the negative "+
			"control's non-zero is meaningless) or the probe name is misspelled (so the detector "+
			"never fires and the negative control would pass vacuously): %v",
			probe, exitCode(posErr), posErr)
	}

	// Negative control: runSupervised must not pass the host env to its child.
	res, err := providers.Resolve(context.Background(), providers.Session{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	code := runSupervised("/bin/sh", supervisedArgs, res)
	switch code {
	case 0:
		t.Fatal("runSupervised passed the host env to its child (exit 0); the launcher must use an " +
			"empty env so /proc/1/environ cannot leak host secrets — regression to os.Environ()")
	case 1:
		// probe correctly absent — the fix holds.
	default:
		t.Fatalf("runSupervised exit %d, want exactly 1 (test -n on an unset var); the positive "+
			"control already proved /bin/sh launches and the probe name is correct, so this is "+
			"unexpected", code)
	}
}

// TestRunDryRunSkipsProviderMint: `corral run --dry-run` must be side-effect-free — it must
// not reach resolveProviders (the sole path to Mint), because Minting makes live API calls
// (mint+revoke a GitLab token, create+delete a k8s ServiceAccount + RBAC) and needs valid
// host credentials, purely to print the would-be command. A dry-run that reaches
// resolveProviders fails the test. The dry-run still names a credential-minter it cannot
// expand without minting (gitlab) in a secret-free note.
func TestRunDryRunSkipsProviderMint(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// Enable a credential-minter (gitlab): its mounts/env are only known after minting,
	// so it cannot be previewed — the dry-run must name it without Minting it. The buggy
	// path would Mint here (a live GitLab API call).
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"),
		[]byte("providers:\n  gitlab:\n    enabled: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	// A non-empty host GITLAB_TOKEN makes the gitlab provider Available (the check is mere
	// token presence — no network), so it reaches the "would mint at launch" note rather
	// than being skipped as unavailable. It is never forwarded into the sandbox.
	t.Setenv("GITLAB_TOKEN", "x")

	orig := resolveProviders
	t.Cleanup(func() { resolveProviders = orig })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		t.Error("--dry-run resolved providers: it must not Mint (dry-run must be side-effect-free)")
		return &providers.Resolved{}, nil
	}

	var code int
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
		})
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d", code)
	}
	// The would-be command still prints faithfully on stdout.
	launcher := "bwrap"
	if runtime.GOOS == "darwin" {
		launcher = "sandbox-exec"
	}
	if !strings.Contains(stdout, launcher) {
		t.Errorf("dry-run did not print the %s command:\n%s", launcher, stdout)
	}
	// …and a secret-free note names the credential-minter that would mint at launch.
	if !strings.Contains(stderr, "not expanded") || !strings.Contains(stderr, "gitlab") {
		t.Errorf("dry-run did not note the unexpanded credential-minter on stderr:\n%s", stderr)
	}
}

// TestRunDryRunFoldsProviderProfile is the positive half of the dry-run contract: the
// printed profile must reflect the providers that a real launch would assemble, not the
// bare pre-provider spec. The default-on home provider's writable $HOME bind must appear even
// though the dry run never creates its backing directory.
func TestRunDryRunFoldsProviderProfile(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d", code)
	}
	// Default config dir (~/.claude) → the bare ~/.cache/corral/home private home.
	privateHome := filepath.Join(home, ".cache", "corral", "home")
	if !strings.Contains(out, privateHome) {
		t.Errorf("dry-run profile did not fold in the home provider's private $HOME %q:\n%s", privateHome, out)
	}
	// The dry run is side-effect-free: the backing dir must not have been created.
	if _, err := os.Stat(privateHome); !os.IsNotExist(err) {
		t.Errorf("dry-run created the private home %q (stat err=%v); preview must not mutate the filesystem", privateHome, err)
	}
}

// captureStderr runs fn while capturing what it writes to os.Stderr (mirrors
// captureStdout; the two compose — outer captureStderr, inner captureStdout).
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func TestExitCodeNilIsZero(t *testing.T) {
	if got := exitCode(nil); got != 0 {
		t.Errorf("exitCode(nil) = %d, want 0", got)
	}
}

// confirmResponse is default-no: only an explicit y/yes proceeds; empty, EOF (""),
// and anything else decline.
func TestConfirmResponse(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"y\n", true}, {"Y\n", true}, {"yes\n", true}, {"  YES \n", true}, {"y", true},
		{"\n", false}, {"", false}, {"n\n", false}, {"no\n", false}, {"nope\n", false},
		{"yeah\n", false}, {"ye\n", false},
	} {
		if got := confirmResponse(c.in); got != c.want {
			t.Errorf("confirmResponse(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// confirmProceed proceeds without prompting when --yes is set or when stdin is not a
// terminal (a regular file stands in for the non-tty case — a pipe/redirect/CI). The
// interactive read path needs a real TTY and is covered by TestConfirmResponse plus the
// cross-platform manual checklist. A non-interactive launch with warnings must keep its
// prior always-launch behavior, and must not emit a prompt nobody can answer.
func TestConfirmProceedSkipsPromptWhenNotInteractive(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stdin") // regular file: not a char device
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, yes := range []bool{false, true} {
		var out strings.Builder
		if !confirmProceed(yes, f, &out, ansi{}) {
			t.Errorf("confirmProceed(yes=%v, non-tty) = false, want true (proceed)", yes)
		}
		if out.Len() != 0 {
			t.Errorf("confirmProceed(yes=%v, non-tty) printed a prompt %q; must stay silent", yes, out.String())
		}
	}
}

// A character-device mode bit cannot identify an interactive terminal: /dev/null must take the
// silent non-interactive path.
func TestConfirmProceedDevNullNonInteractive(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	for _, yes := range []bool{false, true} {
		var out strings.Builder
		if !confirmProceed(yes, f, &out, ansi{}) {
			t.Errorf("confirmProceed(yes=%v, /dev/null) = false, want true (proceed)", yes)
		}
		if out.Len() != 0 {
			t.Errorf("confirmProceed(yes=%v, /dev/null) printed a prompt %q; must stay silent", yes, out.String())
		}
	}
}

// TestRunDeclinedLaunchDoesNotMint ensures the advisory gate precedes credential creation.
func TestRunDeclinedLaunchDoesNotMint(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// kubernetes bound to a write-capable role (`edit`, not a known read-only role) → the
	// static "bound role" advisory. A real launch would mint a SA + RBAC + token for it.
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"),
		[]byte("providers:\n  kubernetes:\n    enabled: true\n    permissions:\n      - clusterWide: true\n        clusterRole: edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	origConfirm := confirmProceed
	t.Cleanup(func() { confirmProceed = origConfirm })
	confirmProceed = func(bool, *os.File, io.Writer, ansi) bool { return false } // decline

	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		t.Error("a declined launch reached the Mint seam: warnings + confirmation must gate BEFORE any provider mints")
		return &providers.Resolved{}, nil
	}
	stubUpdateCheck(t)

	var code int
	stderr := captureStderr(t, func() {
		code = cmdRun([]string{"--home", home, "--project", proj}, "dev")
	})
	if code == 0 {
		t.Errorf("a declined launch must abort with a non-zero code, got %d", code)
	}
	// The advisory the operator declined was shown before the gate, and the launch aborted.
	if !strings.Contains(stderr, `bound role "edit"`) {
		t.Errorf("the kubernetes write-role warning must be shown before the gate:\n%s", stderr)
	}
	if !strings.Contains(stderr, "launch aborted") {
		t.Errorf("a declined launch must report it aborted:\n%s", stderr)
	}
}

// TestRunMintsOnlyAfterConfirmation is the positive complement: when the operator confirms
// (or there is nothing to confirm), the launch proceeds to Mint — and only then. The Mint
// seam asserts the gate already ran, then returns an error to stop the launch cleanly before
// the backend ceremony, keeping the test free of a real bwrap/sandbox-exec.
func TestRunMintsOnlyAfterConfirmation(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"),
		[]byte("providers:\n  kubernetes:\n    enabled: true\n    permissions:\n      - clusterWide: true\n        clusterRole: edit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	confirmed := false
	origConfirm := confirmProceed
	t.Cleanup(func() { confirmProceed = origConfirm })
	confirmProceed = func(bool, *os.File, io.Writer, ansi) bool { confirmed = true; return true } // proceed

	minted := false
	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		minted = true
		if !confirmed {
			t.Error("Mint ran before the confirmation gate")
		}
		// Stop the launch here, after the gate, so the test never needs a real backend.
		return nil, errResolveStub
	}
	stubUpdateCheck(t)

	code := cmdRun([]string{"--home", home, "--project", proj}, "dev")
	if !minted {
		t.Error("a confirmed launch must reach the Mint seam")
	}
	if code == 0 {
		t.Errorf("the stubbed Mint error must fail the launch closed, got code %d", code)
	}
}

// The banner reorder: phase-B mint runs between the gate and the banner body, so a preStart
// session hook's surfaced stderr lands above the config summary, and the providers tree prints
// as one contiguous block (body's built-in rows immediately followed by the feature rows)
// instead of splitting across the mint. Driven with the seatbelt backend, which is unavailable off
// macOS, so the launch aborts cleanly after the body+notices have printed but before any exec.
func TestRunBannerBodyPrintsAfterMint(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this test forces the seatbelt backend to be UNAVAILABLE; only deterministic off macOS")
	}
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// docker enabled raises the static "root-equivalent" advisory (a header warning, above the
	// gate); home disabled keeps linkHome out of the path so the abort point is purely the
	// backend-availability check.
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"),
		[]byte("providers:\n  docker:\n    enabled: true\n  home:\n    enabled: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	stubUpdateCheck(t)

	origConfirm := confirmProceed
	t.Cleanup(func() { confirmProceed = origConfirm })
	confirmProceed = func(bool, *os.File, io.Writer, ansi) bool { return true } // past the gate

	const hookEra = "LIVE-HOOK-STDERR-MARKER"
	const featureNote = "minted-feature-MARKER"
	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		// Stand in for a preStart session hook's surfaced stderr, emitted during phase-B mint.
		fmt.Fprintln(os.Stderr, hookEra)
		return &providers.Resolved{Notices: []providers.Notice{{Provider: "hooks", Text: featureNote}}}, nil
	}

	var code int
	stderr := captureStderr(t, func() {
		code = cmdRun([]string{"--home", home, "--project", proj, "--backend", "seatbelt"}, "dev")
	})
	if code == 0 {
		t.Fatalf("the seatbelt backend is unavailable off macOS; the launch must abort non-zero, got %d\n%s", code, stderr)
	}
	iWarn := strings.Index(stderr, "root-equivalent") // header warning, above the gate
	iHook := strings.Index(stderr, hookEra)           // phase-B mint output
	iBody := strings.Index(stderr, "workdir")         // banner body (config summary)
	iNote := strings.Index(stderr, featureNote)       // feature-provider notice (tree tail)
	if iWarn < 0 || iHook < 0 || iBody < 0 || iNote < 0 {
		t.Fatalf("a region is missing: warn=%d hook=%d body=%d note=%d\n%s", iWarn, iHook, iBody, iNote, stderr)
	}
	// The live hook output sits between the gate (below the header warning) and the tree.
	if iWarn >= iHook || iHook >= iBody {
		t.Errorf("phase-B hook output must fall between the gate and the banner body:\n%s", stderr)
	}
	// The providers tree is contiguous: body then feature notices, nothing between them.
	if iBody >= iNote {
		t.Errorf("feature notices must follow the banner body (one unsplit providers tree):\n%s", stderr)
	}
	if strings.Contains(stderr[iBody:iNote], hookEra) {
		t.Errorf("no live hook output may split the body from the feature notices:\n%s", stderr)
	}
}

// TestRunSignalDuringMintAbortsClosed pins the mint-to-launch signal contract: an interrupt
// during phase B must abort the launch through the fail-closed teardown, not kill corral
// with the default disposition (which would skip every teardown — no defer survives signal
// death). The seam delivers SIGTERM to the test process itself and blocks until the launch
// ctx reflects it, so each regression stays loud: an uninstalled handler kills the whole
// test binary, a non-signal-aware ctx times the wait out, and a swallowed post-mint signal
// launches anyway (caught by the exit code + abort message).
func TestRunSignalDuringMintAbortsClosed(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	stubUpdateCheck(t)

	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(ctx context.Context, _ providers.Session, _ []providers.Active) (*providers.Resolved, error) {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		select {
		case <-ctx.Done():
		case <-time.After(10 * time.Second):
			t.Error("the launch ctx never reflected the signal: the mint window is not signal-aware")
		}
		return &providers.Resolved{}, nil
	}

	var code int
	stderr := captureStderr(t, func() {
		code = cmdRun([]string{"--home", home, "--project", proj}, "dev")
	})
	if code == 0 {
		t.Errorf("an interrupted mint must abort the launch, got exit 0\n%s", stderr)
	}
	if !strings.Contains(stderr, "launch aborted") {
		t.Errorf("the interrupt abort must be reported:\n%s", stderr)
	}
}

// TestRunPostMintAbortFiresTeardown pins the deferred launch teardown: an abort after a
// successful mint (here the forced seatbelt backend is unavailable off macOS — one of the
// several post-mint abort sites) must fire the paired session-end hooks with the zero
// "aborted" SessionExit and the credential revoke. One defer covers every post-mint abort
// path, so a future abort site cannot forget the pairing.
func TestRunPostMintAbortFiresTeardown(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("this test forces the seatbelt backend to be UNAVAILABLE; only deterministic off macOS")
	}
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// home disabled keeps linkHome out of the path so the abort point is purely the
	// backend-availability check.
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"),
		[]byte("providers:\n  home:\n    enabled: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	stubUpdateCheck(t)
	origConfirm := confirmProceed
	t.Cleanup(func() { confirmProceed = origConfirm })
	confirmProceed = func(bool, *os.File, io.Writer, ansi) bool { return true }

	cleaned := false
	exit := providers.SessionExit{Started: true, Code: 99} // sentinel: overwritten iff the hook ran
	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(ctx context.Context, sess providers.Session, _ []providers.Active) (*providers.Resolved, error) {
		return providers.Resolve(ctx, sess, []providers.Active{
			{Provider: cleanupProvider{ran: &cleaned}},
			{Provider: postSessionRecorder{got: &exit}},
		})
	}

	var code int
	stderr := captureStderr(t, func() {
		code = cmdRun([]string{"--home", home, "--project", proj, "--backend", "seatbelt"}, "dev")
	})
	if code == 0 {
		t.Fatalf("the seatbelt backend is unavailable off macOS; the launch must abort non-zero\n%s", stderr)
	}
	if !cleaned {
		t.Error("a post-mint abort must run the providers' LIFO cleanup (credential revoke)")
	}
	if (exit != providers.SessionExit{}) {
		t.Errorf("the session-end hook got %+v; want the zero SessionExit (fired, signalling an aborted launch)", exit)
	}
}

// End-to-end through the real launcher wiring (config → registry → providers.Resolve → real
// `sh` hooks), not the resolveProviders seam: the two session-hook properties that only hold if
// every layer agrees.
func TestRunSessionHooksEndToEnd(t *testing.T) {
	// setup writes a project with the given providers.hooks block and returns (exit code,
	// stderr). files land 0o644; scripts land 0o755 — a hook's exec is a real executable now,
	// run directly (shebang, no shell).
	setup := func(t *testing.T, hooksYAML string, files, scripts map[string]string) (string, int, string) {
		t.Helper()
		home := t.TempDir()
		proj := filepath.Join(home, "proj")
		if err := os.MkdirAll(proj, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(proj, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for name, content := range scripts {
			if err := os.WriteFile(filepath.Join(proj, name), []byte(content), 0o755); err != nil {
				t.Fatal(err)
			}
		}
		// home disabled keeps linkHome out of the path; the launch aborts in phase B either way.
		cfg := "providers:\n  home:\n    enabled: false\n" + hooksYAML
		if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
		isolateConfigEnv(t, home, proj)
		stubUpdateCheck(t)
		origConfirm := confirmProceed
		t.Cleanup(func() { confirmProceed = origConfirm })
		confirmProceed = func(bool, *os.File, io.Writer, ansi) bool { return true }

		var code int
		stderr := captureStderr(t, func() {
			code = cmdRun([]string{"--home", home, "--project", proj}, "dev")
		})
		return proj, code, stderr
	}

	// A preStart failure aborts the launch — and still fires the paired postEnd, which is the
	// abort an operator most expects their cleanup script to see. The marker records
	// CORRAL_AGENT_EXIT, so this also pins the "aborted" signal end to end.
	t.Run("preStart abort still fires the paired postEnd", func(t *testing.T) {
		proj, code, stderr := setup(t, "  hooks:\n"+
			"    preStart:\n      10-fail:\n        exec: ./fail.sh\n"+
			"    postEnd:\n      90-cleanup:\n        exec: ./cleanup.sh\n", nil,
			map[string]string{
				"fail.sh":    "#!/bin/sh\nexit 3\n",
				"cleanup.sh": "#!/bin/sh\nprintf %s \"$CORRAL_AGENT_EXIT\" > post-end.marker\n",
			})
		if code == 0 {
			t.Fatalf("a non-optional preStart failure must abort the launch\n%s", stderr)
		}
		if !strings.Contains(stderr, "providers.hooks.preStart.10-fail") {
			t.Errorf("the abort must attribute the failing entry:\n%s", stderr)
		}
		got, err := os.ReadFile(filepath.Join(proj, "post-end.marker"))
		if err != nil {
			t.Fatalf("the paired postEnd hook never ran: %v\n%s", err, stderr)
		}
		if string(got) != "aborted" {
			t.Errorf("CORRAL_AGENT_EXIT = %q, want \"aborted\" (the agent never ran)", got)
		}
	})

	// A contributed env var naming one of corral's control markers fails the launch closed, on a
	// host where the launcher itself never set that marker (no global config is loaded here, so
	// CORRAL_GLOBAL_CONFIG is absent from the spec) — the case an unclaimed name would slip
	// through. Also exercises the stdout contribution channel with a real shell.
	t.Run("contributed control marker fails closed", func(t *testing.T) {
		contrib := `{"corralContributionVersion":1,"env":{"CORRAL_GLOBAL_CONFIG":"/work/evil.yml"}}`
		_, code, stderr := setup(t,
			"  hooks:\n    preStart:\n      10-plant:\n        exec: ./plant.sh\n",
			map[string]string{"contribution.json": contrib},
			map[string]string{"plant.sh": "#!/bin/sh\ncat contribution.json\n"})
		if code == 0 {
			t.Fatalf("planting a corral control marker must fail the launch closed\n%s", stderr)
		}
		if !strings.Contains(stderr, "reserved control marker") {
			t.Errorf("the abort must name the reservation:\n%s", stderr)
		}
	})
}

// A real launch prints the launch-time update notice (when one exists) on the banner,
// before the gate — so the user sees it before claude takes the terminal.
func TestRunPrintsUpdateNotice(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	orig := checkUpdateOnStart
	t.Cleanup(func() { checkUpdateOnStart = orig })
	checkUpdateOnStart = func(context.Context, *config.Config, string, string) string {
		return "a newer corral is available: 0.3.0 → 0.4.0 — run 'corral update'"
	}
	// Stop the launch right after the banner/notice so the test needs no real backend.
	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		return nil, errResolveStub
	}

	stderr := captureStderr(t, func() { cmdRun([]string{"--home", home, "--project", proj}, "0.3.0") })
	if !strings.Contains(stderr, "newer corral is available") {
		t.Errorf("launch banner did not show the update notice:\n%s", stderr)
	}
}

// An update notice is shown beside ordinary launch warnings but does not create the gate.
// This isolated Claude setup has a missing-integration warning; declining its gate must abort
// before any provider mints while still leaving the update notice visible.
func TestRunWarningsGateWithUpdateNotice(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	origCheck := checkUpdateOnStart
	t.Cleanup(func() { checkUpdateOnStart = origCheck })
	checkUpdateOnStart = func(context.Context, *config.Config, string, string) string {
		return "a newer corral is available: 0.3.0 → 0.4.0 — run 'corral update'"
	}

	origConfirm := confirmProceed
	t.Cleanup(func() { confirmProceed = origConfirm })
	confirmProceed = func(bool, *os.File, io.Writer, ansi) bool { return false } // decline

	origResolve := resolveProviders
	t.Cleanup(func() { resolveProviders = origResolve })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		t.Error("a declined warning gate reached the Mint seam")
		return &providers.Resolved{}, nil
	}

	var code int
	stderr := captureStderr(t, func() { code = cmdRun([]string{"--home", home, "--project", proj}, "0.3.0") })
	if code == 0 {
		t.Errorf("a declined launch must abort with a non-zero code, got %d", code)
	}
	if !strings.Contains(stderr, "newer corral is available") {
		t.Errorf("the update notice must be shown before the gate:\n%s", stderr)
	}
	if !strings.Contains(stderr, "launch aborted") {
		t.Errorf("a declined launch must report it aborted:\n%s", stderr)
	}
}

// stubUpdateCheck silences the launch-time update check for a real-launch test, so it
// never reaches the network (which would be slow/flaky in tests). Restored on cleanup.
func stubUpdateCheck(t *testing.T) {
	t.Helper()
	orig := checkUpdateOnStart
	t.Cleanup(func() { checkUpdateOnStart = orig })
	checkUpdateOnStart = func(context.Context, *config.Config, string, string) string { return "" }
}

// errResolveStub stops a confirmed launch right after the gate (see the test above).
var errResolveStub = errorString("resolve stub: stop after the gate")

type errorString string

func (e errorString) Error() string { return string(e) }

// A launch from a normal project dir mounts that dir at its own path, untouched.
func TestResolveWorkdirProjectUnchanged(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj") // a subdir of home, not home itself
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	src, sub, err := resolveWorkdir(home, proj, false)
	if err != nil {
		t.Fatalf("resolveWorkdir: %v", err)
	}
	if sub || src != proj {
		t.Errorf("got src=%q sub=%v; want the project returned unchanged (mounted at its own path)", src, sub)
	}
}

// A launch from $HOME must not bind home: it gets a fresh scratch dir, created on
// disk, mounted at its own (neutral, random) path — the same own-path model both
// backends use (no /temp-work remap, which macOS Seatbelt could not honor).
func TestResolveWorkdirHomeSubstitutesScratch(t *testing.T) {
	home := t.TempDir()
	src, sub, err := resolveWorkdir(home, home, false)
	if err != nil {
		t.Fatalf("resolveWorkdir: %v", err)
	}
	if !sub {
		t.Fatal("a launch from home must be substituted")
	}
	if src == home || pathutil.Resolve(src) == pathutil.Resolve(home) {
		t.Errorf("scratch src %q must not be home %q", src, home)
	}
	if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
		t.Errorf("scratch dir %q must exist as a directory (err=%v)", src, err)
	}
	if !strings.HasPrefix(filepath.Base(src), "corral-work-") {
		t.Errorf("scratch dir %q should carry the corral-work- prefix", src)
	}
	_ = os.Remove(src)
}

// TestSplitAgentArg pins the `corral run [agent] ...` positional grammar: a registered first
// token is peeled as the agent; a flag, an unknown token, or a `--`-escaped name is left in
// place (so it parses as a flag or an argument for the default agent).
func TestSplitAgentArg(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		wantAgent string
		wantRest  []string
	}{
		{"empty", nil, "", nil},
		{"agent only", []string{"pi"}, "pi", []string{}},
		{"agent then flags", []string{"pi", "--dry-run"}, "pi", []string{"--dry-run"}},
		{"claude explicit", []string{"claude", "--home", "/x"}, "claude", []string{"--home", "/x"}},
		{"flag first is not an agent", []string{"--dry-run", "pi"}, "", []string{"--dry-run", "pi"}},
		{"unknown first token", []string{"fix the bug"}, "", []string{"fix the bug"}},
		{"dash-dash escapes the name", []string{"--", "pi"}, "", []string{"--", "pi"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAgent, gotRest := splitAgentArg(tt.args)
			if gotAgent != tt.wantAgent {
				t.Errorf("agent = %q, want %q", gotAgent, tt.wantAgent)
			}
			if !slices.Equal(gotRest, tt.wantRest) {
				t.Errorf("rest = %v, want %v", gotRest, tt.wantRest)
			}
		})
	}
}

// TestRunAgentPositionalSelectsPi verifies the positional flows into the whole spec, not just
// the binary: selecting pi must build the sandbox with pi's config dir (~/.pi), proving
// cfg.Agent drives AgentConfigDir/AgentLaunch downstream. It also asserts the baseline is
// agent-neutral — `run pi` must bind no claude path (~/.claude.json is a claude-only
// ConfigPath, not an embedded baseline rule), so pi never sees another agent's auth state.
func TestRunAgentPositionalSelectsPi(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"pi", "--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d", code)
	}
	// corral binds pi's ~/.pi umbrella as the agent config dir (not just ~/.pi/agent), so the
	// dry-run argv must show it — and it distinguishes pi from claude's ~/.claude.
	piDir := filepath.Join(home, ".pi")
	if !strings.Contains(out, piDir) {
		t.Errorf("`run pi` dry-run argv missing pi config dir %q (positional did not select pi):\n%s", piDir, out)
	}
	// The baseline is agent-neutral: claude's out-of-config-dir files (~/.claude.json and the
	// macOS siblings) are claude's ConfigPaths, not embedded baseline rules, so `run pi` must
	// expose none of them. (Guards the cross-agent leak this fix closed.)
	if strings.Contains(out, ".claude.json") {
		t.Errorf("`run pi` must not bind a claude path, but argv contains .claude.json:\n%s", out)
	}
}

// TestRunPiActivatesBridge verifies the pi policy bridge is activated at launch: the embedded
// asset is materialized to the host cache, bound read-only into the sandbox, and passed to pi
// via `-e <path>`. Without this, pi would run with FS isolation but no tool-call policy.
func TestRunPiActivatesBridge(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"pi", "--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d", code)
	}
	bridge := filepath.Join(home, ".cache", "corral", "corral-policy.ts")
	// The asset was materialized on the host...
	if _, err := os.Stat(bridge); err != nil {
		t.Errorf("pi bridge was not materialized at %q: %v", bridge, err)
	}
	// ...bound read-only into the sandbox, and activated via `-e <path>`.
	if !strings.Contains(out, bridge) {
		t.Errorf("`run pi` argv missing the bridge path %q (not bound/activated):\n%s", bridge, out)
	}
	if !strings.Contains(out, "-e "+bridge) {
		t.Errorf("`run pi` argv missing `-e %s` activation:\n%s", bridge, out)
	}
}

// TestRunBridgeAgentSuppressesSettingsAdvisory verifies the claude-only settings.json
// advisories (the "run corral sync" sync-state warning and the fullscreen-TUI warning) are
// shown for a command-hook agent (claude) but suppressed for a bridge agent (pi) — telling a
// pi user to `corral sync` would be wrong, since pi has no settings.json.
func TestRunBridgeAgentSuppressesSettingsAdvisory(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	run := func(agent string) string {
		return captureStderr(t, func() {
			_ = captureStdout(t, func() {
				cmdRun([]string{agent, "--dry-run", "--home", home, "--project", proj}, "dev")
			})
		})
	}
	if claudeErr := run("claude"); !strings.Contains(claudeErr, "settings.json") {
		t.Errorf("claude launch should show the settings.json sync advisory:\n%s", claudeErr)
	}
	// pi must not show the claude-specific settings.json advisory (it has its own presence
	// advisory, which mentions `corral sync pi` but never settings.json).
	if piErr := run("pi"); strings.Contains(piErr, "settings.json") {
		t.Errorf("pi launch must NOT show the claude settings.json advisory:\n%s", piErr)
	}
}

// Home is detected through a symlink: a symlinked launch path that resolves to home
// is still substituted.
func TestResolveWorkdirHomeViaSymlink(t *testing.T) {
	home := t.TempDir()
	link := filepath.Join(t.TempDir(), "homelink")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	_, sub, err := resolveWorkdir(home, link, false)
	if err != nil {
		t.Fatalf("resolveWorkdir: %v", err)
	}
	if !sub {
		t.Error("a symlink resolving to home must be detected as home")
	}
}

// A failure to create the scratch dir is reported as an error (fails the launch
// closed), not silently swallowed. Forced deterministically by pointing $TMPDIR at
// a regular file, so os.MkdirTemp cannot create anything under it.
func TestResolveWorkdirScratchCreateError(t *testing.T) {
	home := t.TempDir()
	notADir := filepath.Join(t.TempDir(), "tmpfile")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", notADir) // os.TempDir() honors $TMPDIR; MkdirTemp will fail under a file
	if _, _, err := resolveWorkdir(home, home, false); err == nil {
		t.Error("a scratch-dir creation failure must return an error, not be swallowed")
	}
}

// On a dry run the scratch dir is not created (no $TMPDIR litter), but a
// representative path is still returned so the printed command stays faithful.
func TestResolveWorkdirDryRunDoesNotCreate(t *testing.T) {
	home := t.TempDir()
	src, sub, err := resolveWorkdir(home, home, true)
	if err != nil {
		t.Fatalf("resolveWorkdir: %v", err)
	}
	if !sub {
		t.Fatalf("dry run from home should still substitute; got sub=%v", sub)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("dry run must not create the scratch dir %q (stat err=%v)", src, err)
	}
}

// TestRunMacOSIsolatesTempDir guards the temp-isolation fix: on macOS the shared
// per-user $TMPDIR must not reach claude — TMP/TMPDIR/TEMPDIR/CLAUDE_CODE_TMPDIR all
// point at a fresh per-session dir instead (the Seatbelt analogue of Linux's tmpfs).
func TestRunMacOSIsolatesTempDir(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only: temp isolation runs in the Seatbelt launch path")
	}
	// The launcher creates the session dir under /tmp; skip where /tmp is not writable
	// (e.g. a restrictive outer sandbox) since isolation can't be exercised there.
	if d, err := os.MkdirTemp("/tmp", "corral-test-"); err != nil {
		t.Skipf("/tmp not writable here (%v); cannot exercise macOS temp isolation", err)
	} else {
		_ = os.RemoveAll(d)
	}
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	shared := t.TempDir() // a host $TMPDIR that must not leak through to claude
	t.Setenv("TMPDIR", shared)

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d", code)
	}

	tmpdir := envVal(out, "TMPDIR")
	if !strings.HasPrefix(tmpdir, "/tmp/corral-") {
		t.Errorf("TMPDIR must point at an isolated /tmp/corral-* dir, got %q", tmpdir)
	}
	if strings.HasPrefix(tmpdir, strings.TrimRight(shared, "/")+"/") || tmpdir == shared {
		t.Errorf("TMPDIR must not be under the shared host dir %q", shared)
	}
	for _, k := range []string{"TMP", "TEMPDIR", "CLAUDE_CODE_TMPDIR"} {
		if v := envVal(out, k); v != tmpdir {
			t.Errorf("%s=%q, want %q (all temp vars share the session dir)", k, v, tmpdir)
		}
	}
	// The dry-run must not leave the session dir behind.
	if _, err := os.Stat(tmpdir); err == nil {
		t.Errorf("dry-run leaked the session temp dir %q", tmpdir)
	}
}

func TestRunDryRunReflectsConfig(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte("providers: {block: {directories: [/data/vault]}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("run --dry-run exit=%d", code)
	}
	// The config-blocked path is masked in the generated bwrap argv.
	if !strings.Contains(out, "/data/vault") {
		t.Errorf("config blocked path not reflected in sandbox argv:\n%s", out)
	}
}

// TestRunDryRunReflectsPathsGrants: a providers.paths grant must reach the generated
// argv via the built-in paths provider — the registry Enabled/Build wiring end-to-end
// (the block and env siblings have their own guards; paths had none at this layer).
func TestRunDryRunReflectsPathsGrants(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	rw := filepath.Join(home, "shared-rw")
	ro := filepath.Join(home, "shared-ro")
	for _, d := range []string{proj, rw, ro} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cfg := "providers:\n  paths:\n    rw: [" + rw + "]\n    ro: [" + ro + "]\n"
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("run --dry-run exit=%d", code)
	}
	if !strings.Contains(out, rw) || !strings.Contains(out, ro) {
		t.Errorf("paths grants not reflected in sandbox argv:\n%s", out)
	}
	// On the bwrap backend the kind is visible too: rw grants compile to --bind-try,
	// ro grants to --ro-bind-try (same-path Optional mounts).
	if runtime.GOOS == "linux" {
		if !strings.Contains(out, "--bind-try "+rw) || !strings.Contains(out, "--ro-bind-try "+ro) {
			t.Errorf("grant kinds not reflected (want --bind-try rw / --ro-bind-try ro):\n%s", out)
		}
	}
}

// TestRunBindsCustomClaudeConfigDir: a custom CLAUDE_CONFIG_DIR must be bound into the
// sandbox and forwarded via --setenv, or the sandboxed claude loses its logged-in account +
// trusted folders.
func TestRunBindsCustomClaudeConfigDir(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	cfgDir := filepath.Join(home, "alt-claude")
	for _, d := range []string{proj, cfgDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	isolateConfigEnv(t, home, proj)
	t.Setenv("CLAUDE_CONFIG_DIR", cfgDir)

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("run --dry-run exit=%d", code)
	}
	if !strings.Contains(out, cfgDir) {
		t.Errorf("custom CLAUDE_CONFIG_DIR not bound into sandbox argv:\n%s", out)
	}
	// CLAUDE_CONFIG_DIR must be forwarded into the cleared environment: bwrap uses
	// --setenv, the Seatbelt backend uses `/usr/bin/env -i CLAUDE_CONFIG_DIR=…`.
	wantEnv := "--setenv CLAUDE_CONFIG_DIR"
	if runtime.GOOS == "darwin" {
		wantEnv = "CLAUDE_CONFIG_DIR=" + cfgDir
	}
	if !strings.Contains(out, wantEnv) {
		t.Errorf("CLAUDE_CONFIG_DIR not forwarded (%q):\n%s", wantEnv, out)
	}
	// claude's ~/.claude.json (a $HOME-root file outside the config dir) is contributed by the
	// claude agent as a ConfigPath and must still be exposed — the counterpart to the pi case
	// in TestRunAgentPositionalSelectsPi, proving the agent rule round-trips into the spec.
	if !strings.Contains(out, ".claude.json") {
		t.Errorf("`run claude` must bind ~/.claude.json (claude ConfigPath):\n%s", out)
	}
}

// TestRunForwardsEnvSet is the end-to-end guard that an env.set entry reaches the cleared
// sandbox environment. Exercises the full launcher path (config load + validate →
// applyEnvSet → spec → backend argv) on whichever backend compiles the spec.
func TestRunForwardsEnvSet(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"),
		[]byte("providers:\n  env:\n    set:\n      - {name: CORRAL_TEST_FOO, value: bar}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("run --dry-run exit=%d", code)
	}
	// bwrap forwards via `--setenv CORRAL_TEST_FOO bar`; the Seatbelt backend via
	// `/usr/bin/env -i … CORRAL_TEST_FOO=bar`.
	want := "--setenv CORRAL_TEST_FOO bar"
	if runtime.GOOS == "darwin" {
		want = "CORRAL_TEST_FOO=bar"
	}
	if !strings.Contains(out, want) {
		t.Errorf("env.set var not forwarded (%q):\n%s", want, out)
	}
}

// envVal extracts KEY's value from a `/usr/bin/env -i KEY=VAL …` dry-run line. Temp
// paths under /var/folders contain no shell-special chars, so they are unquoted and
// space-delimited.
// envVal extracts an env assignment's value from a shell-quoted dry-run argv. shellQuote runs each
// arg through syntax.Quote, which single-quotes a KEY=value word (it would otherwise parse as a
// shell assignment), so the assignment appears as 'KEY=value' — or bare KEY=value when a build ever
// emits it unquoted. Match either at a word boundary and read the value up to the next quote or space.
func envVal(out, key string) string {
	for _, pre := range []string{" '", " "} {
		needle := pre + key + "="
		i := strings.Index(out, needle)
		if i < 0 {
			continue
		}
		rest := out[i+len(needle):]
		if j := strings.IndexAny(rest, "' "); j >= 0 {
			return rest[:j]
		}
		return rest
	}
	return ""
}

// TestEnvVal guards the argv parser TestRunMacOSIsolatesTempDir relies on: the dry-run argv is
// shell-quoted, so env assignments appear single-quoted ('TMPDIR=…'), and the key match must not
// bleed across a longer neighbour (CLAUDE_CODE_TMPDIR, TMPPREFIX). Runs anywhere (no /tmp needed).
func TestEnvVal(t *testing.T) {
	quoted := "sandbox-exec -p '(version 1)' /usr/bin/env -i " +
		"'CLAUDE_CODE_TMPDIR=/tmp/corral-501-abc' 'PATH=/usr/bin' 'TEMPDIR=/tmp/corral-501-abc' " +
		"'TMP=/tmp/corral-501-abc' 'TMPDIR=/tmp/corral-501-abc' 'TMPPREFIX=/tmp/corral-501-abc/zsh' /claude"
	for _, tc := range []struct{ key, want string }{
		{"TMPDIR", "/tmp/corral-501-abc"},
		{"TMP", "/tmp/corral-501-abc"},
		{"TEMPDIR", "/tmp/corral-501-abc"},
		{"CLAUDE_CODE_TMPDIR", "/tmp/corral-501-abc"},
		{"TMPPREFIX", "/tmp/corral-501-abc/zsh"},
		{"PATH", "/usr/bin"},
		{"ABSENT", ""},
	} {
		if got := envVal(quoted, tc.key); got != tc.want {
			t.Errorf("envVal(quoted, %q) = %q, want %q", tc.key, got, tc.want)
		}
	}
	// A key must not match a longer neighbour: with only CLAUDE_CODE_TMPDIR present, "TMPDIR" is absent.
	if got := envVal("cmd -i 'CLAUDE_CODE_TMPDIR=/x' end", "TMPDIR"); got != "" {
		t.Errorf(`envVal must not match CLAUDE_CODE_TMPDIR for key "TMPDIR", got %q`, got)
	}
	// The bare (unquoted) form still parses.
	if got := envVal("cmd -i CLAUDE_CODE_TMPDIR=/x TMP=/y TMPDIR=/z end", "TMPDIR"); got != "/z" {
		t.Errorf("envVal bare TMPDIR = %q, want /z", got)
	}
}

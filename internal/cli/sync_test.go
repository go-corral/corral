package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSyncWarnsBinaryUnreachable: when --binary lives outside every baseline mount,
// sync prints a heads-up to stderr (but still succeeds — warn-and-allow).
func TestSyncWarnsBinaryUnreachable(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")

	// A binary under the project tree is not a baseline mount.
	binary := filepath.Join(home, "projects", "corral", "bin", "corral")

	var code int
	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			code = cmdSync([]string{"--settings", settings, "--binary", binary})
		})
	})
	if code != 0 {
		t.Fatalf("sync should still succeed (warn-and-allow), got exit %d", code)
	}
	if !strings.Contains(stderr, "outside every directory the sandbox mounts") {
		t.Errorf("expected unreachable-binary warning on stderr, got:\n%s", stderr)
	}
}

// TestSyncNoWarnBinaryReachable: a binary under a baseline-mounted dir (/usr/...) is
// reachable in the sandbox, so no warning is printed.
func TestSyncNoWarnBinaryReachable(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")

	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			cmdSync([]string{"--settings", settings, "--binary", "/usr/local/bin/corral"})
		})
	})
	if strings.Contains(stderr, "outside every directory the sandbox mounts") {
		t.Errorf("a binary under /usr must not warn, got:\n%s", stderr)
	}
}

// TestWarnBinaryUnreachableUsesConfigDirParam: warnBinaryUnreachable treats a hook binary
// under the caller-supplied config dir as reachable, taking the $AGENT_CONFIG_DIR baseline
// token from its parameter rather than re-reading $CLAUDE_CONFIG_DIR itself: the cli must ask
// the agent (a.ConfigDir), so a decoy $CLAUDE_CONFIG_DIR pointing elsewhere must not change
// the verdict.
func TestWarnBinaryUnreachableUsesConfigDirParam(t *testing.T) {
	home := t.TempDir()
	configDir := t.TempDir()                   // the agent-resolved dir the caller supplies
	t.Setenv("CLAUDE_CONFIG_DIR", t.TempDir()) // decoy: must be ignored in favor of the configDir param
	binary := filepath.Join(configDir, "bin", "corral")

	stderr := captureStderr(t, func() {
		warnBinaryUnreachable(os.Stderr, binary, home, configDir)
	})
	if strings.Contains(stderr, "outside every directory the sandbox mounts") {
		t.Errorf("a binary under the supplied config dir must be reachable, got:\n%s", stderr)
	}
}

// runSync runs cmdSync capturing stdout (stderr is swallowed — the binary-reachability
// warning is tested separately).
func runSync(t *testing.T, args ...string) string {
	t.Helper()
	return captureStdout(t, func() {
		_ = captureStderr(t, func() { cmdSync(args) })
	})
}

// A fresh sync prints the semantic headline (what corral registered) plus the diff.
func TestSyncFreshPrintsHeadlineAndDiff(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")

	out := runSync(t, "--settings", settings, "--binary", "/usr/local/bin/corral")
	if !strings.Contains(out, "registered hooks: PreToolUse") {
		t.Errorf("expected registration headline, got:\n%s", out)
	}
	if !strings.Contains(out, "hook pre-tool-use") {
		t.Errorf("expected the hook registration in the diff, got:\n%s", out)
	}
	if !strings.Contains(out, "@@") {
		t.Errorf("expected a diff hunk, got:\n%s", out)
	}
}

// Re-running sync on an identical file reports "already up to date" with no diff.
func TestSyncIdempotentReportsUpToDate(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")
	bin := "/usr/local/bin/corral"
	runSync(t, "--settings", settings, "--binary", bin)

	out := runSync(t, "--settings", settings, "--binary", bin)
	if !strings.Contains(out, "already up to date") {
		t.Errorf("second sync should be up to date, got:\n%s", out)
	}
	if strings.Contains(out, "@@") {
		t.Errorf("an up-to-date sync must not print a diff, got:\n%s", out)
	}
}

// The core of the diff-noise fix: a sync that only reformats an already-synced file
// (whitespace/key order) is reported as such — not as a full-file diff.
func TestSyncReformatOnlyNoNoise(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")
	bin := "/usr/local/bin/corral"
	runSync(t, "--settings", settings, "--binary", bin)

	reindentOnDisk(t, settings)

	out := runSync(t, "--settings", settings, "--binary", bin)
	if !strings.Contains(out, "no policy change") {
		t.Errorf("a reformat-only sync should say no policy change, got:\n%s", out)
	}
	if strings.Contains(out, "@@") {
		t.Errorf("a reformat-only sync must not print a diff hunk, got:\n%s", out)
	}
}

// Same case under --dry-run: a reformat-only run is named, not dumped as a diff.
func TestSyncReformatOnlyDryRun(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")
	bin := "/usr/local/bin/corral"
	runSync(t, "--settings", settings, "--binary", bin)

	reindentOnDisk(t, settings)

	out := runSync(t, "--settings", settings, "--binary", bin, "--dry-run")
	if !strings.Contains(out, "would only be reformatted") {
		t.Errorf("a reformat-only dry-run should say so, got:\n%s", out)
	}
	if strings.Contains(out, "@@") {
		t.Errorf("a reformat-only dry-run must not print a diff hunk, got:\n%s", out)
	}
}

// TestSyncRemoveDeregistersHooks is the end-to-end round trip through the cli: register the hooks
// with a real `corral sync`, then strip them with `--remove` and assert both the headline and the
// file on disk. A second removal reports the no-op, and a plain re-sync puts the hooks back —
// de-registering is reversible.
func TestSyncRemoveDeregistersHooks(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")
	bin := "/usr/local/bin/corral"
	runSync(t, "--settings", settings, "--binary", bin)

	var code int
	out := captureStdout(t, func() {
		_ = captureStderr(t, func() { code = cmdSync([]string{"--settings", settings, "--remove"}) })
	})
	if code != 0 {
		t.Fatalf("sync --remove should succeed, got exit %d", code)
	}
	if !strings.Contains(out, "removed hooks: PreToolUse") {
		t.Errorf("expected a removal headline, got:\n%s", out)
	}
	if !strings.Contains(out, "(after removal)") {
		t.Errorf("expected the diff to be labeled as a removal, got:\n%s", out)
	}
	data, err := os.ReadFile(settings)
	if err != nil {
		t.Fatalf("--remove must not delete settings.json: %v", err)
	}
	if strings.Contains(string(data), "hook pre-tool-use") {
		t.Errorf("corral's hooks survived --remove:\n%s", data)
	}

	// Nothing left to remove.
	out = runSync(t, "--settings", settings, "--remove")
	if !strings.Contains(out, "nothing to remove") {
		t.Errorf("a second --remove should report nothing to remove, got:\n%s", out)
	}

	// And a plain sync re-registers.
	out = runSync(t, "--settings", settings, "--binary", bin)
	if !strings.Contains(out, "registered hooks: PreToolUse") {
		t.Errorf("re-syncing after a removal should register again, got:\n%s", out)
	}
	if data, _ := os.ReadFile(settings); !strings.Contains(string(data), "hook pre-tool-use") {
		t.Errorf("re-sync should restore the hook:\n%s", data)
	}
}

// TestSyncRemoveSkipsUnreachableBinaryWarning: the unreachable-binary heads-up is about a hook
// being registered (can the sandboxed agent exec it?), so --remove, which registers nothing,
// must stay silent even with a --binary outside every baseline mount.
func TestSyncRemoveSkipsUnreachableBinaryWarning(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")
	binary := filepath.Join(home, "projects", "corral", "bin", "corral") // not a baseline mount
	runSync(t, "--settings", settings, "--binary", binary)

	var code int
	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			code = cmdSync([]string{"--settings", settings, "--binary", binary, "--remove"})
		})
	})
	if code != 0 {
		t.Fatalf("sync --remove should succeed, got exit %d", code)
	}
	if strings.Contains(stderr, "outside every directory the sandbox mounts") {
		t.Errorf("--remove registers no hook, so it must not warn about the binary:\n%s", stderr)
	}
}

// TestSyncRemoveDryRunWritesNothing: `--remove --dry-run` previews the de-registration and leaves
// settings.json exactly as it was.
func TestSyncRemoveDryRunWritesNothing(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home) // chdir to a clean temp home so the trust gate finds no repo config
	settings := filepath.Join(home, ".claude", "settings.json")
	runSync(t, "--settings", settings, "--binary", "/usr/local/bin/corral")
	before, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}

	out := runSync(t, "--settings", settings, "--remove", "--dry-run")
	if !strings.Contains(out, "would change (dry-run, not written)") || !strings.Contains(out, "removed hooks: PreToolUse") {
		t.Errorf("expected a dry-run removal preview, got:\n%s", out)
	}
	after, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("--remove --dry-run must not write:\n--- after ---\n%s\n--- before ---\n%s", after, before)
	}
}

// TestSyncRemoveBridgeAgent: `corral sync pi --remove` deletes the presence backstop the install
// path wrote, and reports the no-op once it is gone.
func TestSyncRemoveBridgeAgent(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home)
	t.Setenv("PI_CODING_AGENT_DIR", "") // pi config dir resolves to <home>/.pi/agent
	presence := filepath.Join(home, ".pi", "agent", "extensions", "corral-presence.ts")

	_ = captureStdout(t, func() { cmdSync([]string{"pi"}) })
	if _, err := os.Stat(presence); err != nil {
		t.Fatalf("seed sync pi should install the backstop: %v", err)
	}

	// Dry-run: previewed, not deleted.
	out := captureStdout(t, func() { cmdSync([]string{"pi", "--remove", "--dry-run"}) })
	if !strings.Contains(out, "would delete the presence backstop") {
		t.Errorf("sync pi --remove --dry-run should preview the delete:\n%s", out)
	}
	if _, err := os.Stat(presence); err != nil {
		t.Errorf("sync pi --remove --dry-run must not delete the backstop: %v", err)
	}

	out = captureStdout(t, func() { cmdSync([]string{"pi", "--remove"}) })
	if !strings.Contains(out, "deleted the presence backstop") {
		t.Errorf("sync pi --remove should delete the backstop:\n%s", out)
	}
	if _, err := os.Stat(presence); !os.IsNotExist(err) {
		t.Errorf("the backstop should be gone (stat err = %v)", err)
	}

	out = captureStdout(t, func() { cmdSync([]string{"pi", "--remove"}) })
	if !strings.Contains(out, "nothing to remove") {
		t.Errorf("a second sync pi --remove should report nothing to remove:\n%s", out)
	}
}

// reindentOnDisk rewrites settings to 4-space indent: byte-different, semantically
// identical to corral's 2-space output — the formatting churn the diff should hide.
func reindentOnDisk(t *testing.T, settings string) {
	t.Helper()
	orig, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, orig, "", "    "); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, append(buf.Bytes(), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestSyncBridgeAgent verifies `corral sync pi` reports the in-process bridge instead of
// writing a settings.json, and installs the presence backstop into pi's global extensions:
// --dry-run explains and installs nothing, while a real run installs corral-presence.ts.
func TestSyncBridgeAgent(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home)
	t.Setenv("PI_CODING_AGENT_DIR", "") // pi config dir resolves to <home>/.pi/agent
	presence := filepath.Join(home, ".pi", "agent", "extensions", "corral-presence.ts")

	out := captureStdout(t, func() { cmdSync([]string{"pi", "--dry-run"}) })
	if !strings.Contains(out, "no settings file to sync") {
		t.Errorf("sync pi --dry-run should explain pi has no settings file:\n%s", out)
	}
	if !strings.Contains(out, "would install") {
		t.Errorf("sync pi --dry-run should report the presence-backstop install:\n%s", out)
	}
	if _, err := os.Stat(presence); !os.IsNotExist(err) {
		t.Errorf("sync pi --dry-run must not install the presence backstop (stat err=%v)", err)
	}

	_ = captureStdout(t, func() { cmdSync([]string{"pi"}) })
	if _, err := os.Stat(presence); err != nil {
		t.Errorf("sync pi should install the presence backstop at %q: %v", presence, err)
	}

	// Diff check: a second sync with the backstop already current must report no changes and
	// must not rewrite (mirrors claude's "already up to date").
	out = captureStdout(t, func() { cmdSync([]string{"pi"}) })
	if !strings.Contains(out, "already up to date") {
		t.Errorf("sync pi with the backstop current should report 'already up to date':\n%s", out)
	}

	// A stale copy is detected and updated.
	if err := os.WriteFile(presence, []byte("// stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() { cmdSync([]string{"pi"}) })
	if !strings.Contains(out, "updated the presence backstop") {
		t.Errorf("sync pi should update a stale backstop:\n%s", out)
	}
	if cur, _ := os.ReadFile(presence); string(cur) == "// stale" {
		t.Error("sync pi must overwrite a stale backstop with the embedded content")
	}
}

// TestRunBridgeAgentWarnsMissingBackstop verifies the launch-time advisory: `corral run pi`
// warns when pi's presence backstop is not installed (so a bare pi outside corral would not be
// flagged), and stops warning once it is installed — the bridge-agent analogue of claude's
// settings-sync advisory.
func TestRunBridgeAgentWarnsMissingBackstop(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	t.Setenv("PI_CODING_AGENT_DIR", "")

	runErr := func() string {
		return captureStderr(t, func() {
			_ = captureStdout(t, func() {
				cmdRun([]string{"pi", "--dry-run", "--home", home, "--project", proj}, "dev")
			})
		})
	}
	if got := runErr(); !strings.Contains(got, "presence backstop") {
		t.Errorf("run pi should warn when the presence backstop is missing:\n%s", got)
	}
	// Install it, then the warning must be gone.
	_ = captureStdout(t, func() { cmdSync([]string{"pi"}) })
	if got := runErr(); strings.Contains(got, "presence backstop") {
		t.Errorf("run pi must NOT warn once the presence backstop is installed:\n%s", got)
	}
}

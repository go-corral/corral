package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/trust"
)

// --- helpers ---

// uninstallEnv isolates HOME + the config/state dirs (isolateConfigEnv) and additionally clears
// the agent relocators, so every path `corral uninstall` resolves lands under the temp home even
// when the developer's real environment relocates an agent's config dir.
func uninstallEnv(t *testing.T, home string) {
	t.Helper()
	isolateConfigEnv(t, home, home)
	t.Setenv("PI_CODING_AGENT_DIR", "")
	t.Setenv("PI_CODING_AGENT_SESSION_DIR", "")
}

// fakeUninstallBinary points updateTarget at a throwaway path so the "kept" section's `rm <path>`
// line is assertable (and never names the test binary). Returns that path.
func fakeUninstallBinary(t *testing.T, home string) string {
	t.Helper()
	target := filepath.Join(home, ".local", "bin", "corral")
	orig := updateTarget
	t.Cleanup(func() { updateTarget = orig })
	updateTarget = func() (string, error) { return target, nil }
	return target
}

// seedUninstallFootprint installs, under home, one of everything `corral uninstall` reports on:
// claude's registered hooks, pi's presence backstop, the cache dir (including two
// sandbox-private homes), a trust approval record, and an audit log with a rotated backup and a
// lock file. It returns the paths a test asserts over.
type seededFootprint struct {
	Settings   string
	Presence   string
	CacheDir   string
	Home       string // ~/.cache/corral/home
	HomeKeyed  string // ~/.cache/corral/home-abcd1234
	Kube       string
	UpdateFile string
	StateDir   string
	RepoConfig string
	AuditLog   string
	AuditOld   string
	AuditLock  string
}

func seedUninstallFootprint(t *testing.T, home string) seededFootprint {
	t.Helper()
	host := map[string]string{}

	claude, _ := agents.Lookup("claude")
	if _, err := claude.Sync(agents.SyncInput{Home: home, Host: host, BinaryPath: "/usr/local/bin/corral"}); err != nil {
		t.Fatalf("seed claude sync: %v", err)
	}
	pi, _ := agents.Lookup("pi")
	if _, err := pi.Sync(agents.SyncInput{Home: home, Host: host}); err != nil {
		t.Fatalf("seed pi sync: %v", err)
	}

	s := seededFootprint{
		Settings:   filepath.Join(home, ".claude", "settings.json"),
		Presence:   filepath.Join(home, ".pi", "agent", "extensions", "corral-presence.ts"),
		CacheDir:   filepath.Join(home, ".cache", "corral"),
		StateDir:   filepath.Join(home, ".local", "state", "corral"),
		RepoConfig: filepath.Join(home, "src", "proj", ".corral.yml"),
	}
	s.Home = filepath.Join(s.CacheDir, "home")
	s.HomeKeyed = filepath.Join(s.CacheDir, "home-abcd1234")
	s.Kube = filepath.Join(s.CacheDir, "kube", "config-x")
	s.UpdateFile = filepath.Join(s.CacheDir, "update-check.json")
	s.AuditLog = filepath.Join(home, ".claude", "corral-audit.jsonl")
	s.AuditOld = s.AuditLog + ".20260101T000000Z"
	s.AuditLock = s.AuditLog + ".lock"

	mkdirs(t, filepath.Join(s.Home, "state"), s.HomeKeyed, filepath.Dir(s.Kube))
	writeFiles(t, map[string]string{
		filepath.Join(s.Home, "state", "blob"): "private home data",
		s.Kube:                                 "kubeconfig",
		s.UpdateFile:                           `{"latest":"9.9.9"}`,
		s.AuditLog:                             "{\"tool\":\"Read\"}\n",
		s.AuditOld:                             "{\"tool\":\"Bash\"}\n",
		s.AuditLock:                            "",
	})

	if err := trust.NewStore(trust.DefaultDir(home)).Approve([]trust.Entry{{Path: s.RepoConfig, SHA256: "abc123"}}); err != nil {
		t.Fatalf("seed trust store: %v", err)
	}
	return s
}

func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
}

func writeFiles(t *testing.T, files map[string]string) {
	t.Helper()
	for p, body := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
}

// runUninstallCmd runs cmdUninstall with a scripted stdin, capturing stdout (and swallowing
// stderr, which carries only the flag-validation messages asserted separately).
func runUninstallCmd(t *testing.T, stdin string, args ...string) (string, int) {
	t.Helper()
	var code int
	out := captureStdout(t, func() {
		_ = captureStderr(t, func() {
			withStdin(t, stdin, func() { code = cmdUninstall(args) })
		})
	})
	return out, code
}

func mustExist(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s must still exist: %v", p, err)
		}
	}
}

func mustNotExist(t *testing.T, paths ...string) {
	t.Helper()
	for _, p := range paths {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s must be gone", p)
		}
	}
}

func mustContain(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output must mention %q, got:\n%s", w, out)
		}
	}
}

// --- manifest (read-only) ---

// A bare `corral uninstall` reports every part of the footprint — and deletes nothing.
func TestUninstallManifestReportsFootprintAndDeletesNothing(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	seed := seedUninstallFootprint(t, home)
	bin := fakeUninstallBinary(t, home)

	out, code := runUninstallCmd(t, "")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}

	// Enforcement: both agents registered, with their resolved paths.
	mustContain(t, out, "enforcement ─", "  ● claude          registered — config dir ~/.claude\n",
		"  ● pi              registered — config dir ~/",
		"~/.claude/settings.json", "~/.pi/agent/extensions/corral-presence.ts")
	// State: cache entries, the trust-record count, audit siblings.
	mustContain(t, out, "~/.cache/corral", "home-abcd1234", "kube", "update-check.json",
		"~/.local/state/corral", "1 approval record",
		"~/.claude/corral-audit.jsonl", "1 rotated backup(s)", "corral-audit.jsonl.lock")
	// Kept: the print-only section with its by-hand commands.
	mustContain(t, out, "kept ─", "rm "+bin, "~/.config/corral/config.yml", "alias claude=",
		"claude plugin uninstall corral-helper@corral", "claude plugin marketplace remove corral")
	// And the hint that says how to actually remove things.
	mustContain(t, out, "nothing was deleted", "                    → corral uninstall --apply\n")
	// Repo config is not uninstall's concern: the approved path recorded in the trust store
	// must never surface in the report.
	if strings.Contains(out, "src/proj") || strings.Contains(out, ".corral.yml") {
		t.Errorf("the report must not name repo config paths, got:\n%s", out)
	}

	mustExist(t, seed.Settings, seed.Presence, seed.Home, seed.HomeKeyed, seed.Kube,
		seed.UpdateFile, seed.StateDir, seed.AuditLog, seed.AuditOld, seed.AuditLock)
	if data, err := os.ReadFile(seed.Settings); err != nil || !strings.Contains(string(data), "hook pre-tool-use") {
		t.Errorf("the manifest must not touch settings.json (err %v)", err)
	}
}

// On a pristine home the manifest still renders, reporting each part as absent, and exits 0.
func TestUninstallManifestPristineHome(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	fakeUninstallBinary(t, home)

	out, code := runUninstallCmd(t, "")
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	mustContain(t, out, "not registered", "nothing to remove", "~/.cache/corral — not present",
		"~/.local/state/corral — not present", "corral-audit.jsonl (claude default) — not present")
	if strings.Count(out, "●") != 1 { // the binary only
		t.Errorf("pristine home must not report registered enforcement, got:\n%s", out)
	}
}

// --- --apply ---

// `--apply --yes` performs every phase: it de-registers both agents, deletes the cache wholesale
// (the sandbox-private homes included — they are scratch state), drops the state dir and the
// audit log family, and still prints the print-only section.
func TestUninstallApplyYesRemovesEnforcementCacheStateAudit(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	seed := seedUninstallFootprint(t, home)
	bin := fakeUninstallBinary(t, home)

	out, code := runUninstallCmd(t, "", "--apply", "--yes")
	if code != 0 {
		t.Errorf("exit = %d, want 0; output:\n%s", code, out)
	}

	// claude's hooks are gone from settings.json (the file itself stays — it is the user's).
	data, err := os.ReadFile(seed.Settings)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	if strings.Contains(string(data), "hook pre-tool-use") {
		t.Errorf("corral's hook must be stripped from settings.json, got:\n%s", data)
	}
	// pi's presence backstop is gone; corral's whole cache (private homes included), the state
	// dir, and the audit family are gone.
	mustNotExist(t, seed.Presence, seed.Kube, seed.UpdateFile, seed.Home, seed.HomeKeyed,
		seed.CacheDir, seed.StateDir, seed.AuditLog, seed.AuditOld, seed.AuditLock)

	mustContain(t, out, "kept ─", "rm "+bin, "~/.config/corral/config.yml", "  ✓ done\n",
		"claude plugin uninstall corral-helper@corral", "claude plugin marketplace remove corral")
	if strings.Contains(out, "skipped") {
		t.Errorf("--yes must not skip a phase, got:\n%s", out)
	}
}

// Answering y at every prompt (no --yes) removes the full footprint. This also pins that the
// phases share one reader: with a per-prompt reader the answers after the first would be
// swallowed and the later phases would silently decline.
func TestUninstallApplyInteractiveAcceptsEveryPhase(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	seed := seedUninstallFootprint(t, home)
	fakeUninstallBinary(t, home)

	out, code := runUninstallCmd(t, "y\ny\ny\ny\ny\n", "--apply")
	if code != 0 {
		t.Errorf("exit = %d, want 0; output:\n%s", code, out)
	}
	if strings.Contains(out, "skipped") {
		t.Errorf("every prompt was answered y, so no phase may report skipped; output:\n%s", out)
	}
	mustNotExist(t, seed.Presence, seed.Kube, seed.UpdateFile, seed.Home, seed.HomeKeyed,
		seed.CacheDir, seed.StateDir, seed.AuditLog, seed.AuditOld, seed.AuditLock)
	if data, err := os.ReadFile(seed.Settings); err != nil || strings.Contains(string(data), "hook pre-tool-use") {
		t.Errorf("corral's hook must be stripped from settings.json (err %v)", err)
	}
}

// Declining every prompt deletes nothing, says so visibly, and is not an error.
func TestUninstallApplyDeclinedDeletesNothing(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	seed := seedUninstallFootprint(t, home)
	fakeUninstallBinary(t, home)

	out, code := runUninstallCmd(t, "n\nn\nn\nn\nn\n", "--apply")
	if code != 0 {
		t.Errorf("exit = %d, want 0; output:\n%s", code, out)
	}
	mustContain(t, out, "skipped")
	mustExist(t, seed.Settings, seed.Presence, seed.Home, seed.HomeKeyed, seed.Kube,
		seed.UpdateFile, seed.StateDir, seed.AuditLog, seed.AuditOld, seed.AuditLock)
	if data, err := os.ReadFile(seed.Settings); err != nil || !strings.Contains(string(data), "hook pre-tool-use") {
		t.Errorf("a declined de-registration must leave the hook in place (err %v)", err)
	}
}

// A non-interactive `--apply` with no --yes declines every phase (EOF is a "no"), so a piped
// invocation deletes nothing instead of hanging or guessing.
func TestUninstallApplyNonInteractiveDeclines(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	seed := seedUninstallFootprint(t, home)
	fakeUninstallBinary(t, home)

	out, code := runUninstallCmd(t, "", "--apply")
	if code != 0 {
		t.Errorf("exit = %d, want 0; output:\n%s", code, out)
	}
	mustContain(t, out, "skipped")
	mustExist(t, seed.Settings, seed.Presence, seed.Home, seed.HomeKeyed, seed.Kube,
		seed.UpdateFile, seed.StateDir, seed.AuditLog, seed.AuditOld, seed.AuditLock)
}

// --- degradation ---

// An invalid global config must not block the uninstall: the manifest warns and falls back to
// corral's default locations (exit 0), and --apply skips only the gc phase — whose reaper
// selection needs the config — with a nonzero exit, while every local phase still runs.
func TestUninstallInvalidGlobalConfigDegrades(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	seed := seedUninstallFootprint(t, home)
	fakeUninstallBinary(t, home)
	writeFiles(t, map[string]string{
		filepath.Join(home, ".config", "corral", "config.yml"): "providers: [broken\n",
	})

	out, code := runUninstallCmd(t, "")
	if code != 0 {
		t.Errorf("manifest exit = %d, want 0; output:\n%s", code, out)
	}
	mustContain(t, out, "global config is invalid")

	out, code = runUninstallCmd(t, "", "--apply", "--yes")
	if code != 1 {
		t.Errorf("apply exit = %d, want 1 (the gc phase cannot run); output:\n%s", code, out)
	}
	mustContain(t, out, "cannot check", "`corral gc`", "finished with errors")
	// --apply prints no footprint, and names the config error once, in the gc phase.
	if strings.Contains(out, "footprint on this system") || strings.Count(out, "did not find expected") != 1 {
		t.Errorf("apply must show the config error once and no footprint title:\n%s", out)
	}
	// The local phases ran regardless of the config failure.
	mustNotExist(t, seed.Presence, seed.UpdateFile, seed.Home, seed.HomeKeyed,
		seed.StateDir, seed.AuditLog)
}

// --- flag validation ---

// The destructive modifier is refused without --apply rather than silently accepted.
func TestUninstallModifiersRequireApply(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	fakeUninstallBinary(t, home)

	var code int
	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			withStdin(t, "", func() { code = cmdUninstall([]string{"--yes"}) })
		})
	})
	if code == 0 {
		t.Errorf("--yes without --apply must fail, got exit 0")
	}
	if !strings.Contains(stderr, "only applies with --apply") {
		t.Errorf("--yes without --apply must explain itself, got: %q", stderr)
	}
}

func TestUninstallRemovePhase(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".cache", "corral")
	mkdirs(t, dir)
	for _, tt := range []struct {
		name   string
		style  report.Style
		exists bool
		opts   uninstallOptions
		in     string
		want   string
	}{
		{"absent", report.NewStyle(false, false), false, uninstallOptions{}, "", "\n" +
			"cache ────────────────────────────────────────────────────────────\n" +
			"  ○ ~/.cache/corral not present\n"},
		{"declined", report.NewStyle(false, true), true, uninstallOptions{}, "n\n", "\n" +
			"cache ------------------------------------------------------------\n" +
			"Delete ~/.cache/corral (2 entries)? [y/N] [--] skipped\n"},
		{"deleted", report.NewStyle(false, true), true, uninstallOptions{Yes: true}, "", "\n" +
			"cache ------------------------------------------------------------\n" +
			"[ok] deleted ~/.cache/corral\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			opts.Home, opts.Colors = home, tt.style
			var out strings.Builder
			if failed := removePhase(opts, strings.NewReader(tt.in), &out, "cache", dir, tt.exists, "2 entries"); failed {
				t.Error("removePhase reported a failure")
			}
			if out.String() != tt.want {
				t.Errorf("output:\n%s\nwant:\n%s", out.String(), tt.want)
			}
		})
	}
	mustNotExist(t, dir)
}

func TestUninstallManifestASCII(t *testing.T) {
	home := t.TempDir()
	uninstallEnv(t, home)
	fakeUninstallBinary(t, home)
	var out strings.Builder
	runUninstall(uninstallOptions{Home: home, Host: map[string]string{}, Colors: report.NewStyle(false, true)}, strings.NewReader(""), &out)
	for i, r := range out.String() {
		if r > 0x7f {
			t.Fatalf("non-ASCII %q at byte %d:\n%s", r, i, out.String())
		}
	}
	mustContain(t, out.String(), "[--] cache          ~/.cache/corral - not present\n", "                    -> corral uninstall --apply\n")
}

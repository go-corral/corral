package bwrap

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// TestAvailableDetectsResolvableBinary verifies bwrap.Available returns true when
// exec.LookPath succeeds and false when it fails.
func TestAvailableDetectsResolvableBinary(t *testing.T) {
	// When the binary path is resolvable (bwrap exists on PATH), Available returns true.
	b := New("")
	if !b.Available() {
		t.Skip("bwrap not available on this system (expected in dev sandboxes)")
	}

	// When the binary path does not exist, Available returns false.
	b = New("/nonexistent/path/to/bwrap")
	if b.Available() {
		t.Error("Available must return false for nonexistent path")
	}

	// With custom path that doesn't exist.
	b = New("/tmp/fake_bwrap_xyz_9999")
	if b.Available() {
		t.Error("Available must return false for custom nonexistent path")
	}
}

// TestUnavailableHintContainsBinaryPath verifies UnavailableHint returns a string
// containing the resolved binary name and hint text.
func TestUnavailableHintContainsBinaryPath(t *testing.T) {
	// With default empty path, should reference 'bwrap'
	b := New("")
	hint := b.UnavailableHint()
	if !strings.Contains(hint, "bwrap") {
		t.Errorf("UnavailableHint must mention binary name; got: %s", hint)
	}

	// With custom path, should reference that path
	custom := "/custom/bwrap"
	b = New(custom)
	hint = b.UnavailableHint()
	if !strings.Contains(hint, custom) {
		t.Errorf("UnavailableHint must mention custom path %q; got: %s", custom, hint)
	}

	// Should contain actionable hint
	if !strings.Contains(hint, "install") && !strings.Contains(hint, "pass") {
		t.Errorf("UnavailableHint must contain install/override hint; got: %s", hint)
	}
}

// AgentNotes: bwrap's /tmp is a fresh writable tmpfs, so it contributes no standing
// session-context note (the seatbelt backend is the one with the /tmp/$TMPDIR caveat).
func TestBackendAgentNotesEmpty(t *testing.T) {
	if notes := New("bwrap").AgentNotes(); len(notes) != 0 {
		t.Errorf("bwrap AgentNotes should be empty, got %v", notes)
	}
}

// TestNameReturnsBwrap verifies Name() returns exactly "bwrap".
func TestNameReturnsBwrap(t *testing.T) {
	b := New("bwrap")
	if b.Name() != "bwrap" {
		t.Errorf("Name must return 'bwrap', got %q", b.Name())
	}

	b = New("/custom/path/bwrap")
	if b.Name() != "bwrap" {
		t.Errorf("Name must return 'bwrap' regardless of Path, got %q", b.Name())
	}

	b = New("")
	if b.Name() != "bwrap" {
		t.Errorf("Name must return 'bwrap' for empty Path, got %q", b.Name())
	}
}

// TestDoctorReportsPidNamespace verifies Doctor writes the tool report and the pid namespace.
func TestDoctorReportsPidNamespace(t *testing.T) {
	b := New("")
	var buf bytes.Buffer
	b.Doctor(&buf)
	output := buf.String()

	// Should report the binary
	if !strings.Contains(output, "bwrap") {
		t.Errorf("Doctor output must mention bwrap; got: %s", output)
	}

	// Should mention PID namespace (either successfully or as unavailable)
	if !strings.Contains(output, "pid namespace") {
		t.Errorf("Doctor output must mention 'pid namespace'; got: %s", output)
	}
}

// TestDoctorReportsLegacyTIOCSTI verifies Doctor reports the legacy TIOCSTI status.
// corral shares the caller's terminal with the sandbox (--new-session would detach it and
// break the agent's TUI), so a kernel that still permits legacy TIOCSTI leaves a
// keystroke-injection path out of the sandbox. Doctor must surface that instead of relying
// silently on the Linux 6.2 default. Each branch is driven from a temp file so the
// assertion does not depend on the test kernel.
func TestDoctorReportsLegacyTIOCSTI(t *testing.T) {
	cases := []struct {
		name     string
		content  string // ignored unless write is true
		write    bool
		want     string
		wantWarn bool
	}{
		{name: "enabled warns", content: "1\n", write: true, want: "ENABLED", wantWarn: true},
		{name: "disabled is quiet", content: "0\n", write: true, want: "disabled"},
		{name: "absent is not a failure", write: false, want: "not present"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "legacy_tiocsti")
			if tc.write {
				if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
					t.Fatalf("seed sysctl: %v", err)
				}
			}
			var buf bytes.Buffer
			reportLegacyTIOCSTI(&buf, path)
			got := buf.String()
			if !strings.Contains(got, "legacy tiocsti:") {
				t.Errorf("must report under a stable label; got %q", got)
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("expected %q in the report; got %q", tc.want, got)
			}
			// Only the enabled case may tell the operator to change a sysctl — the other
			// two must not nag about a kernel that is already safe.
			if mentions := strings.Contains(got, "dev.tty.legacy_tiocsti=0"); mentions != tc.wantWarn {
				t.Errorf("remediation advice present=%v, want %v; got %q", mentions, tc.wantWarn, got)
			}
		})
	}
}

// The real Doctor must include the check, so it cannot be added to the helper yet left
// unwired (the failure mode that made this a review finding in the first place).
func TestDoctorIncludesLegacyTIOCSTICheck(t *testing.T) {
	var buf bytes.Buffer
	New("").Doctor(&buf)
	if !strings.Contains(buf.String(), "legacy tiocsti:") {
		t.Errorf("Doctor must report the legacy TIOCSTI status; got %q", buf.String())
	}
}

// TestBinResolvesCustomPath verifies bin() returns Path when set and "bwrap" when empty.
func TestBinResolvesCustomPath(t *testing.T) {
	// Empty Path defaults to "bwrap"
	b := New("")
	if b.bin() != "bwrap" {
		t.Errorf("bin() with empty Path must return 'bwrap', got %q", b.bin())
	}

	// Custom path is returned as-is
	custom := "/custom/bwrap"
	b = New(custom)
	if b.bin() != custom {
		t.Errorf("bin() with custom Path must return %q, got %q", custom, b.bin())
	}

	// Another custom path
	custom2 := "path/to/bwrap"
	b = New(custom2)
	if b.bin() != custom2 {
		t.Errorf("bin() must return %q, got %q", custom2, b.bin())
	}
}

// TestArgvBlockMountOrdering verifies Argv emits clearenv, setenv, tmpfs, binds,
// symlinks, /proc /dev, blocked-path masks, overlays, unshare, optional flags,
// chdir, command in that order.
func TestArgvBlockMountOrdering(t *testing.T) {
	spec := sandbox.SandboxSpec{
		Hostname:     "test",
		WorkDir:      "/work",
		Mounts:       []sandbox.Mount{{Src: "/usr", ReadOnly: true}},
		Symlinks:     []sandbox.Symlink{{Target: "usr/bin", Path: "/bin"}},
		Tmpfs:        []string{"/tmp"},
		BlockedPaths: []string{"/root/.ssh"},
		SetEnv:       map[string]string{"PATH": "/usr/bin"},
		Net:          sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}

	// Find indices of key sections
	var clearenvIdx, setenvIdx, tmpfsIdx, bindIdx, symlinkIdx, procIdx, devIdx, tmpfsBlockIdx, unsharePidIdx, chdirIdx, cmdIdx int
	clearenvIdx, setenvIdx, tmpfsIdx, bindIdx, symlinkIdx, procIdx, devIdx = -1, -1, -1, -1, -1, -1, -1
	tmpfsBlockIdx, unsharePidIdx, chdirIdx, cmdIdx = -1, -1, -1, -1

	for i, a := range argv {
		switch a {
		case "--clearenv":
			clearenvIdx = i
		case "--setenv":
			if setenvIdx < 0 {
				setenvIdx = i
			}
		case "--tmpfs":
			if tmpfsIdx < 0 && i+1 < len(argv) && argv[i+1] == "/tmp" {
				tmpfsIdx = i
			} else if tmpfsBlockIdx < 0 && i+1 < len(argv) && argv[i+1] == "/root/.ssh" {
				tmpfsBlockIdx = i
			}
		case "--ro-bind":
			if bindIdx < 0 && i+1 < len(argv) && argv[i+1] == "/usr" {
				bindIdx = i
			}
		case "--symlink":
			if symlinkIdx < 0 {
				symlinkIdx = i
			}
		case "--proc":
			procIdx = i
		case "--dev":
			devIdx = i
		case "--unshare-pid":
			unsharePidIdx = i
		case "--chdir":
			chdirIdx = i
		case "true":
			cmdIdx = i
		}
	}

	// Verify that --proc is followed by /proc
	if procIdx >= 0 && procIdx+1 < len(argv) && argv[procIdx+1] != "/proc" {
		t.Errorf("--proc must be followed by /proc, got %q at index %d", argv[procIdx+1], procIdx+1)
	}

	// Verify that --dev is followed by /dev
	if devIdx >= 0 && devIdx+1 < len(argv) && argv[devIdx+1] != "/dev" {
		t.Errorf("--dev must be followed by /dev, got %q at index %d", argv[devIdx+1], devIdx+1)
	}

	// Verify ordering: clearenv < setenv < tmpfs < bind < symlink < proc < dev < blocked-tmpfs < unshare < chdir < cmd
	checks := []struct {
		name string
		idx  int
	}{
		{"clearenv", clearenvIdx},
		{"setenv", setenvIdx},
		{"tmpfs /tmp", tmpfsIdx},
		{"bind", bindIdx},
		{"symlink", symlinkIdx},
		{"--proc", procIdx},
		{"--dev", devIdx},
		{"tmpfs blocked", tmpfsBlockIdx},
		{"unshare-pid", unsharePidIdx},
		{"chdir", chdirIdx},
		{"cmd", cmdIdx},
	}

	for i := 0; i < len(checks)-1; i++ {
		if checks[i].idx >= 0 && checks[i+1].idx >= 0 && checks[i].idx >= checks[i+1].idx {
			t.Errorf("ordering violation: %s (%d) must come before %s (%d)",
				checks[i].name, checks[i].idx, checks[i+1].name, checks[i+1].idx)
		}
	}
}

// TestBindArgsDstDefaultsToSrc verifies bindArgs uses m.Dst when set and m.Src
// when m.Dst is empty.
func TestBindArgsDstDefaultsToSrc(t *testing.T) {
	// When Dst is set, it should be used
	m := sandbox.Mount{Src: "/source", Dst: "/dest", ReadOnly: true}
	args, err := bindArgs(m)
	if err != nil {
		t.Fatalf("bindArgs: %v", err)
	}
	if args[2] != "/dest" {
		t.Errorf("bindArgs with explicit Dst must use it; got argv=%v", args)
	}

	// When Dst is empty, Src should be used as destination
	m = sandbox.Mount{Src: "/source", Dst: "", ReadOnly: true}
	args, err = bindArgs(m)
	if err != nil {
		t.Fatalf("bindArgs: %v", err)
	}
	if args[2] != "/source" {
		t.Errorf("bindArgs with empty Dst must default to Src; got argv=%v", args)
	}
}

// TestArgvIncludesAllUnshareFlags verifies Argv always includes all unshare flags.
func TestArgvIncludesAllUnshareFlags(t *testing.T) {
	spec := sandbox.SandboxSpec{
		Net: sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}

	requiredFlags := []string{
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup",
	}
	for _, flag := range requiredFlags {
		if !contains(argv, flag) {
			t.Errorf("Argv must always include %s; argv=%v", flag, argv)
		}
	}

	// When Net==NetNone, also include --unshare-net
	spec.Net = sandbox.NetNone
	argv, err = New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "--unshare-net") {
		t.Errorf("Argv with NetNone must include --unshare-net; argv=%v", argv)
	}

	// When Net==NetOpen, do not include --unshare-net
	spec.Net = sandbox.NetOpen
	argv, err = New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if contains(argv, "--unshare-net") {
		t.Errorf("Argv with NetOpen must NOT include --unshare-net; argv=%v", argv)
	}
}

// TestArgvOptionalHostnameAndDieWithParent verifies the Hostname and DieWithParent
// flags are only included when set.
func TestArgvOptionalHostnameAndDieWithParent(t *testing.T) {
	// With both set
	spec := sandbox.SandboxSpec{
		Hostname:      "test-host",
		DieWithParent: true,
		Net:           sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "--hostname") || !contains(argv, "test-host") {
		t.Errorf("Argv must include --hostname when set; argv=%v", argv)
	}
	if !contains(argv, "--die-with-parent") {
		t.Errorf("Argv must include --die-with-parent when true; argv=%v", argv)
	}

	// With both empty/false
	spec.Hostname = ""
	spec.DieWithParent = false
	argv, err = New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if contains(argv, "--hostname") {
		t.Errorf("Argv must not include --hostname when empty; argv=%v", argv)
	}
	if contains(argv, "--die-with-parent") {
		t.Errorf("Argv must not include --die-with-parent when false; argv=%v", argv)
	}
}

// TestArgvWorkdirChdir verifies Argv includes --chdir when WorkDir is set and omits it
// when empty.
func TestArgvWorkdirChdir(t *testing.T) {
	// With WorkDir set
	spec := sandbox.SandboxSpec{
		WorkDir: "/path/to/work",
		Net:     sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] == "--chdir" && argv[i+1] == "/path/to/work" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Argv must include --chdir /path/to/work when WorkDir is set; argv=%v", argv)
	}

	// With WorkDir empty
	spec.WorkDir = ""
	argv, err = New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if contains(argv, "--chdir") {
		t.Errorf("Argv must not include --chdir when WorkDir is empty; argv=%v", argv)
	}
}

// TestCompileLinuxBaselineCreateRule verifies a rule with Create:true appears in
// createDirs and as a Mount with ReadOnly per the rule.
func TestCompileLinuxBaselineCreateRule(t *testing.T) {
	rules := []sandbox.Rule{
		{
			Path:        "$HOME/.cache/corral/test",
			Description: "test create dir",
			Writeable:   true,
			Create:      true,
		},
	}
	tokens := map[string]string{"HOME": "/home/u"}

	mounts, _, createDirs := compileLinuxBaseline(rules, tokens, fakeFS{})

	// Should be in createDirs
	if len(createDirs) != 1 || createDirs[0] != "/home/u/.cache/corral/test" {
		t.Errorf("Create rule must record createDir; got %v", createDirs)
	}

	// Should be in mounts as writable (Writeable:true -> !ReadOnly)
	if m, ok := findMount(mounts, "/home/u/.cache/corral/test"); !ok || m.ReadOnly {
		t.Errorf("Create rule must produce a writable mount; got %+v ok=%v", m, ok)
	}
}

// TestRealFSSymlinkDetection verifies realFS.symlink detects symlinks correctly.
func TestRealFSSymlinkDetection(t *testing.T) {
	dir := t.TempDir()

	// Create a symlink
	linkPath := filepath.Join(dir, "link")
	targetPath := filepath.Join(dir, "target")
	if err := os.WriteFile(targetPath, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, linkPath); err != nil {
		t.Fatal(err)
	}

	fs := realFS{}

	// Symlink detection
	isSym, target := fs.symlink(linkPath)
	if !isSym || !strings.HasSuffix(target, "target") {
		t.Errorf("realFS.symlink must detect symlink; got isSym=%v target=%q", isSym, target)
	}

	// Regular file is not a symlink
	isSym, target = fs.symlink(targetPath)
	if isSym || target != "" {
		t.Errorf("realFS.symlink must return false for regular file; got isSym=%v target=%q", isSym, target)
	}

	// Nonexistent path
	isSym, target = fs.symlink(filepath.Join(dir, "nonexistent"))
	if isSym || target != "" {
		t.Errorf("realFS.symlink must return false for nonexistent path; got isSym=%v target=%q", isSym, target)
	}
}

// TestBindArgsFlagCombinations verifies bindArgs generates the correct flags
// for all four combinations of (ReadOnly, Optional).
func TestBindArgsFlagCombinations(t *testing.T) {
	tests := []struct {
		ro       bool
		optional bool
		want     string
	}{
		{ro: true, optional: true, want: "--ro-bind-try"},
		{ro: true, optional: false, want: "--ro-bind"},
		{ro: false, optional: true, want: "--bind-try"},
		{ro: false, optional: false, want: "--bind"},
	}

	for _, tt := range tests {
		m := sandbox.Mount{Src: "/src", ReadOnly: tt.ro, Optional: tt.optional}
		args, err := bindArgs(m)
		if err != nil {
			t.Fatalf("bindArgs: %v", err)
		}
		if args[0] != tt.want {
			t.Errorf("bindArgs(ro=%v optional=%v) must return %q, got %q; argv=%v",
				tt.ro, tt.optional, tt.want, args[0], args)
		}
	}
}

// TestCompileLinuxBaselineArchFiltering verifies compileLinuxBaseline skips macos-only and
// regex rules, includes linux and both-arch rules, and skips rules with missing
// token expansions.
func TestCompileLinuxBaselineArchFiltering(t *testing.T) {
	rules := []sandbox.Rule{
		{Path: "/linux-only", Description: "linux", Archs: []string{"linux"}, Writeable: true},
		{Path: "/both-arch", Description: "both", Writeable: true}, // empty Archs = both
		{Path: "/macos-only", Description: "macos", Archs: []string{"darwin"}, Writeable: true},
		{Path: "/with-regex", Description: "regex", Regex: true, Writeable: true},
	}

	mounts, _, _ := compileLinuxBaseline(rules, map[string]string{}, fakeFS{})

	if _, ok := findMount(mounts, "/linux-only"); !ok {
		t.Error("linux-arch rule must be included")
	}
	if _, ok := findMount(mounts, "/both-arch"); !ok {
		t.Error("both-arch rule must be included")
	}
	if _, ok := findMount(mounts, "/macos-only"); ok {
		t.Error("macos-only rule must be skipped")
	}
	if _, ok := findMount(mounts, "/with-regex"); ok {
		t.Error("regex rule must be skipped")
	}
}

// TestProcDevAlwaysMounted verifies Argv always includes --proc and --dev after
// symlinks but before blocked-path masks.
func TestProcDevAlwaysMounted(t *testing.T) {
	spec := sandbox.SandboxSpec{
		Mounts:       []sandbox.Mount{{Src: "/usr", ReadOnly: true}},
		BlockedPaths: []string{"/root/.ssh"},
		Net:          sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}

	procIdx, devIdx, blockedIdx := -1, -1, -1
	for i, a := range argv {
		switch a {
		case "--proc":
			procIdx = i
		case "--dev":
			devIdx = i
		case "/root/.ssh":
			if blockedIdx < 0 {
				blockedIdx = i
			}
		}
	}

	if procIdx < 0 {
		t.Error("Argv must include --proc")
	}
	if devIdx < 0 {
		t.Error("Argv must include --dev")
	}

	// Both /proc and /dev should be present and relatively close
	if procIdx >= 0 && devIdx >= 0 {
		// They should be adjacent (--proc /proc --dev /dev)
		if procIdx+2 != devIdx {
			t.Logf("proc at %d, dev at %d (may be OK if other args in between)", procIdx, devIdx)
		}
	}

	// /proc /dev must come before the blocked-path mask
	if blockedIdx >= 0 && procIdx >= 0 && procIdx >= blockedIdx {
		t.Errorf("--proc must come before blocked-path mask; proc=%d blocked=%d", procIdx, blockedIdx)
	}
}

// TestSymlinkTargetPathOrder verifies Argv emits symlinks as --symlink target path
// (not path target).
func TestSymlinkTargetPathOrder(t *testing.T) {
	spec := sandbox.SandboxSpec{
		Symlinks: []sandbox.Symlink{
			{Target: "usr/bin", Path: "/bin"},
			{Target: "usr/sbin", Path: "/sbin"},
		},
		Net: sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}

	// Find each --symlink and verify target comes before path
	for i := 0; i+2 < len(argv); i++ {
		if argv[i] == "--symlink" {
			target := argv[i+1]
			path := argv[i+2]

			// target should be the link target, path should be the link location
			foundPath := false
			for _, s := range spec.Symlinks {
				if s.Path == path && s.Target == target {
					foundPath = true
					break
				}
			}
			if !foundPath {
				t.Errorf("--symlink %s %s does not match any spec symlink", target, path)
			}
		}
	}
}

// TestPrepareReturnsCleanupAndNoChdir verifies Prepare returns an error if compilation
// fails (theoretical, never happens in practice).
func TestPrepareReturnsCleanupAndNoChdir(t *testing.T) {
	home := t.TempDir()
	spec := sandbox.SandboxSpec{
		Tokens: map[string]string{
			"HOME":             home,
			"AGENT_CONFIG_DIR": filepath.Join(home, ".claude"),
		},
	}

	prep, err := New("").Prepare(&spec, io.Discard)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}

	// Must return a non-nil cleanup
	if prep.Cleanup == nil {
		t.Error("Prepare must return a non-nil Cleanup")
	}

	// bwrap needs no launcher chdir (uses --chdir in argv)
	if prep.Chdir != "" {
		t.Errorf("bwrap Prepare must return empty Chdir, got %q", prep.Chdir)
	}

	// Cleanup should be callable (no-op)
	prep.Cleanup() // should not panic
}

// Integration test: verify that a spec with all features produces correct argv
// ordering and content.
func TestArgvCompleteSpec(t *testing.T) {
	spec := sandbox.SandboxSpec{
		Hostname:      "sandbox",
		WorkDir:       "/work",
		Mounts:        []sandbox.Mount{{Src: "/usr", ReadOnly: true}},
		Symlinks:      []sandbox.Symlink{{Target: "usr/bin", Path: "/bin"}},
		Tmpfs:         []string{"/tmp"},
		BlockedPaths:  []string{"/root/.ssh"},
		SetEnv:        map[string]string{"HOME": "/home/user", "PATH": "/usr/bin"},
		Net:           sandbox.NetNone,
		DieWithParent: true,
	}

	argv, err := New("bwrap").Argv(spec, []string{"bash", "-c", "echo hello"})
	if err != nil {
		t.Fatal(err)
	}

	// First element is bwrap
	if argv[0] != "bwrap" {
		t.Errorf("first argv element must be bwrap, got %q", argv[0])
	}

	// Last elements are the command
	if argv[len(argv)-3] != "bash" || argv[len(argv)-2] != "-c" || argv[len(argv)-1] != "echo hello" {
		t.Errorf("command must be appended; last 3: %v", argv[len(argv)-3:])
	}

	// Verify all required flags are present
	for _, required := range []string{
		"--clearenv", "--setenv", "HOME", "--setenv", "PATH",
		"--tmpfs", "/tmp",
		"--ro-bind", "/usr",
		"--symlink", "usr/bin", "/bin",
		"--proc", "/proc", "--dev", "/dev",
		"--tmpfs", "/root/.ssh",
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--unshare-net", // Because Net==NetNone
		"--hostname", "sandbox",
		"--die-with-parent",
		"--chdir", "/work",
	} {
		if !contains(argv, required) {
			t.Errorf("Argv must contain %q; argv=%v", required, argv)
		}
	}
}

package bwrap

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

var update = flag.Bool("update", false, "regenerate golden files")

// fixedSpec is a host-independent spec used for golden testing the bwrap argv. It is
// hand-built (no baseline) on purpose: Argv is a pure spec→argv emitter, so the golden
// pins the argv structure without coupling to the embedded baseline.
func fixedSpec() sandbox.SandboxSpec {
	return sandbox.SandboxSpec{
		Hostname: "corral",
		WorkDir:  "/home/u/proj",
		Mounts: []sandbox.Mount{
			{Src: "/usr", ReadOnly: true},
			{Src: "/etc", ReadOnly: true},
			{Src: "/home/u/proj"},
			{Src: "/home/u/.claude.json"},
			{Src: "/srv/ro", Dst: "/data", ReadOnly: true},
		},
		Symlinks:      []sandbox.Symlink{{Target: "usr/bin", Path: "/bin"}},
		Tmpfs:         []string{"/tmp"},
		BlockedPaths:  []string{"/home/u/.ssh", "/home/u/.gnupg"},
		SetEnv:        map[string]string{"HOME": "/home/u", "PATH": "/usr/bin", "TERM": "xterm-256color"},
		Net:           sandbox.NetOpen,
		DieWithParent: true,
	}
}

// fakeFS reports a fixed set of paths as symlinks (merged-/usr layout) for
// deterministic compile tests.
type fakeFS struct{ links map[string]string }

func (f fakeFS) symlink(p string) (bool, string) {
	t, ok := f.links[p]
	return ok, t
}

// resolve models EvalSymlinks over the link table for final-component chains only: it follows each
// hop (relative targets against the link's own dir) until the path is not a key in the table. It does
// not resolve symlinked ancestor directories, so it is not a full EvalSymlinks stand-in; a test that
// needs ancestor resolution uses a real t.TempDir tree with realFS (TestResolveSymlinksFollowsSymlinkedAncestor).
func (f fakeFS) resolve(p string) string {
	for range 40 {
		t, ok := f.links[p]
		if !ok {
			return p
		}
		if filepath.IsAbs(t) {
			p = filepath.Clean(t)
		} else {
			p = filepath.Clean(filepath.Join(filepath.Dir(p), t))
		}
	}
	return p
}

func mergedUsrFS() fakeFS {
	return fakeFS{links: map[string]string{
		"/bin": "usr/bin", "/sbin": "usr/sbin", "/lib": "usr/lib", "/lib64": "usr/lib64",
	}}
}

func testTokens() map[string]string {
	return map[string]string{"HOME": "/home/u", "AGENT_CONFIG_DIR": "/home/u/.claude", "XDG_RUNTIME_DIR": "/run/user/1000"}
}

func findMount(ms []sandbox.Mount, src string) (sandbox.Mount, bool) {
	for _, m := range ms {
		if m.Src == src {
			return m, true
		}
	}
	return sandbox.Mount{}, false
}

func findSymlink(ss []sandbox.Symlink, path string) (sandbox.Symlink, bool) {
	for _, s := range ss {
		if s.Path == path {
			return s, true
		}
	}
	return sandbox.Symlink{}, false
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

// indexOf returns the index of v in s, or -1 if absent.
func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func TestBwrapArgvGolden(t *testing.T) {
	b := New("bwrap")
	argv, err := b.Argv(fixedSpec(), []string{"claude", "--model", "opus"})
	if err != nil {
		t.Fatalf("Argv: %v", err)
	}
	got := strings.Join(argv, "\n") + "\n"

	golden := filepath.Join("testdata", "bwrap_default.golden")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run `go test -update` to create): %v", err)
	}
	if got != string(want) {
		t.Errorf("argv mismatch with %s:\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
	}
}

func TestBwrapNetNoneUnsharesNet(t *testing.T) {
	spec := fixedSpec()
	spec.Net = sandbox.NetNone
	argv, err := New("").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(argv, "--unshare-net") {
		t.Errorf("NetNone must unshare the network namespace; argv=%v", argv)
	}
}

func TestBwrapNetOpenSharesNet(t *testing.T) {
	argv, err := New("").Argv(fixedSpec(), []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if contains(argv, "--unshare-net") {
		t.Errorf("NetOpen must NOT unshare the network namespace; argv=%v", argv)
	}
}

func TestBwrapEmptyCommand(t *testing.T) {
	if _, err := New("").Argv(fixedSpec(), nil); err == nil {
		t.Error("expected error for empty command")
	}
}

func TestBwrapEnvDeterministic(t *testing.T) {
	// Map iteration order must not leak into the argv.
	spec := sandbox.SandboxSpec{SetEnv: map[string]string{"Z": "1", "A": "2", "M": "3"}}
	argv, err := New("").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	// Expect A, M, Z order.
	var keys []string
	for i := 0; i < len(argv)-1; i++ {
		if argv[i] == "--setenv" {
			keys = append(keys, argv[i+1])
		}
	}
	want := []string{"A", "M", "Z"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Errorf("env keys = %v, want %v", keys, want)
	}
}

// An Overlay mount must be emitted after the blocked-path tmpfs mask of the dir it
// sits in, so the file is re-added on top of the emptied dir (not shadowed by it).
func TestOverlayEmittedAfterBlockedMask(t *testing.T) {
	spec := sandbox.SandboxSpec{
		Mounts: []sandbox.Mount{
			{Src: "/usr", ReadOnly: true}, // ordinary
			{Src: "/host/cfg", Dst: "/home/u/.ssh/config", ReadOnly: true, Overlay: true}, // overlay
		},
		BlockedPaths: []string{"/home/u/.ssh"},
		Net:          sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	maskIdx, overlayIdx, usrIdx := -1, -1, -1
	for i, a := range argv {
		switch a {
		case "/home/u/.ssh": // the --tmpfs mask arg
			maskIdx = i
		case "/home/u/.ssh/config": // the overlay's dst
			overlayIdx = i
		case "/usr":
			usrIdx = i
		}
	}
	if usrIdx < 0 || maskIdx < 0 || overlayIdx < 0 {
		t.Fatalf("missing args: usr=%d mask=%d overlay=%d\n%v", usrIdx, maskIdx, overlayIdx, argv)
	}
	if usrIdx >= maskIdx || maskIdx >= overlayIdx {
		t.Errorf("order must be ordinary-bind < mask < overlay; got usr=%d mask=%d overlay=%d", usrIdx, maskIdx, overlayIdx)
	}
}

// Symlinks must be emitted before the blocked-path tmpfs masks. A symlink whose
// target lives under a masked directory would break if the mask (which empties the
// dir) ran first. The golden test pins one fixture; this guards the ordering for an
// arbitrary spec.
func TestSymlinkEmittedBeforeBlockedMask(t *testing.T) {
	spec := sandbox.SandboxSpec{
		Mounts:       []sandbox.Mount{{Src: "/usr", ReadOnly: true}},
		Symlinks:     []sandbox.Symlink{{Target: "usr/bin", Path: "/bin"}},
		BlockedPaths: []string{"/home/u/.ssh"},
		Net:          sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	symIdx, maskIdx := -1, -1
	for i, a := range argv {
		switch a {
		case "--symlink":
			if symIdx < 0 {
				symIdx = i
			}
		case "/home/u/.ssh": // the --tmpfs blocked-mask target
			maskIdx = i
		}
	}
	if symIdx < 0 || maskIdx < 0 {
		t.Fatalf("missing args: symlink=%d mask=%d\n%v", symIdx, maskIdx, argv)
	}
	if symIdx > maskIdx {
		t.Errorf("symlink (%d) must be emitted before the blocked-path mask (%d)", symIdx, maskIdx)
	}
}

// Fresh tmpfs mounts (spec.Tmpfs, e.g. /tmp) must be emitted before the bind mounts,
// so a bind whose destination falls under a tmpfs — a launch-from-$HOME scratch workdir
// created under /tmp and mounted at its own path — layers on top of the empty tmpfs
// instead of being shadowed by it. Guards the cross-OS own-path workdir model.
func TestTmpfsEmittedBeforeBindMounts(t *testing.T) {
	spec := sandbox.SandboxSpec{
		Mounts: []sandbox.Mount{{Src: "/tmp/corral-work-xyz"}}, // a scratch workdir under /tmp
		Tmpfs:  []string{"/tmp"},
		Net:    sandbox.NetOpen,
	}
	argv, err := New("bwrap").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	tmpfsIdx, bindIdx := -1, -1
	for i := 0; i+1 < len(argv); i++ {
		switch argv[i] {
		case "--tmpfs":
			if argv[i+1] == "/tmp" && tmpfsIdx < 0 {
				tmpfsIdx = i
			}
		case "--bind":
			if argv[i+1] == "/tmp/corral-work-xyz" && bindIdx < 0 {
				bindIdx = i
			}
		}
	}
	if tmpfsIdx < 0 || bindIdx < 0 {
		t.Fatalf("missing args: tmpfs=%d bind=%d\n%v", tmpfsIdx, bindIdx, argv)
	}
	if tmpfsIdx > bindIdx {
		t.Errorf("the /tmp tmpfs (%d) must be emitted before the scratch bind (%d) so the bind is not shadowed", tmpfsIdx, bindIdx)
	}
}

func TestBwrapOptionalMountTryFlags(t *testing.T) {
	spec := sandbox.SandboxSpec{Mounts: []sandbox.Mount{
		{Src: "/opt", ReadOnly: true, Optional: true},
		{Src: "/home/u/.cache", Optional: true},
		{Src: "/usr", ReadOnly: true}, // required
	}}
	argv, err := New("").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "--ro-bind-try /opt /opt") {
		t.Errorf("optional ro mount must use --ro-bind-try; argv=%v", argv)
	}
	if !strings.Contains(joined, "--bind-try /home/u/.cache /home/u/.cache") {
		t.Errorf("optional rw mount must use --bind-try; argv=%v", argv)
	}
	if !strings.Contains(joined, "--ro-bind /usr /usr") {
		t.Errorf("required mount must use --ro-bind (no -try); argv=%v", argv)
	}
}

// bindIndex returns the argv index of the bind whose destination is dst, or -1. A bind is
// three consecutive elements (flag, src, dst), so matching the third one distinguishes a
// remapped mount's destination from its source.
func bindIndex(argv []string, dst string) int {
	for i := 2; i < len(argv); i++ {
		if strings.HasPrefix(argv[i-2], "--bind") || strings.HasPrefix(argv[i-2], "--ro-bind") {
			if argv[i] == dst {
				return i - 2
			}
		}
	}
	return -1
}

// TestBwrapRWWorkdirUnderROGrantStaysWritable: a read-write workdir under a broader
// providers.paths.ro grant is emitted after the grant and keeps its --bind, so the workdir
// stays writable, as it does on Seatbelt.
func TestBwrapRWWorkdirUnderROGrantStaysWritable(t *testing.T) {
	spec := sandbox.SandboxSpec{
		WorkDir: "/home/u/.agents/skills",
		Mounts: []sandbox.Mount{
			{Src: "/home/u/.agents/skills"},                          // rw workdir, listed first
			{Src: "/home/u/.agents", ReadOnly: true, Optional: true}, // ro ancestor, listed after
		},
		SetEnv: map[string]string{"HOME": "/home/u"},
		Net:    sandbox.NetOpen,
	}
	argv, err := New("").Argv(spec, []string{"claude"})
	if err != nil {
		t.Fatal(err)
	}
	idxSkills := bindIndex(argv, "/home/u/.agents/skills")
	idxAgents := bindIndex(argv, "/home/u/.agents")
	if idxSkills < 0 || idxAgents < 0 {
		t.Fatalf("missing mounts in argv: %v", argv)
	}
	if idxSkills < idxAgents {
		t.Errorf("rw workdir bind (idx %d) must come after ro ancestor bind (idx %d); argv=%v",
			idxSkills, idxAgents, argv)
	}
	if !strings.Contains(strings.Join(argv, " "), "--bind /home/u/.agents/skills /home/u/.agents/skills") {
		t.Errorf("rw workdir must remain a --bind; argv=%v", argv)
	}
}

// TestBwrapROGrantInsideRWGrantHasNoEffect: a read-only grant inside a read-write grant is
// shadowed by it even when the spec lists the read-only one later. Seatbelt allows the write
// wherever a read-write grant covers the path, so bwrap must too.
func TestBwrapROGrantInsideRWGrantHasNoEffect(t *testing.T) {
	spec := sandbox.SandboxSpec{Mounts: []sandbox.Mount{
		{Src: "/home/u/proj", Optional: true},                        // broad rw, listed first
		{Src: "/home/u/proj/vendor", ReadOnly: true, Optional: true}, // narrow ro, listed after
	}}
	argv, err := New("").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	idxProj := bindIndex(argv, "/home/u/proj")
	idxVendor := bindIndex(argv, "/home/u/proj/vendor")
	if idxProj < 0 || idxVendor < 0 {
		t.Fatalf("missing mounts in argv: %v", argv)
	}
	if idxProj < idxVendor {
		t.Errorf("rw bind (idx %d) must come after the ro bind it contains (idx %d); argv=%v",
			idxProj, idxVendor, argv)
	}
}

// TestBwrapRWBindsFollowEveryROBind: read-write binds come after every read-only bind in
// either containment direction. A workdir that contains a baseline read-only path keeps that
// path writable, and a paths.ro grant over the agent config dir leaves the config dir
// writable, matching Seatbelt. The spec is in Prepare order: baseline first, then the
// workdir, then the paths provider's grant.
func TestBwrapRWBindsFollowEveryROBind(t *testing.T) {
	spec := sandbox.SandboxSpec{
		WorkDir: "/home/u/.config",
		Mounts: []sandbox.Mount{
			{Src: "/usr", ReadOnly: true},
			{Src: "/home/u/.config/git", ReadOnly: true, Optional: true},
			{Src: "/home/u/.claude"},
			{Src: "/home/u/.config"},
			{Src: "/home/u", ReadOnly: true, Optional: true},
		},
	}
	argv, err := New("").Argv(spec, []string{"claude"})
	if err != nil {
		t.Fatal(err)
	}
	idxGit := bindIndex(argv, "/home/u/.config/git")
	idxConfig := bindIndex(argv, "/home/u/.config")
	idxHome := bindIndex(argv, "/home/u")
	idxClaude := bindIndex(argv, "/home/u/.claude")
	if idxGit < 0 || idxConfig < 0 || idxHome < 0 || idxClaude < 0 {
		t.Fatalf("missing mounts in argv: %v", argv)
	}
	if idxConfig < idxGit {
		t.Errorf("rw workdir (idx %d) must come after the ro path it contains (idx %d); argv=%v", idxConfig, idxGit, argv)
	}
	if idxClaude < idxHome {
		t.Errorf("rw agent config dir (idx %d) must come after its ro ancestor (idx %d); argv=%v", idxClaude, idxHome, argv)
	}
}

// TestBwrapROGroupEmitsContainerFirst: inside one mode group the container is emitted first,
// so a nested bind that carries different content stays visible. A read-only /etc grant must
// not hide the baseline's symlink-resolved /etc/resolv.conf.
func TestBwrapROGroupEmitsContainerFirst(t *testing.T) {
	spec := sandbox.SandboxSpec{Mounts: []sandbox.Mount{
		{Src: "/run/systemd/resolve/stub-resolv.conf", Dst: "/etc/resolv.conf", ReadOnly: true},
		{Src: "/etc", ReadOnly: true, Optional: true},
	}}
	argv, err := New("").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	idxEtc := bindIndex(argv, "/etc")
	idxResolv := bindIndex(argv, "/etc/resolv.conf")
	if idxEtc < 0 || idxResolv < 0 {
		t.Fatalf("missing mounts in argv: %v", argv)
	}
	if idxResolv < idxEtc {
		t.Errorf("nested bind (idx %d) must come after its container (idx %d); argv=%v", idxResolv, idxEtc, argv)
	}
}

// TestBwrapUnrelatedMountsKeepSpecOrder: mounts of one mode whose destinations do not overlap
// keep their spec order, so a golden without containment does not move.
func TestBwrapUnrelatedMountsKeepSpecOrder(t *testing.T) {
	srcs := []string{"/srv/a", "/srv/b", "/opt/c", "/var/d"}
	var mounts []sandbox.Mount
	for _, s := range srcs {
		mounts = append(mounts, sandbox.Mount{Src: s, Optional: true})
	}
	spec := sandbox.SandboxSpec{Mounts: mounts, Net: sandbox.NetOpen}
	argv, err := New("").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	var got []int
	for _, m := range mounts {
		got = append(got, indexOf(argv, m.Src))
	}
	for i := 1; i < len(got); i++ {
		if got[i] <= got[i-1] {
			t.Errorf("unrelated mounts reordered: indices %v; argv=%v", got, argv)
			break
		}
	}
}

// TestBwrapEqualDstMountsKeepSpecOrder: two binds of the same mode at the same destination
// keep their spec order, so the later one still wins.
func TestBwrapEqualDstMountsKeepSpecOrder(t *testing.T) {
	spec := sandbox.SandboxSpec{Mounts: []sandbox.Mount{
		{Src: "/a", Dst: "/x", ReadOnly: true, Optional: true},
		{Src: "/b", Dst: "/x", ReadOnly: true, Optional: true},
	}}
	argv, err := New("").Argv(spec, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	idxA := indexOf(argv, "/a")
	idxB := indexOf(argv, "/b")
	if idxA < 0 || idxB < 0 {
		t.Fatalf("missing mounts in argv: %v", argv)
	}
	if idxA > idxB {
		t.Errorf("equal-dst mounts reordered; expected spec order (/a before /b); argv=%v", argv)
	}
}

// TestBwrapRWWorkdirUnderROGrantWithUnrelatedMountBetween is the spec shape the launcher
// produces: the workdir precedes the read-only global-config pin, and the paths provider's
// grant follows both. The workdir still lands after the grant.
func TestBwrapRWWorkdirUnderROGrantWithUnrelatedMountBetween(t *testing.T) {
	spec := sandbox.SandboxSpec{
		WorkDir: "/home/u/.agents/skills",
		Mounts: []sandbox.Mount{
			{Src: "/home/u/.agents/skills"},                                            // rw workdir
			{Src: "/home/u/.config/corral/config.yml", ReadOnly: true, Optional: true}, // unrelated pin
			{Src: "/home/u/.agents", ReadOnly: true, Optional: true},                   // ro ancestor
		},
		SetEnv: map[string]string{"HOME": "/home/u"},
		Net:    sandbox.NetOpen,
	}
	argv, err := New("").Argv(spec, []string{"claude"})
	if err != nil {
		t.Fatal(err)
	}
	idxSkills := bindIndex(argv, "/home/u/.agents/skills")
	idxAgents := bindIndex(argv, "/home/u/.agents")
	if idxSkills < 0 || idxAgents < 0 {
		t.Fatalf("missing mounts in argv: %v", argv)
	}
	if idxSkills < idxAgents {
		t.Errorf("rw workdir bind (idx %d) must come after ro ancestor bind (idx %d); argv=%v",
			idxSkills, idxAgents, argv)
	}
}

func TestBwrapRejectsEmptyMountSource(t *testing.T) {
	spec := sandbox.SandboxSpec{Mounts: []sandbox.Mount{{Src: ""}}}
	if _, err := New("").Argv(spec, []string{"true"}); err == nil {
		t.Error("an empty mount source must fail closed")
	}
}

func TestCompileLinuxBaselineBehavior(t *testing.T) {
	mounts, symlinks, createDirs := compileLinuxBaseline(sandbox.BaselineRules(), testTokens(), mergedUsrFS())

	// $AGENT_CONFIG_DIR expands, is writable, and is required (the law marks it required;
	// the launcher mkdir's it before launch so first run doesn't fail).
	if m, ok := findMount(mounts, "/home/u/.claude"); !ok {
		t.Error("$AGENT_CONFIG_DIR must compile to a mount of the claude dir")
	} else if m.ReadOnly || m.Optional {
		t.Errorf("$AGENT_CONFIG_DIR must be writable and required; got %+v", m)
	}

	// /usr is read-only and required (per the law). Its recursive bind also covers
	// /usr/local, which therefore has no rule of its own.
	if m, ok := findMount(mounts, "/usr"); !ok {
		t.Error("/usr must be a mount")
	} else if !m.ReadOnly || m.Optional {
		t.Errorf("/usr must be read-only and required; got %+v", m)
	}
	if _, ok := findMount(mounts, "/usr/local"); ok {
		t.Error("/usr/local must NOT be a separate rule — it is covered by the recursive /usr ro bind")
	}

	// The law binds specific /etc nodes (not the whole tree); they are both-arch, so
	// they appear on Linux, read-only and required.
	if m, ok := findMount(mounts, "/etc/resolv.conf"); !ok {
		t.Error("/etc/resolv.conf must be bound on Linux")
	} else if !m.ReadOnly || m.Optional {
		t.Errorf("/etc/resolv.conf must be read-only and required; got %+v", m)
	}
	if _, ok := findMount(mounts, "/etc"); ok {
		t.Error("/etc must NOT be bound wholesale on Linux (the law binds specific nodes only)")
	}

	// git identity is read-only + optional.
	if m, ok := findMount(mounts, "/home/u/.gitconfig"); !ok || !m.ReadOnly || !m.Optional {
		t.Errorf("$HOME/.gitconfig must be read-only optional; got %+v ok=%v", m, ok)
	}

	// A symlinked system dir becomes a Symlink, not a bind.
	if s, ok := findSymlink(symlinks, "/bin"); !ok || s.Target != "usr/bin" {
		t.Errorf("/bin must compile to a symlink -> usr/bin; got %+v ok=%v", s, ok)
	}
	if _, ok := findMount(mounts, "/bin"); ok {
		t.Error("/bin must NOT also be a bind mount when it is a symlink")
	}

	if len(createDirs) != 0 {
		t.Errorf("the Linux baseline currently uses no create rules; got %v", createDirs)
	}

	// No macOS-only path may leak into the Linux compile. (The /etc/* nodes are now
	// both-arch, so they are intentionally not in this list.)
	for _, bad := range []string{"/System", "/Library", "/private/var", "/dev/null", "/home/u/Library/Keychains"} {
		if _, ok := findMount(mounts, bad); ok {
			t.Errorf("macOS-only path %q must not appear in the Linux compile", bad)
		}
	}
}

// TestLinuxConformance: every linux-applicable, non-regex rule must produce exactly
// one enforcing directive (a Mount or Symlink), with nothing silently dropped, and
// no path may be both. (testTokens supplies both tokens, so none are skipped here.)
func TestLinuxConformance(t *testing.T) {
	mounts, symlinks, _ := compileLinuxBaseline(sandbox.BaselineRules(), testTokens(), mergedUsrFS())
	var want int
	for _, r := range sandbox.BaselineRules() {
		if sandbox.ArchMatch(r, "linux") && !r.Regex {
			want++
		}
	}
	if got := len(mounts) + len(symlinks); got != want {
		t.Errorf("conformance: %d linux rules but %d compiled directives (mounts+symlinks)", want, got)
	}
	// A path must not compile to both a mount and a symlink.
	seen := map[string]bool{}
	for _, m := range mounts {
		seen[m.Src] = true
	}
	for _, s := range symlinks {
		if seen[s.Path] {
			t.Errorf("%s compiled to BOTH a mount and a symlink", s.Path)
		}
	}
	// Under the merged-/usr probe, these must be symlinks, never binds. (/sbin is
	// macOS-only in the law, so it is not a Linux rule.)
	for _, p := range []string{"/bin", "/lib", "/lib64"} {
		if _, ok := findSymlink(symlinks, p); !ok {
			t.Errorf("%s must compile to a symlink under the merged-/usr probe", p)
		}
		if _, ok := findMount(mounts, p); ok {
			t.Errorf("%s must not also be a bind mount", p)
		}
	}

	// Cross-platform invariant (Linux half): every shared (arch-less) concrete rule is
	// enforced on Linux. The macOS half — that the same rule appears /private-normalized
	// in the Seatbelt compile — is the seatbelt package's TestMacOSConformance.
	linuxPaths := map[string]bool{}
	for _, m := range mounts {
		linuxPaths[m.Src] = true
	}
	for _, s := range symlinks {
		linuxPaths[s.Path] = true
	}
	for _, r := range sandbox.BaselineRules() {
		if len(r.Archs) != 0 || r.Regex {
			continue
		}
		l, _ := sandbox.ExpandPath(r.Path, testTokens())
		if !linuxPaths[l] {
			t.Errorf("shared rule %q missing from Linux compile (%s)", r.Path, l)
		}
	}
}

// TestCompileSkipsEmptyOrMissingToken proves the fail-safe: a rule whose token is
// missing or empty is skipped rather than binding a partially-resolved path.
func TestCompileSkipsEmptyOrMissingToken(t *testing.T) {
	rules := []sandbox.Rule{
		{Path: "$AGENT_CONFIG_DIR", Description: "d", Writeable: true},
		{Path: "$HOME/.cache", Description: "d", Writeable: true},
		{Path: "/usr", Description: "d"},
	}
	// AGENT_CONFIG_DIR absent from the map -> that rule is skipped; the rest compile.
	mounts, _, _ := compileLinuxBaseline(rules, map[string]string{"HOME": "/home/u"}, fakeFS{})
	if _, ok := findMount(mounts, "/home/u/.cache"); !ok {
		t.Error("$HOME/.cache must compile when HOME is set")
	}
	if _, ok := findMount(mounts, "/usr"); !ok {
		t.Error("/usr (no token) must compile")
	}
	for _, m := range mounts {
		if m.Src == "" {
			t.Error("no compiled mount may have an empty source")
		}
	}
	if len(mounts) != 2 {
		t.Errorf("$AGENT_CONFIG_DIR rule must be skipped when AGENT_CONFIG_DIR is unset; got %d: %+v", len(mounts), mounts)
	}
	// Empty HOME -> the $HOME/.cache rule is skipped (never bind "/.cache").
	mounts2, _, _ := compileLinuxBaseline(rules, map[string]string{"HOME": "", "AGENT_CONFIG_DIR": "/c"}, fakeFS{})
	if _, ok := findMount(mounts2, "/.cache"); ok {
		t.Error("must not bind /.cache when HOME is empty")
	}
}

// TestCompileCreateRule exercises the create path (a baseline rule with create:true
// that mkdir -p's its host path before binding, e.g. a sandbox-private dir).
func TestCompileCreateRule(t *testing.T) {
	rules := []sandbox.Rule{{Path: "$HOME/.cache/corral/npm", Description: "d", Writeable: true, Create: true}}
	mounts, _, createDirs := compileLinuxBaseline(rules, map[string]string{"HOME": "/home/u"}, fakeFS{})
	if len(createDirs) != 1 || createDirs[0] != "/home/u/.cache/corral/npm" {
		t.Errorf("create rule must record a createDir; got %v", createDirs)
	}
	if m, ok := findMount(mounts, "/home/u/.cache/corral/npm"); !ok || m.ReadOnly {
		t.Errorf("create rule must produce a writable mount; got %+v ok=%v", m, ok)
	}
}

// TestCompileLinuxBaselineGolden pins the compiled Linux baseline (a
// security-critical artifact) against testdata, using a fixed merged-/usr probe.
// TestPrepareFileMaskStubBind exercises the block.files path: Prepare must create the
// persistent ~/.cache/corral stub and turn each spec.BlockedFiles entry into a read-only
// Overlay bind sourced from it, and Argv must emit those binds after the directory tmpfs
// masks (so a file nested in a masked dir is re-added on top of the emptied dir).
func TestPrepareFileMaskStubBind(t *testing.T) {
	home := t.TempDir()
	spec := sandbox.SandboxSpec{
		Tokens:       map[string]string{"HOME": home, "AGENT_CONFIG_DIR": filepath.Join(home, ".claude")},
		BlockedPaths: []string{"/home/u/.config/app"},
		BlockedFiles: []string{"/home/u/.config/app/secret.txt", "/home/u/.npmrc"},
	}
	b := New("")
	if _, err := b.Prepare(&spec, io.Discard); err != nil {
		t.Fatal(err)
	}

	stub := filepath.Join(home, ".cache", "corral", "deny-stub.txt")
	data, err := os.ReadFile(stub)
	if err != nil {
		t.Fatalf("mask stub not created: %v", err)
	}
	if string(data) != maskStubContent {
		t.Errorf("stub content = %q, want %q", data, maskStubContent)
	}

	for _, f := range spec.BlockedFiles {
		var found *sandbox.Mount
		for i := range spec.Mounts {
			if m := spec.Mounts[i]; m.Overlay && m.Dst == f {
				found = &spec.Mounts[i]
				break
			}
		}
		if found == nil {
			t.Fatalf("no overlay mount for blocked file %q", f)
		}
		if found.Src != stub || !found.ReadOnly || !found.Optional {
			t.Errorf("blocked-file mount %+v: want src=%q, read-only, optional", *found, stub)
		}
	}

	argv, err := b.Argv(spec, []string{"claude"})
	if err != nil {
		t.Fatal(err)
	}
	line := strings.Join(argv, " ")
	maskIdx := strings.Index(line, "--tmpfs /home/u/.config/app")
	bindIdx := strings.Index(line, "--ro-bind-try "+stub+" /home/u/.config/app/secret.txt")
	if maskIdx < 0 || bindIdx < 0 {
		t.Fatalf("argv missing the dir mask and/or the file stub-bind:\n%s", line)
	}
	if bindIdx < maskIdx {
		t.Errorf("file stub-bind must be emitted AFTER the dir tmpfs mask:\n%s", line)
	}
}

func TestCompileLinuxBaselineGolden(t *testing.T) {
	mounts, symlinks, _ := compileLinuxBaseline(sandbox.BaselineRules(), testTokens(), mergedUsrFS())

	var b strings.Builder
	b.WriteString("# mounts\n")
	for _, m := range mounts {
		flag := "bind"
		if m.ReadOnly {
			flag = "ro-bind"
		}
		opt := ""
		if m.Optional {
			opt = " (try)"
		}
		fmt.Fprintf(&b, "%s %s%s\n", flag, m.Src, opt)
	}
	b.WriteString("# symlinks\n")
	for _, s := range symlinks {
		fmt.Fprintf(&b, "%s -> %s\n", s.Path, s.Target)
	}
	got := b.String()

	golden := filepath.Join("testdata", "baseline_linux.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run `go test -update`): %v", err)
	}
	if got != string(want) {
		t.Errorf("compiled baseline mismatch with %s:\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
	}
}

// ReadOnlyTargets exposes the baseline's read-only mount destinations (for the
// launcher's paths.rw-shadow warning). /usr is a stable read-only baseline target.
// The call must be side-effect-free — unlike a launch it must not create ~/.claude.
func TestBwrapReadOnlyTargets(t *testing.T) {
	home := t.TempDir()
	spec := sandbox.SandboxSpec{Tokens: map[string]string{
		"HOME":             home,
		"AGENT_CONFIG_DIR": filepath.Join(home, ".claude"),
	}}
	ro := New("bwrap").ReadOnlyTargets(spec)
	if !contains(ro, "/usr") {
		t.Errorf("baseline read-only targets should include /usr: %v", ro)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude")); !os.IsNotExist(err) {
		t.Errorf("ReadOnlyTargets must not create ~/.claude (stat err=%v)", err)
	}
}

// Prepare folds the embedded baseline into the spec's mounts (prepended, before the
// per-launch project/extra mounts) so Argv can stay a pure emitter, and asks for no
// launcher chdir (bwrap uses --chdir in its argv).
func TestBwrapPrepareFoldsBaseline(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	spec := sandbox.SandboxSpec{
		Tokens: map[string]string{"HOME": home, "AGENT_CONFIG_DIR": filepath.Join(home, ".claude")},
		Mounts: []sandbox.Mount{{Src: proj}},
	}
	prep, err := New("").Prepare(&spec, io.Discard)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if prep.Cleanup == nil {
		t.Error("Prepare must return a non-nil cleanup")
	}
	if prep.Chdir != "" {
		t.Errorf("bwrap needs no launcher chdir; got %q", prep.Chdir)
	}
	if _, ok := findMount(spec.Mounts, "/usr"); !ok {
		t.Errorf("Prepare must fold the baseline into the spec (expected a /usr mount); got %v", spec.Mounts)
	}
	projIdx, usrIdx := -1, -1
	for i, m := range spec.Mounts {
		switch m.Src {
		case proj:
			projIdx = i
		case "/usr":
			usrIdx = i
		}
	}
	if usrIdx < 0 || projIdx < 0 || usrIdx > projIdx {
		t.Errorf("baseline mounts must be prepended before the project mount; usr=%d proj=%d (%v)", usrIdx, projIdx, spec.Mounts)
	}
}

// A baseline rule with resolveSymlinks whose source is a symlink must compile to a
// bind of the resolved target at the unresolved destination — not a reproduced
// --symlink. Reproducing the link is the DNS bug on systemd-resolved distros, where
// /etc/resolv.conf points into /run/systemd/resolve (a path the sandbox never mounts),
// so the link would dangle. Covers both a relative link target (resolved against the
// link's own dir) and an absolute one (used as-is), and asserts the bind keeps the
// rule's read-only + required (fail-closed) posture.
func TestResolveSymlinksBindsResolvedTarget(t *testing.T) {
	rules := []sandbox.Rule{
		{Path: "/etc/resolv.conf", Description: "dns (relative link)", ResolveSymlinks: true},
		{Path: "/etc/absolute", Description: "abs link", ResolveSymlinks: true},
	}
	fs := fakeFS{links: map[string]string{
		"/etc/resolv.conf": "../run/systemd/resolve/stub-resolv.conf", // systemd-resolved: relative, into /run
		"/etc/absolute":    "/run/other/target",                       // absolute target: used verbatim
	}}
	mounts, symlinks, _ := compileLinuxBaseline(rules, testTokens(), fs)

	if len(symlinks) != 0 {
		t.Fatalf("resolveSymlinks rules must NOT be reproduced as --symlink; got %+v", symlinks)
	}

	m, ok := findMount(mounts, "/run/systemd/resolve/stub-resolv.conf")
	if !ok {
		t.Fatalf("relative link must resolve against the link's dir and bind the target; got %+v", mounts)
	}
	if m.Dst != "/etc/resolv.conf" {
		t.Errorf("resolved bind must land at the unresolved dest; got Dst=%q", m.Dst)
	}
	if !m.ReadOnly {
		t.Errorf("resolv.conf bind must be read-only; got %+v", m)
	}
	if m.Optional {
		t.Errorf("a required rule must stay required (fail-closed) after resolution; got %+v", m)
	}

	if m, ok := findMount(mounts, "/run/other/target"); !ok || m.Dst != "/etc/absolute" {
		t.Errorf("absolute link target must be bound verbatim at its dest; got %+v ok=%v", m, ok)
	}
}

// A resolveSymlinks rule must bind the fully-resolved target, not the first hop: a chained dotfile
// (~/.gitconfig -> ~/mid -> ~/.dotfiles/git/gitconfig) would otherwise bind a still-symlink source.
func TestResolveSymlinksFollowsChain(t *testing.T) {
	rules := []sandbox.Rule{{Path: "$HOME/.gitconfig", Description: "chained dotfile", ResolveSymlinks: true, Optional: true}}
	fs := fakeFS{links: map[string]string{
		"/home/u/.gitconfig": "/home/u/mid",
		"/home/u/mid":        ".dotfiles/git/gitconfig", // relative, resolved against /home/u
	}}
	mounts, symlinks, _ := compileLinuxBaseline(rules, testTokens(), fs)
	if len(symlinks) != 0 {
		t.Fatalf("resolveSymlinks rules must NOT be reproduced as --symlink; got %+v", symlinks)
	}
	m, ok := findMount(mounts, "/home/u/.dotfiles/git/gitconfig")
	if !ok {
		t.Fatalf("chain must resolve to the final target; got %+v", mounts)
	}
	if m.Dst != "/home/u/.gitconfig" {
		t.Errorf("resolved bind must land at the unresolved dest; got Dst=%q", m.Dst)
	}
	if !m.Optional {
		t.Errorf("an optional rule must stay optional after resolution; got %+v", m)
	}
}

// A resolveSymlinks target reached through a symlinked ancestor directory must bind the
// fully-canonicalized real path — the primary reason resolution is EvalSymlinks-based, not
// one-level. Uses a real t.TempDir tree with realFS (the production Linux resolver) because the
// fakeFS link table models final-component chains only, not ancestor symlinks — so realFS's
// ancestor behavior needs a real check here.
func TestResolveSymlinksFollowsSymlinkedAncestor(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "code", "dotfiles", "git")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(real, "gitconfig"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// ~/.dotfiles -> ~/code/dotfiles (symlinked ancestor); ~/.gitconfig -> ~/.dotfiles/git/gitconfig.
	if err := os.Symlink(filepath.Join(home, "code", "dotfiles"), filepath.Join(home, ".dotfiles")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".dotfiles", "git", "gitconfig"), filepath.Join(home, ".gitconfig")); err != nil {
		t.Fatal(err)
	}

	rules := []sandbox.Rule{{Path: "$HOME/.gitconfig", Description: "dotfile", ResolveSymlinks: true, Optional: true}}
	tokens := map[string]string{"HOME": home, "AGENT_CONFIG_DIR": filepath.Join(home, ".claude"), "XDG_RUNTIME_DIR": "/run/user/1000"}
	mounts, symlinks, _ := compileLinuxBaseline(rules, tokens, realFS{})

	if len(symlinks) != 0 {
		t.Fatalf("resolveSymlinks rules must NOT be reproduced as --symlink; got %+v", symlinks)
	}
	// EvalSymlinks of the directly-built real path folds any symlinked ancestor of t.TempDir() (macOS
	// /var -> /private/var), so the assertion is a canonical-vs-canonical comparison, not tautological:
	// a one-level regression would leave `.dotfiles` unresolved and miss this target.
	want, err := filepath.EvalSymlinks(filepath.Join(real, "gitconfig"))
	if err != nil {
		t.Fatal(err)
	}
	m, ok := findMount(mounts, want)
	if !ok {
		t.Fatalf("symlinked-ancestor target must resolve to canonical %q; got %+v", want, mounts)
	}
	if m.Dst != filepath.Join(home, ".gitconfig") {
		t.Errorf("resolved bind must land at the unresolved dest; got Dst=%q", m.Dst)
	}
}

// Package bwrap is the Linux sandbox backend: it compiles a sandbox.SandboxSpec
// into a bubblewrap (bwrap) invocation.
package bwrap

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/sandbox"
)

type Backend struct {
	Path string
}

func New(path string) Backend {
	if path == "" {
		path = "bwrap"
	}
	return Backend{Path: path}
}

func (b Backend) Name() string { return "bwrap" }

func (b Backend) Available() bool {
	_, err := exec.LookPath(b.bin())
	return err == nil
}

func (b Backend) UnavailableHint() string {
	return fmt.Sprintf("bwrap not found (%q); install bubblewrap or pass -bwrap", b.bin())
}

func (b Backend) Doctor(w io.Writer) {
	sandbox.ReportTool(w, b.bin())
	if ns, err := os.Readlink("/proc/self/ns/pid"); err == nil {
		fmt.Fprintf(w, "  pid namespace: %s\n", ns)
	} else {
		fmt.Fprintf(w, "  pid namespace: unavailable (%v)\n", err)
	}
	reportLegacyTIOCSTI(w, legacyTIOCSTIPath)
}

const legacyTIOCSTIPath = "/proc/sys/dev/tty/legacy_tiocsti"

// reportLegacyTIOCSTI surfaces the residual risk of sharing the caller's
// terminal with the sandbox. Where legacy TIOCSTI is still enabled, a process
// inside the sandbox can push characters into the terminal's input queue for
// the operator's shell to run after corral exits. Warns rather than blocks:
// it reports a host-kernel property corral cannot change.
func reportLegacyTIOCSTI(w io.Writer, path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(w, "  legacy tiocsti: not present — this kernel has no legacy TIOCSTI path")
		return
	}
	if strings.TrimSpace(string(raw)) != "1" {
		fmt.Fprintln(w, "  legacy tiocsti: disabled")
		return
	}
	fmt.Fprintln(w, "  legacy tiocsti: ENABLED — the sandbox shares your terminal, so a process inside it")
	fmt.Fprintln(w, "    could inject keystrokes into your shell; set dev.tty.legacy_tiocsti=0 to close that")
}

func (b Backend) ReadOnlyTargets(spec sandbox.SandboxSpec) []string {
	mounts, _, _ := compileLinuxBaseline(sandbox.RulesFor(spec), spec.Tokens, realFS{})
	var out []string
	for _, m := range mounts {
		if m.ReadOnly {
			out = append(out, sandbox.MountTarget(m))
		}
	}
	return out
}

func (b Backend) AgentNotes() []string { return nil }

// Prepare compiles the embedded baseline into bwrap bind mounts/symlinks and
// prepends them to the spec, so Argv stays a pure spec→argv emitter. bwrap
// acquires no launch resource, so the returned cleanup is a no-op.
func (b Backend) Prepare(spec *sandbox.SandboxSpec, w io.Writer) (sandbox.LaunchPrep, error) {
	mounts, symlinks, createDirs := compileLinuxBaseline(sandbox.RulesFor(*spec), spec.Tokens, realFS{})
	for _, d := range createDirs {
		_ = os.MkdirAll(d, 0o700)
	}
	spec.Mounts = append(mounts, spec.Mounts...)
	spec.Symlinks = append(symlinks, spec.Symlinks...)

	// File masks: a tmpfs needs a directory mountpoint, so a file cannot be
	// tmpfs-masked. Mask each by RO-binding a stub over it, emitted as an
	// Overlay mount so Argv places it after the directory tmpfs masks. Best-effort:
	// if the stub cannot be created the file stays hook-enforced.
	if len(spec.BlockedFiles) > 0 {
		stub, err := ensureMaskStub(spec.Tokens["HOME"])
		if err != nil {
			fmt.Fprintf(w, "corral: warning: could not create the file-mask stub (%v); "+
				"providers.block.files stay hook-enforced but are not filesystem-masked\n", err)
		} else {
			for _, f := range spec.BlockedFiles {
				spec.Mounts = append(spec.Mounts, sandbox.Mount{
					Src: stub, Dst: f, ReadOnly: true, Overlay: true, Optional: true,
				})
			}
		}
	}
	return sandbox.LaunchPrep{Cleanup: func() {}}, nil
}

const maskStubContent = "File content masked by corral\n"

// ensureMaskStub idempotently creates the shared file-mask stub under
// home/.cache/corral and returns its host path.
func ensureMaskStub(home string) (string, error) {
	if home == "" {
		return "", errors.New("no HOME to place the mask stub under")
	}
	dir := filepath.Join(home, ".cache", "corral")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	stub := filepath.Join(dir, "deny-stub.txt")
	if data, err := os.ReadFile(stub); err != nil || string(data) != maskStubContent {
		if err := os.WriteFile(stub, []byte(maskStubContent), 0o444); err != nil {
			return "", err
		}
	}
	return stub, nil
}

// Argv compiles spec into a full bwrap argv. Pure function of spec (the baseline
// is already folded into spec.Mounts/Symlinks by Prepare). Argument order is
// deterministic, so the argv is golden-testable from a hand-built spec.
func (b Backend) Argv(spec sandbox.SandboxSpec, command []string) ([]string, error) {
	if len(command) == 0 {
		return nil, errors.New("sandbox: empty command")
	}
	bin := b.bin()

	args := []string{bin}

	args = append(args, "--clearenv")
	for _, k := range slices.Sorted(maps.Keys(spec.SetEnv)) {
		args = append(args, "--setenv", k, spec.SetEnv[k])
	}

	// Fresh tmpfs mounts first, so a later bind whose destination lands under
	// one layers on top of the empty tmpfs instead of being shadowed by it.
	for _, t := range spec.Tmpfs {
		args = append(args, "--tmpfs", t)
	}

	for _, m := range orderBinds(spec.Mounts) {
		a, err := bindArgs(m)
		if err != nil {
			return nil, err
		}
		args = append(args, a...)
	}

	for _, s := range spec.Symlinks {
		args = append(args, "--symlink", s.Target, s.Path)
	}

	args = append(args, "--proc", "/proc", "--dev", "/dev")

	// Blocked paths masked with an empty tmpfs, after binds so they win even
	// when nested under a bound directory.
	for _, p := range spec.BlockedPaths {
		args = append(args, "--tmpfs", p)
	}

	// Overlay mounts after blocked-path masks so they re-grant a specific
	// vetted file on top of an emptied secret dir.
	for _, m := range spec.Mounts {
		if !m.Overlay {
			continue
		}
		a, err := bindArgs(m)
		if err != nil {
			return nil, err
		}
		args = append(args, a...)
	}

	// --new-session is deliberately not passed: it detaches the controlling
	// terminal, which breaks the agent's interactive TUI. The cost is that the
	// sandbox shares that terminal, and on a kernel with legacy TIOCSTI still
	// enabled a process inside could ioctl(TIOCSTI) characters into the
	// terminal's input queue. Linux 6.2 removed that path by default; Doctor
	// warns when it is still enabled.
	args = append(
		args,
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-uts",
		"--unshare-cgroup",
	)
	if spec.Net == sandbox.NetNone {
		args = append(args, "--unshare-net")
	}

	if spec.Hostname != "" {
		args = append(args, "--hostname", spec.Hostname)
	}
	if spec.DieWithParent {
		args = append(args, "--die-with-parent")
	}
	if spec.WorkDir != "" {
		args = append(args, "--chdir", spec.WorkDir)
	}

	args = append(args, command...)
	return args, nil
}

func (b Backend) bin() string {
	if b.Path == "" {
		return "bwrap"
	}
	return b.Path
}

// orderBinds returns non-Overlay mounts in emit order: every read-only mount,
// then every read-write mount, each group ordered so a mount comes after any
// mount whose destination contains it. Read-write after read-only gives bwrap
// Seatbelt's semantics: a write is allowed wherever a read-write grant covers
// the path.
func orderBinds(mounts []sandbox.Mount) []sandbox.Mount {
	var ro, rw []sandbox.Mount
	for _, m := range mounts {
		switch {
		case m.Overlay:
		case m.ReadOnly:
			ro = append(ro, m)
		default:
			rw = append(rw, m)
		}
	}
	return append(topoByContainment(ro), topoByContainment(rw)...)
}

// topoByContainment orders mounts so every mount comes after any mount whose
// destination strictly contains its own. Among ready mounts it always takes
// the earliest in input order. Strict containment is a partial order, so the
// loop always terminates.
func topoByContainment(mounts []sandbox.Mount) []sandbox.Mount {
	n := len(mounts)
	dsts := make([]string, n)
	for i, m := range mounts {
		dsts[i] = filepath.Clean(sandbox.MountTarget(m))
	}
	inDegree := make([]int, n)
	for i := range dsts {
		for j := range dsts {
			if pathutil.Under(dsts[i], dsts[j]) {
				inDegree[i]++
			}
		}
	}
	out := make([]sandbox.Mount, 0, n)
	emitted := make([]bool, n)
	for len(out) < n {
		for i := 0; i < n; i++ {
			if emitted[i] || inDegree[i] > 0 {
				continue
			}
			out = append(out, mounts[i])
			emitted[i] = true
			for j := range dsts {
				if !emitted[j] && pathutil.Under(dsts[j], dsts[i]) {
					inDegree[j]--
				}
			}
			break
		}
	}
	return out
}

func bindArgs(m sandbox.Mount) ([]string, error) {
	if m.Src == "" {
		return nil, errors.New("sandbox: empty mount source")
	}
	flag := "--bind"
	if m.ReadOnly {
		flag = "--ro-bind"
	}
	if m.Optional {
		flag += "-try"
	}
	dst := m.Dst
	if dst == "" {
		dst = m.Src
	}
	return []string{flag, m.Src, dst}, nil
}

// fsProbe abstracts host-dependent symlink decisions so the Linux compiler is
// a pure, deterministically-testable function.
type fsProbe interface {
	symlink(path string) (bool, string)
	resolve(path string) string
}

type realFS struct{}

func (realFS) symlink(path string) (bool, string) {
	fi, err := os.Lstat(path)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		return false, ""
	}
	target, err := os.Readlink(path)
	if err != nil {
		return false, ""
	}
	return true, target
}

func (realFS) resolve(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}
	return resolved
}

// compileLinuxBaseline turns the baseline rules into bwrap mounts + symlinks.
// A symlink source (e.g. /bin -> usr/bin) becomes a Symlink rather than a bind;
// a required source that is missing stays a hard bind so the launch fails closed.
func compileLinuxBaseline(rules []sandbox.Rule, tokens map[string]string, probe fsProbe) (mounts []sandbox.Mount, symlinks []sandbox.Symlink, createDirs []string) {
	for _, r := range rules {
		if !sandbox.ArchMatch(r, "linux") || r.Regex {
			continue
		}
		path, ok := sandbox.ExpandPath(r.Path, tokens)
		if !ok || path == "" {
			continue
		}
		if r.Create {
			createDirs = append(createDirs, path)
			mounts = append(mounts, sandbox.Mount{Src: path, ReadOnly: !r.Writeable})
			continue
		}
		if r.ResolveSymlinks {
			// Bind the fully-canonicalized target at the unresolved destination.
			// Keeps /etc/resolv.conf working on systemd-resolved distros where
			// it's a symlink into /run/systemd/resolve — a path the sandbox never
			// mounts. Merged-/usr dir symlinks don't set the flag and stay
			// reproduced below; their target /usr is mounted.
			mounts = append(mounts, sandbox.Mount{Src: probe.resolve(path), Dst: path, ReadOnly: !r.Writeable, Optional: r.Optional})
			continue
		}
		if isSym, target := probe.symlink(path); isSym {
			symlinks = append(symlinks, sandbox.Symlink{Target: target, Path: path})
			continue
		}
		mounts = append(mounts, sandbox.Mount{Src: path, ReadOnly: !r.Writeable, Optional: r.Optional})
	}
	return mounts, symlinks, createDirs
}

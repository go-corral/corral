package sandbox

import (
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/go-corral/corral/internal/health"
)

// NetPolicy describes the sandbox's network posture. Only NetOpen is set
// today; the field exists so the launch path never hard-codes "network is
// open" where it would be costly to undo if egress filtering is ever added.
type NetPolicy string

const (
	NetOpen NetPolicy = "open"
	// NetNone gives the sandbox no network. Config rejects it; the backends
	// carry the plumbing so egress filtering has a place to plug in.
	NetNone NetPolicy = "none"
)

// Mount is a bind mount of a host path into the sandbox.
type Mount struct {
	Src      string
	Dst      string
	ReadOnly bool
	// Optional: a missing source is skipped instead of failing the launch
	// (bwrap --bind-try/--ro-bind-try).
	Optional bool
	// Overlay marks a mount layered on top of a BlockedPaths mask, emitted
	// after the masks so it re-grants a specific file inside an otherwise
	// emptied secret dir (e.g. ssh provider re-adding ~/.ssh/config).
	Overlay bool
}

// Symlink is a symlink created inside the sandbox (e.g. /bin -> usr/bin).
type Symlink struct {
	Target string
	Path   string
}

// SandboxSpec is the backend-agnostic description of a sandbox, compiled by
// each backend to its native form (bwrap argv, Seatbelt SBPL).
//
// Where two mounts overlap, a read-write mount wins over a read-only one on
// every backend. BlockedPaths masks are applied after ordinary mounts, and
// Overlay mounts are applied last, re-granting vetted files on top of an
// emptied masked dir.
type SandboxSpec struct {
	Hostname string
	WorkDir  string
	Mounts   []Mount
	Symlinks []Symlink
	Tmpfs    []string
	// BlockedPaths are directories masked with an empty tmpfs even under a
	// mounted directory. Applied after ordinary mounts, before Overlay mounts.
	BlockedPaths []string
	// BlockedFiles are individual files to mask. A tmpfs needs a directory
	// mountpoint, so bwrap RO-binds a stub over each (as an Overlay mount);
	// Seatbelt denies each as an SBPL literal. The hook enforces them
	// regardless — the FS mask is defense-in-depth.
	BlockedFiles   []string
	SetEnv         map[string]string
	TempEnvAliases []string
	// AgentRules are the selected agent's filesystem grants outside its config
	// dir, unioned with the embedded baseline at compile time (RulesFor) so a
	// backend compiles them identically to the embedded rules. Empty keeps the
	// launch agent-neutral.
	AgentRules []Rule
	// Tokens expands the baseline's path tokens for this launch. A rule whose
	// token is missing/empty is skipped (fail-safe). A backend may add a token
	// in Prepare (Seatbelt fills $SESSION_TMPDIR).
	Tokens        map[string]string
	Net           NetPolicy
	DieWithParent bool
}

// LaunchPrep is what a backend's Prepare returns: backend-specific launch
// ceremony captured so the launcher orchestrates every backend uniformly.
type LaunchPrep struct {
	// Cleanup releases any resource Prepare acquired. Always non-nil — a
	// no-op for backends that acquire nothing.
	Cleanup func()
	// Chdir, when non-empty, is a directory the launcher must chdir into before
	// launch. Seatbelt has no in-sandbox working-directory control; bwrap returns "".
	Chdir string
}

// Backend compiles a SandboxSpec into a concrete launch invocation.
type Backend interface {
	Name() string
	Available() bool
	UnavailableHint() string
	Doctor() []health.Check
	// ReadOnlyTargets returns the in-sandbox paths this backend would expose
	// read-only from the embedded baseline. The launcher uses it to warn when
	// a providers.paths.rw grant would shadow a baseline read-only system path.
	ReadOnlyTargets(spec SandboxSpec) []string
	// AgentNotes are static, secret-free, model-facing lines describing
	// environment quirks the agent would otherwise waste turns discovering.
	AgentNotes() []string
	// Prepare performs backend-specific pre-launch setup, mutating spec in
	// place, and returns the resulting LaunchPrep. Best-effort setup warns via
	// w; a returned error is fatal.
	Prepare(spec *SandboxSpec, w io.Writer) (LaunchPrep, error)
	// Argv returns the full argv to launch command inside the sandbox. The
	// first element is the sandbox helper binary; the caller starts it with
	// spec.Environ() as its environment. Pure function of spec (Prepare has
	// already folded any baseline contribution), keeping the argv
	// golden-testable from a hand-built spec.
	Argv(spec SandboxSpec, command []string) ([]string, error)
}

// IsLoaderEnv reports whether name is a dynamic loader variable: LD_ for ld.so, DYLD_ for dyld.
// The loader applies it to the host-side helper itself, so a value that points into the sandbox
// would run sandbox-written code on the host.
func IsLoaderEnv(name string) bool {
	return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_")
}

// Environ returns SetEnv as NAME=VALUE entries sorted by name, without loader variables.
// The result is never nil: a nil exec.Cmd.Env inherits os.Environ().
func (s SandboxSpec) Environ() []string {
	env := make([]string, 0, len(s.SetEnv))
	for _, k := range slices.Sorted(maps.Keys(s.SetEnv)) {
		if !IsLoaderEnv(k) {
			env = append(env, k+"="+s.SetEnv[k])
		}
	}
	return env
}

// MountTarget is the in-sandbox path a mount lands at (Dst, or Src when empty).
func MountTarget(m Mount) string {
	if m.Dst != "" {
		return m.Dst
	}
	return m.Src
}

// Package spec holds the provider contract: the Provider interface and every
// neutral carrier type a provider implementation produces or consumes. It is a
// leaf package — it imports sandbox and no other corral package.
package spec

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/go-corral/corral/internal/sandbox"
)

// Session is the per-launch context handed to a provider. ID is unique per launch
// and, with User, names out-of-process resources so cross-session GC can rediscover
// orphans by convention.
type Session struct {
	User    string
	ID      string
	WorkDir string
}

// Contribution is what an active provider adds to the sandbox. It is purely
// in-memory and ephemeral (no path into Config).
type Contribution struct {
	Mounts []sandbox.Mount
	// Env values may be secret (a minted token); they never leave memory.
	Env map[string]string
	// Status are secret-free lines for the startup banner. Authored from metadata only.
	Status []string
	// AgentNotes are secret-free, model-facing lines. Keep each to one terse line —
	// they ride every turn's context.
	AgentNotes []string
	// Warnings are secret-free advisory lines the launcher prints after the providers
	// section. They are ignored when Mint fails, so a failing Mint puts them in its error.
	Warnings []string
	// CleanupHint is surfaced only when Cleanup fails: the residual-credential risk
	// and the remedy.
	CleanupHint string
	// Cleanup tears down whatever Mint created; fires LIFO on launcher exit. nil when
	// there is nothing to undo.
	Cleanup func(context.Context) error
	// PostSession runs once the agent session ends for host-side work. It runs in
	// declaration order on an unbounded context, before Cleanup. It is the one field
	// honored from a Contribution returned alongside a Mint error, so a provider
	// whose Mint ran host side effects still gets its paired postEnd.
	PostSession func(ctx context.Context, exit SessionExit) error

	// Built-in provider channels: the launcher half of the config-owned built-in
	// providers (block, aiignore, paths, env).

	// RWPaths/ROPaths are extra host paths granted same-path as Optional mounts.
	// A missing path is skipped; a deliberate overlap with a baseline path is
	// warn-and-allow.
	RWPaths []string
	ROPaths []string
	// BlockedDirs/BlockedFiles extend the spec's FS mask, append-unique. The
	// always-blocked paths are not carried here — they are baked into the spec.
	BlockedDirs  []string
	BlockedFiles []string
	// EnvSet are config-pinned env entries applied in order. An entry may override a
	// value corral already set (advisory warning, never a launch error).
	EnvSet []EnvEntry
}

// EnvEntry is one EnvSet pair. A slice of pairs (not a map) so application stays
// in declaration order.
type EnvEntry struct {
	Name  string
	Value string
}

// SessionExit tells a PostSession hook how the agent session ended. Its zero
// value means the launch was aborted before the agent ran.
type SessionExit struct {
	Started  bool
	Code     int
	Signaled bool
}

// Provider is a sanitized host capability. dryRun tells Mint to perform no side
// effect; a Mint that is irreducibly a side effect (a minter's live API call)
// returns an error. This makes dryRun the single preview mechanism.
type Provider interface {
	Name() string
	Available(ctx context.Context) bool
	Mint(ctx context.Context, sess Session, dryRun bool) (*Contribution, error)
}

// Orphan is a leftover out-of-process resource discovered by a Reaper (used only
// by `corral gc`).
type Orphan struct {
	Provider string
	ID       string
	Describe string
}

// Reaper is the optional interface for providers that create out-of-process
// resources needing cross-session garbage collection. It powers `corral gc` only
// — a separate concern from Contribution.Cleanup.
type Reaper interface {
	Provider
	GC(ctx context.Context) ([]Orphan, error)
	Reap(ctx context.Context, approved []Orphan) error
}

// ErrNoDryRun is the standard error a credential provider returns from Mint under
// dryRun. detail completes the sentence "<provider>: cannot <detail> (no dry-run mode)".
func ErrNoDryRun(provider, detail string) error {
	return fmt.Errorf("%s: cannot %s (no dry-run mode)", provider, detail)
}

// IsSocket reports whether path exists and is a unix socket.
func IsSocket(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// IsRegular reports whether path resolves to a regular file.
func IsRegular(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

const summarizeCap = 6

// Summarize joins up to summarizeCap paths and counts the rest.
func Summarize(paths []string) string {
	if len(paths) <= summarizeCap {
		return strings.Join(paths, ", ")
	}
	return strings.Join(paths[:summarizeCap], ", ") + fmt.Sprintf(" (+%d more)", len(paths)-summarizeCap)
}

// SummarizeQuoted is Summarize with each path backtick-quoted, for the model-facing
// AgentNotes that render as markdown.
func SummarizeQuoted(paths []string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = "`" + p + "`"
	}
	return Summarize(q)
}

// IsEnvName reports whether s is a POSIX environment variable name.
func IsEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '_':
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// SanitizeLabel keeps s valid as a k8s label value (alphanumerics, -, _, ., <=63,
// must start/end alphanumeric).
func SanitizeLabel(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "-_.")
	if len(out) > 63 {
		out = strings.Trim(out[:63], "-_.")
	}
	if out == "" {
		out = "unknown"
	}
	return out
}

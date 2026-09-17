// Package providers is the facade upper layers import; the provider contract
// lives in the leaf package internal/providers/spec (re-exported here as aliases).
// What remains is the engine — Resolve/ResolvePreview, Apply, Cleanup — callable
// only by the launcher.
package providers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/providers/spec"
	"github.com/go-corral/corral/internal/sandbox"
)

// Re-exported contract types, aliased rather than wrapped, so upper layers never
// need to import internal/providers/spec directly.
type (
	Session      = spec.Session
	Contribution = spec.Contribution
	Provider     = spec.Provider
	Orphan       = spec.Orphan
	Reaper       = spec.Reaper
	EnvEntry     = spec.EnvEntry
	SessionExit  = spec.SessionExit
)

// Active pairs a provider with its launch-time policy. Optional downgrades both
// failure modes — an unavailable prerequisite and a Mint error — to a
// skip-with-warning; otherwise each fails closed.
type Active struct {
	Provider Provider
	Optional bool
}

type Notice struct {
	Provider string
	Text     string
}

type Resolved struct {
	items        []resolvedItem
	cleanups     []namedCleanup
	postSessions []namedPostSession
	Warnings     []string
	Notices      []Notice
	AgentNotes   []Notice
	LogWriter    io.Writer
	mountOwners  map[string]string
	envOwners    map[string]string
}

type resolvedItem struct {
	provider string
	mounts   []sandbox.Mount
	env      map[string]string
	// built-in provider channels
	rwPaths      []string
	roPaths      []string
	blockedDirs  []string
	blockedFiles []string
	envSet       []spec.EnvEntry
}

func noticesFor(provider string, lines []string) []Notice {
	out := make([]Notice, len(lines))
	for i, s := range lines {
		out[i] = Notice{Provider: provider, Text: s}
	}
	return out
}

func newResolvedItem(name string, c *Contribution) resolvedItem {
	return resolvedItem{
		provider:     name,
		mounts:       c.Mounts,
		env:          c.Env,
		rwPaths:      c.RWPaths,
		roPaths:      c.ROPaths,
		blockedDirs:  c.BlockedDirs,
		blockedFiles: c.BlockedFiles,
		envSet:       c.EnvSet,
	}
}

// namedCleanup pairs a teardown closure with its provider name for failure
// attribution. hint is surfaced if the closure fails.
type namedCleanup struct {
	provider string
	fn       func(context.Context) error
	hint     string
}

type namedPostSession struct {
	provider string
	fn       func(context.Context, SessionExit) error
}

const unwindTimeout = 30 * time.Second

// Resolve runs each active provider in declaration order. An unavailable prerequisite
// or a Mint error fails the launch closed unless the provider is optional (then
// skip-with-warning); on a fail-closed error mid-sequence, accumulated contributions
// are torn down before returning.
func Resolve(ctx context.Context, sess Session, active []Active) (res *Resolved, err error) {
	res = &Resolved{}
	defer func() {
		if err != nil {
			// Fire session-end hooks before tearing down credentials on a fresh ctx,
			// since the launch ctx may be the cancellation that failed the resolve.
			_ = res.RunPostSession(context.Background(), SessionExit{})
			uctx, cancel := context.WithTimeout(context.Background(), unwindTimeout)
			defer cancel()
			_ = res.Cleanup(uctx)
			res = nil
		}
	}()

	for _, a := range active {
		// Honor cancellation between providers.
		if cerr := ctx.Err(); cerr != nil {
			return res, fmt.Errorf("provider resolution canceled: %w", cerr)
		}
		p := a.Provider
		if !p.Available(ctx) {
			if a.Optional {
				res.Warnings = append(res.Warnings, fmt.Sprintf("provider %q unavailable; skipped (optional)", p.Name()))
				continue
			}
			return res, fmt.Errorf("provider %q unavailable (required; set optional: true to allow skipping)", p.Name())
		}
		c, mErr := p.Mint(ctx, sess, false)
		if mErr != nil {
			// Only PostSession is honored from a failing Mint, so a provider whose
			// Mint ran host side effects still gets its paired postEnd.
			if c != nil && c.PostSession != nil {
				res.postSessions = append(res.postSessions, namedPostSession{provider: p.Name(), fn: c.PostSession})
			}
			if a.Optional {
				res.Warnings = append(res.Warnings, fmt.Sprintf("provider %q: %v (optional; skipped)", p.Name(), mErr))
				continue
			}
			return res, fmt.Errorf("provider %q: %w", p.Name(), mErr)
		}
		if c == nil {
			continue
		}
		res.items = append(res.items, newResolvedItem(p.Name(), c))
		res.Notices = append(res.Notices, noticesFor(p.Name(), c.Status)...)
		res.AgentNotes = append(res.AgentNotes, noticesFor(p.Name(), c.AgentNotes)...)
		if c.Cleanup != nil {
			res.cleanups = append(res.cleanups, namedCleanup{provider: p.Name(), fn: c.Cleanup, hint: c.CleanupHint})
		}
		if c.PostSession != nil {
			res.postSessions = append(res.postSessions, namedPostSession{provider: p.Name(), fn: c.PostSession})
		}
	}
	return res, nil
}

// ResolvePreview builds a side-effect-free preview for `corral run --dry-run`. Each
// Mint runs with dryRun=true: a contribution is merged, an error (a minter refuses
// dryRun) is collected in notExpanded, unavailable+optional is skipped, and
// unavailable+required returns the same fail-closed error Resolve would. The result
// carries no cleanups or post-session hooks.
func ResolvePreview(ctx context.Context, sess Session, active []Active) (res *Resolved, notExpanded []string, err error) {
	res = &Resolved{}
	for _, a := range active {
		p := a.Provider
		if !p.Available(ctx) {
			if !a.Optional {
				return nil, nil, fmt.Errorf("provider %q unavailable (required; set optional: true to allow skipping)", p.Name())
			}
			res.Warnings = append(res.Warnings, fmt.Sprintf("provider %q unavailable; skipped (optional)", p.Name()))
			continue
		}
		c, mErr := p.Mint(ctx, sess, true)
		if mErr != nil {
			notExpanded = append(notExpanded, p.Name())
			continue
		}
		if c == nil {
			continue
		}
		res.items = append(res.items, newResolvedItem(p.Name(), c))
		res.Notices = append(res.Notices, noticesFor(p.Name(), c.Status)...)
		res.AgentNotes = append(res.AgentNotes, noticesFor(p.Name(), c.AgentNotes)...)
	}
	return res, notExpanded, nil
}

// Mounts returns the resolved contributions' mounts in provider order. Nil-safe.
func (r *Resolved) Mounts() []sandbox.Mount {
	if r == nil {
		return nil
	}
	var out []sandbox.Mount
	for _, it := range r.items {
		out = append(out, it.mounts...)
	}
	return out
}

// Apply merges the resolved contributions into spec. It checks all collisions first
// (provider-vs-provider and provider-vs-baseline duplicate mounts/env keys, and a mount
// landing in a blocked-path mask) before any mutation. A collision is a launch
// error, never a silent override.
//
// prior is an earlier Apply phase's Resolved over the same spec; its entries are
// already in the spec, so prior only refines attribution.
func (r *Resolved) Apply(spec *sandbox.SandboxSpec, prior ...*Resolved) error {
	if r == nil {
		return nil
	}

	seenMount := map[string]string{}
	for _, m := range spec.Mounts {
		seenMount[mountDst(m)] = "baseline"
	}
	for _, p := range prior {
		if p == nil {
			continue
		}
		for dst, owner := range p.mountOwners {
			seenMount[dst] = owner
		}
	}
	blockedDirs := append([]string{}, spec.BlockedPaths...)
	blockedFiles := append([]string{}, spec.BlockedFiles...)
	seenEnv := map[string]string{}
	for k := range spec.SetEnv {
		seenEnv[k] = "baseline"
	}
	for _, p := range prior {
		if p == nil {
			continue
		}
		for k, owner := range p.envOwners {
			seenEnv[k] = owner
		}
	}
	// Pre-claim corral's own env channels so a provider Env can neither plant nor clobber them.
	seenEnv[sandbox.ProviderNotesEnvVar] = "corral (reserved for provider notes)"
	seenEnv[sandbox.BackendNotesEnvVar] = "corral (reserved for backend notes)"
	for _, name := range []string{sandbox.SandboxEnvVar, sandbox.GlobalConfigEnvVar, sandbox.AgentEnvVar, sandbox.BinEnvVar} {
		seenEnv[name] = "corral (reserved control marker)"
	}

	for _, it := range r.items {
		blockedDirs = append(blockedDirs, it.blockedDirs...)
		blockedFiles = append(blockedFiles, it.blockedFiles...)
		for _, m := range it.mounts {
			dst := mountDst(m)
			if dst == "" {
				return fmt.Errorf("provider %q: mount has empty source and destination", it.provider)
			}
			if owner, ok := seenMount[dst]; ok {
				return fmt.Errorf("provider %q: mount target %q already provided by %s", it.provider, dst, owner)
			}
			if !m.Overlay {
				for _, b := range blockedDirs {
					if pathutil.AtOrUnderClean(dst, b) {
						return fmt.Errorf("provider %q: mount target %q is inside blocked path %q (would be masked)", it.provider, dst, b)
					}
				}
				for _, b := range blockedFiles {
					if pathutil.AtOrUnderClean(dst, b) {
						return fmt.Errorf("provider %q: mount target %q is a blocked file %q (would be masked)", it.provider, dst, b)
					}
				}
			}
			seenMount[dst] = it.provider
		}
		for k := range it.env {
			if owner, ok := seenEnv[k]; ok {
				return fmt.Errorf("provider %q: env %q already provided by %s", it.provider, k, owner)
			}
			seenEnv[k] = it.provider
		}
		// EnvSet names claim their key but don't collide here: overriding is
		// warn-and-allow, and config already rejects duplicate set names.
		for _, e := range it.envSet {
			if _, ok := seenEnv[e.Name]; !ok {
				seenEnv[e.Name] = it.provider + " (env.set)"
			}
		}
	}

	if r.mountOwners == nil {
		r.mountOwners, r.envOwners = map[string]string{}, map[string]string{}
	}
	for _, it := range r.items {
		// Built-in grant channel: same-path Optional mounts. A missing path is skipped.
		for _, src := range it.rwPaths {
			spec.Mounts = append(spec.Mounts, sandbox.Mount{Src: src, Optional: true})
			r.mountOwners[src] = it.provider
		}
		for _, src := range it.roPaths {
			spec.Mounts = append(spec.Mounts, sandbox.Mount{Src: src, ReadOnly: true, Optional: true})
			r.mountOwners[src] = it.provider
		}
		spec.BlockedPaths = appendUnique(spec.BlockedPaths, it.blockedDirs)
		spec.BlockedFiles = appendUnique(spec.BlockedFiles, it.blockedFiles)
		if len(it.envSet) > 0 && spec.SetEnv == nil {
			spec.SetEnv = map[string]string{}
		}
		for _, e := range it.envSet {
			if old, ok := spec.SetEnv[e.Name]; ok && old != e.Value {
				r.Warnings = append(r.Warnings, fmt.Sprintf("providers.env.set: %q overrides a value corral already sets for the sandbox", e.Name))
			}
			spec.SetEnv[e.Name] = e.Value
			r.envOwners[e.Name] = it.provider + " (env.set)"
		}
		spec.Mounts = append(spec.Mounts, it.mounts...)
		for _, m := range it.mounts {
			r.mountOwners[mountDst(m)] = it.provider
		}
		if len(it.env) > 0 && spec.SetEnv == nil {
			spec.SetEnv = map[string]string{}
		}
		for k, v := range it.env {
			spec.SetEnv[k] = v
			r.envOwners[k] = it.provider
		}
	}
	// Fold the collected model-facing notes into the reserved env var as bullets.
	// Append across phases: the second Apply must not clobber the first's notes.
	if len(r.AgentNotes) > 0 {
		if spec.SetEnv == nil {
			spec.SetEnv = map[string]string{}
		}
		lines := make([]string, len(r.AgentNotes))
		for i, n := range r.AgentNotes {
			lines[i] = "- " + n.Provider + ": " + n.Text
		}
		notes := strings.Join(lines, "\n")
		if prev := spec.SetEnv[sandbox.ProviderNotesEnvVar]; prev != "" {
			notes = prev + "\n" + notes
		}
		spec.SetEnv[sandbox.ProviderNotesEnvVar] = notes
	}
	return nil
}

// appendUnique appends the entries of add not already present in dst (order kept).
func appendUnique(dst, add []string) []string {
	seen := make(map[string]bool, len(dst))
	for _, s := range dst {
		seen[s] = true
	}
	for _, s := range add {
		if !seen[s] {
			seen[s] = true
			dst = append(dst, s)
		}
	}
	return dst
}

// Cleanup runs the teardown closures LIFO, joining any errors; idempotent.
// With LogWriter set, each teardown logs a confirmation or the residual-credential
// risk on failure. Nil LogWriter stays silent.
func (r *Resolved) Cleanup(ctx context.Context) error {
	if r == nil {
		return nil
	}
	var errs []error
	for i := len(r.cleanups) - 1; i >= 0; i-- {
		nc := r.cleanups[i]
		if err := nc.fn(ctx); err != nil {
			errs = append(errs, err)
			if r.LogWriter != nil {
				hint := nc.hint
				if hint == "" {
					hint = "a minted credential may still be live until it expires on its own"
				}
				fmt.Fprintf(r.LogWriter, "corral: %s: teardown FAILED — %s\n", nc.provider, hint)
			}
		} else if r.LogWriter != nil {
			fmt.Fprintf(r.LogWriter, "corral: %s: minted credentials torn down\n", nc.provider)
		}
	}
	r.cleanups = nil
	return errors.Join(errs...)
}

// HasCleanup reports whether any provider registered a teardown. The launcher
// picks its strategy from it: none -> syscall.Exec; some -> supervise the child.
func (r *Resolved) HasCleanup() bool { return r != nil && len(r.cleanups) > 0 }

// HasPostSession reports whether any provider registered a session-end hook.
// The launcher ORs it with HasCleanup: a hook but no cleanup still needs the
// supervised path.
func (r *Resolved) HasPostSession() bool { return r != nil && len(r.postSessions) > 0 }

// RunPostSession runs the session-end hooks in declaration order, joining errors
// with per-provider attribution. Idempotent and nil-safe. Failure is warn-only.
func (r *Resolved) RunPostSession(ctx context.Context, exit SessionExit) error {
	if r == nil {
		return nil
	}
	var errs []error
	for _, ps := range r.postSessions {
		if err := ps.fn(ctx, exit); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ps.provider, err))
		}
	}
	r.postSessions = nil
	return errors.Join(errs...)
}

func mountDst(m sandbox.Mount) string {
	if m.Dst != "" {
		return m.Dst
	}
	return m.Src
}

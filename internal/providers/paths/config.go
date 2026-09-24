package paths

import (
	"fmt"

	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/pathutil"
)

// Config grants extra filesystem access on top of the built-in system view
// (providers.paths), as rw/ro lists of host paths.
type Config struct {
	RW []string `yaml:"rw"`
	RO []string `yaml:"ro"`
}

// Validate checks providers.paths: every entry must be an absolute (or ~-prefixed)
// path and must not re-expose an always-blocked secret directory. floor arrives
// ~-expanded and cleaned.
func (c Config) Validate(floor []string) error {
	for _, p := range c.RW {
		if err := pathutil.RequireAbs("providers.paths.rw", p); err != nil {
			return err
		}
	}
	for _, p := range c.RO {
		if err := pathutil.RequireAbs("providers.paths.ro", p); err != nil {
			return err
		}
	}

	// A path grant must not re-expose an always-blocked secret directory. Granting
	// an ancestor is fine because the always-blocked path is re-masked. This check
	// is lexical; the symlink-resolving half lives in ValidateResolved.
	for _, floorDir := range floor {
		for _, m := range append(append([]string{}, c.RW...), c.RO...) {
			if pathutil.AtOrUnder(m, floorDir) {
				return fmt.Errorf("providers.paths: %q overlaps the always-blocked path %q and cannot be granted", m, floorDir)
			}
		}
	}
	return nil
}

// Warnings returns the advisory lints for providers.paths. A read-only entry at
// or under a read-write entry grants nothing: read-write wins where they overlap.
func (c Config) Warnings() []health.Check {
	var w []health.Check
	for _, ro := range c.RO {
		for _, rw := range c.RW {
			if pathutil.AtOrUnder(ro, rw) {
				w = append(w, health.Check{State: health.Warn, Label: "paths.ro", Value: fmt.Sprintf("%q is covered by %q", ro, rw),
					Reason: "read-write grants win where they overlap, so this grant has no effect"})
				break
			}
		}
	}
	return w
}

// ValidateResolved is the launcher-only, symlink-resolving half of the
// always-blocked overlap guard. It is deliberately not part of Validate: it
// reads host state, and Validate runs inside the hook on every tool call — that
// path must stay fast. Callers run this in addition to Validate, never instead
// of it. floor arrives ~-expanded and cleaned.
func (c Config) ValidateResolved(floor []string) error {
	resolvedFloor := make([]string, len(floor))
	for i, f := range floor {
		resolvedFloor[i] = pathutil.Resolve(f)
	}
	for _, m := range append(append([]string{}, c.RW...), c.RO...) {
		real := pathutil.Resolve(m)
		if real == m {
			continue // no symlink in play: Validate's lexical check already covered it
		}
		for i, floorDir := range floor {
			switch {
			case real == resolvedFloor[i]:
				return fmt.Errorf("providers.paths: %q resolves to the always-blocked path %q and cannot be granted", m, floorDir)
			case pathutil.AtOrUnder(real, resolvedFloor[i]):
				return fmt.Errorf("providers.paths: %q resolves to %q, which is inside the always-blocked path %q and cannot be granted", m, real, floorDir)
			case pathutil.Under(resolvedFloor[i], real):
				return fmt.Errorf("providers.paths: %q is a symlink to %q, which contains the always-blocked path %q — "+
					"the always-blocked mask cannot cover it under the link's name; grant %q directly instead", m, real, floorDir, real)
			}
		}
	}
	return nil
}

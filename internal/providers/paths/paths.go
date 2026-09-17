// Package paths implements the built-in paths provider: the launcher half of
// the extra host-path grants (providers.paths.rw / .ro).
package paths

import (
	"context"

	"github.com/go-corral/corral/internal/providers/spec"
)

type paths struct {
	rw []string
	ro []string
}

// New builds the paths provider from the config grants (already ~-expanded
// absolute paths).
func New(rw, ro []string) spec.Provider {
	return &paths{rw: rw, ro: ro}
}

func (p *paths) Name() string { return "paths" }

func (p *paths) Available(ctx context.Context) bool { return true }

// Mint is pure.
func (p *paths) Mint(ctx context.Context, _ spec.Session, dryRun bool) (*spec.Contribution, error) {
	var notes []string
	if len(p.rw) > 0 {
		notes = append(notes, "extra writable host paths granted by config: "+spec.SummarizeQuoted(p.rw))
	}
	if len(p.ro) > 0 {
		notes = append(notes, "extra read-only host paths granted by config: "+spec.SummarizeQuoted(p.ro))
	}
	// No Status row: the banner's read-only/read-write access rows already show
	// these exact grants.
	return &spec.Contribution{
		RWPaths:    p.rw,
		ROPaths:    p.ro,
		AgentNotes: notes,
	}, nil
}

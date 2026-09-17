// Package block implements the built-in block provider: the launcher half of the
// config deny lists. The always-blocked paths are not part of this provider —
// DefaultSpec bakes them into the spec before any provider runs.
package block

import (
	"context"

	"github.com/go-corral/corral/internal/providers/spec"
)

type block struct {
	dirs  []string
	files []string
}

// New builds the block provider from the config-added deny lists (already
// ~-expanded absolute paths).
func New(dirs, files []string) spec.Provider {
	return &block{dirs: dirs, files: files}
}

func (b *block) Name() string { return "block" }

func (b *block) Available(ctx context.Context) bool { return true }

// Mint is pure. It authors no Status row: the banner's blocked row already names
// these paths.
func (b *block) Mint(ctx context.Context, _ spec.Session, dryRun bool) (*spec.Contribution, error) {
	masked := append(append([]string{}, b.dirs...), b.files...)
	return &spec.Contribution{
		BlockedDirs:  b.dirs,
		BlockedFiles: b.files,
		AgentNotes:   []string{"config additionally masks these paths (reads fail, they are not merely empty): " + spec.SummarizeQuoted(masked)},
	}, nil
}

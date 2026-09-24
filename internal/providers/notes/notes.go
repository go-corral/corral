// Package notes implements the notes provider: lines added to the agent's session-start note
package notes

import (
	"context"

	"github.com/go-corral/corral/internal/providers/spec"
)

type notes struct {
	lines []string
}

// New builds the notes provider from its already-trimmed lines (Config.Lines).
func New(lines []string) spec.Provider {
	return &notes{lines: lines}
}

func (n *notes) Name() string { return "notes" }

func (n *notes) Available(ctx context.Context) bool { return true }

func (n *notes) Mint(ctx context.Context, _ spec.Session, dryRun bool) (*spec.Contribution, error) {
	return &spec.Contribution{AgentNotes: n.lines}, nil
}

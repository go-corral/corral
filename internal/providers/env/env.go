// Package env implements the built-in env provider: the launcher half of the
// config env policy (providers.env). The passthrough half is applied by
// DefaultSpec, not here — the base < passthrough < agent-env < sandbox-marker
// layering is load-bearing. This provider owns the config surface and reporting.
package env

import (
	"context"
	"strings"

	"github.com/go-corral/corral/internal/providers/spec"
)

type env struct {
	passthrough []string
	set         []spec.EnvEntry
}

// New builds the env provider from its config. The Set pairs convert to the
// contract's neutral spec.EnvEntry carrier here, preserving declaration order.
func New(cfg Config) spec.Provider {
	set := make([]spec.EnvEntry, len(cfg.Set))
	for i, e := range cfg.Set {
		set[i] = spec.EnvEntry{Name: e.Name, Value: e.Value}
	}
	return &env{passthrough: cfg.Passthrough, set: set}
}

func (e *env) Name() string { return "env" }

func (e *env) Available(ctx context.Context) bool { return true }

// Mint is pure. It authors no Status row.
func (e *env) Mint(ctx context.Context, _ spec.Session, dryRun bool) (*spec.Contribution, error) {
	c := &spec.Contribution{
		EnvSet: e.set,
	}
	if len(e.set) > 0 {
		names := make([]string, len(e.set))
		for i, s := range e.set {
			names[i] = s.Name
		}
		// Names only — a pinned value may be something the operator would not want
		// riding the model's context every turn.
		c.AgentNotes = []string{"config pins these env vars inside the sandbox (already set, do not export/override): " + strings.Join(names, ", ")}
	}
	return c, nil
}

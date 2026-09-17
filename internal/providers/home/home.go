// Package home implements the default-on private-$HOME provider.
package home

import (
	"context"
	"fmt"
	"os"

	"github.com/go-corral/corral/internal/providers/spec"
	"github.com/go-corral/corral/internal/sandbox"
)

// home gives the sandboxed session a sandbox-private home directory instead of
// the host's real home. Everything not allowlisted is absent — a tool that
// hardcodes ~/foo writes into the private home. Because dir is persistent,
// home-relative tool caches land inside it and survive across sessions.
//
// It deliberately does not emit a HOME env var: HOME is in the always-set base
// env, redirected by the launcher. Emitting HOME here would trip Apply's
// env-collision guard.
type home struct {
	dir string
}

// New builds the private-home provider rooted at the launcher-resolved dir.
func New(dir string) spec.Provider { return &home{dir: dir} }

func (h *home) Name() string { return "home" }

func (h *home) Available(ctx context.Context) bool { return true }

func (h *home) Mint(ctx context.Context, _ spec.Session, dryRun bool) (*spec.Contribution, error) {
	if !dryRun {
		if err := os.MkdirAll(h.dir, 0o700); err != nil {
			return nil, fmt.Errorf("home: create %s: %w", h.dir, err)
		}
	}
	return &spec.Contribution{
		Mounts:     []sandbox.Mount{{Src: h.dir}},
		AgentNotes: []string{"$HOME is a writable sandbox-private home, not the host home; files there persist across corral sessions."},
	}, nil
}

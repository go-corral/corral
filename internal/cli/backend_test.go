package cli

import (
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
)

// newBackend is the composition-root factory: it maps a resolved Kind to a concrete
// backend. Its Name() identifies which one was built; an unrecognized kind must still
// construct a non-nil backend (falls back to bwrap) so the launcher never panics.
func TestNewBackend(t *testing.T) {
	if b := newBackend(sandbox.KindBwrap, "bwrap", config.Sandbox{}); b.Name() != "bwrap" {
		t.Errorf("newBackend(bwrap).Name() = %q, want bwrap", b.Name())
	}
	if b := newBackend(sandbox.KindSeatbelt, "", config.Sandbox{}); b.Name() != "seatbelt" {
		t.Errorf("newBackend(seatbelt).Name() = %q, want seatbelt", b.Name())
	}
	if b := newBackend("unknown", "", config.Sandbox{}); b == nil || b.Name() != "bwrap" {
		t.Errorf("newBackend(unknown) should fall back to a non-nil bwrap backend, got %v", b)
	}
}

// setBackendNotes folds the resolved backend's AgentNotes into the reserved sandbox-env channel
// the in-sandbox session-start hook reads. Seatbelt contributes the /tmp/$TMPDIR note; bwrap
// contributes none and must leave the var unset (so the hook injects the base note alone).
func TestSetBackendNotes(t *testing.T) {
	seat := sandbox.SandboxSpec{}
	setBackendNotes(&seat, newBackend(sandbox.KindSeatbelt, "", config.Sandbox{}))
	if v := seat.SetEnv[sandbox.BackendNotesEnvVar]; !strings.Contains(v, "$TMPDIR") {
		t.Errorf("seatbelt notes should populate %s with the /tmp line, got %q", sandbox.BackendNotesEnvVar, v)
	}

	bw := sandbox.SandboxSpec{}
	setBackendNotes(&bw, newBackend(sandbox.KindBwrap, "bwrap", config.Sandbox{}))
	if _, ok := bw.SetEnv[sandbox.BackendNotesEnvVar]; ok {
		t.Errorf("bwrap contributes no notes; %s must stay unset", sandbox.BackendNotesEnvVar)
	}
}

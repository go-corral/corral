package cli

import (
	"strings"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sandbox/bwrap"
	"github.com/go-corral/corral/internal/sandbox/seatbelt"
)

// newBackend constructs the sandbox backend for kind. The cli is the composition
// root so the sandbox package imports no backend.
func newBackend(kind sandbox.Kind, bwrapPath string, sandboxCfg config.Sandbox) sandbox.Backend {
	switch kind {
	case sandbox.KindSeatbelt:
		return seatbelt.New("", sandboxCfg.Seatbelt)
	default:
		return bwrap.New(bwrapPath)
	}
}

// setBackendNotes folds backend.AgentNotes() into spec.SetEnv under
// sandbox.BackendNotesEnvVar for the session-start hook.
func setBackendNotes(spec *sandbox.SandboxSpec, backend sandbox.Backend) {
	notes := backend.AgentNotes()
	if len(notes) == 0 {
		return
	}
	if spec.SetEnv == nil {
		spec.SetEnv = map[string]string{}
	}
	spec.SetEnv[sandbox.BackendNotesEnvVar] = strings.Join(notes, "\n")
}

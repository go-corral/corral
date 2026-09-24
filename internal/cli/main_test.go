package cli

import (
	"os"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// TestMain clears the pins a dev sandbox (devving corral on corral) sets: the hook honors
// them first, so they would send test audit records to the real log and config dir.
func TestMain(m *testing.M) {
	_ = os.Unsetenv(sandbox.AuditPathEnvVar)
	_ = os.Unsetenv(sandbox.AgentEnvVar)
	os.Exit(m.Run())
}

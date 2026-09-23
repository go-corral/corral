package cli

import (
	"os"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// TestMain clears the pins a dev sandbox (devving corral on corral) sets: the hook honors
// them first, so they would send test audit records to the real log and config dir. It also
// pins a UTF-8 locale and clears NO_COLOR, so output tests see the Unicode form on any host.
func TestMain(m *testing.M) {
	_ = os.Unsetenv(sandbox.AuditPathEnvVar)
	_ = os.Unsetenv(sandbox.AgentEnvVar)
	_ = os.Setenv("LC_ALL", "C.UTF-8")
	_ = os.Unsetenv("NO_COLOR")
	os.Exit(m.Run())
}

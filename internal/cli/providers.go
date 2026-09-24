package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/hooks"
	"github.com/go-corral/corral/internal/providers/registry"
)

// resolveProviders is replaceable so tests can prove dry runs never reach side-effecting Mint.
var resolveProviders = providers.Resolve

// launchDeps assembles the registry's host-input carrier for a launch.
func launchDeps(cfg *config.Config, home string, host map[string]string, workDir string) registry.Deps {
	dir, _ := homeDir(cfg, home, host)
	return registry.Deps{Home: home, Host: host, WorkDir: workDir, HomeDir: dir}
}

// activeProviders returns enabled feature providers in registry order.
func activeProviders(cfg *config.Config, home string, host map[string]string, workDir string, present hooks.Presenter, log io.Writer) []providers.Active {
	d := launchDeps(cfg, home, host, workDir)
	d.SessionHookPresenter = present
	d.SessionHookLog = log
	return registry.Features(cfg, d)
}

// builtinProviders returns active built-ins in registry order.
func builtinProviders(cfg *config.Config, home string) []providers.Active {
	// Built-ins need only cfg + home; no host env or workdir.
	return registry.Builtins(cfg, registry.Deps{Home: home})
}

// knownProviders returns every host-probeable provider for doctor's availability probe.
func knownProviders(home string, host map[string]string) []providers.Provider {
	return registry.Known(registry.Deps{Home: home, Host: host})
}

// ProviderView is the config-level summary of one enabled provider for validate.
type ProviderView = registry.View

// enabledProviders summarizes which providers the merged config turns on. Derived from
// config alone (no host probing).
func enabledProviders(cfg *config.Config) []ProviderView {
	return registry.Views(cfg)
}

// newSession builds the per-launch provider session. ID is a short random token so
// out-of-process resources get a unique, GC-discoverable name.
func newSession(home, project string) providers.Session {
	return providers.Session{
		User:    filepath.Base(home),
		ID:      sessionID(),
		WorkDir: project,
	}
}

// sessionID returns a short unique launch identifier: the pid plus 4 random hex bytes.
// Concurrent launches always differ (distinct pids); the random suffix guards pid reuse.
func sessionID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to pid alone; uniqueness is best-effort.
		return fmt.Sprintf("%d", os.Getpid())
	}
	return fmt.Sprintf("%d-%s", os.Getpid(), hex.EncodeToString(b[:]))
}

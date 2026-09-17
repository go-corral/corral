package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
)

// config.Net == NetNone sets params.Net = NetNone.
func TestSpecParamsNetNone(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Net: config.NetNone,
	}
	host := map[string]string{}

	params := specParams(cfg, home, proj, host, "")

	// The sandbox package's NetNone must be set (it's an enum, not a string method)
	if params.Net != sandbox.NetNone {
		t.Errorf("specParams with Net=NetNone: got %v, want NetNone", params.Net)
	}
}

// config.Net != NetNone (or the zero value) sets params.Net = NetOpen.
func TestSpecParamsNetOpen(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Net: config.NetOpen, // or default (zero value)
	}
	host := map[string]string{}

	params := specParams(cfg, home, proj, host, "")

	// Default should be NetOpen
	if params.Net != sandbox.NetOpen {
		t.Errorf("specParams with Net=NetOpen (or default): got %v, want NetOpen", params.Net)
	}
}

// An enabled home provider sets SandboxHome to the private home.
func TestSpecParamsHomeProviderEnabled(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Providers.Home.Enabled = true
	// Path is empty, so it will use the default: the keyed home for the default agent's config dir.
	host := map[string]string{}
	privateHome, ok := homeDir(cfg, home, host)
	if !ok {
		t.Fatal("homeDir: provider unexpectedly disabled")
	}

	params := specParams(cfg, home, proj, host, "")

	// SandboxHome must be set to the private home
	if params.SandboxHome == "" {
		t.Errorf("specParams with home provider enabled: SandboxHome is empty, want private home")
	}
	if params.SandboxHome != privateHome {
		t.Errorf("specParams with home provider enabled: got %q, want %q", params.SandboxHome, privateHome)
	}
}

// A disabled home provider leaves SandboxHome empty.
func TestSpecParamsHomeProviderDisabled(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Providers.Home.Enabled = false

	host := map[string]string{}

	params := specParams(cfg, home, proj, host, "")

	// SandboxHome should be empty when home provider is disabled
	if params.SandboxHome != "" {
		t.Errorf("specParams with home provider disabled: SandboxHome = %q, want empty", params.SandboxHome)
	}
}

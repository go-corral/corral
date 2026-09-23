package cli

import (
	"testing"

	"github.com/go-corral/corral/internal/config"
)

// Provider declaration order determines collision handling and LIFO cleanup.
func TestActiveProvidersDeclarationOrder(t *testing.T) {
	cfg := &config.Config{}
	cfg.Providers.Docker.Enabled = true
	cfg.Providers.SSH.Enabled = true
	cfg.Providers.Home.Enabled = true
	cfg.Providers.Kubernetes.Enabled = true
	cfg.Providers.Gitlab.Enabled = true

	got := activeProviders(cfg, "/home/u", map[string]string{
		"SSH_AUTH_SOCK": "/run/agent.sock",
		"GITLAB_TOKEN":  "glpat-x",
	}, "", nil, nil)
	want := []string{"docker", "ssh", "home", "kubernetes", "gitlab"}
	if len(got) != len(want) {
		t.Fatalf("expected %d active providers, got %d", len(want), len(got))
	}
	for i, name := range want {
		if got[i].Provider.Name() != name {
			t.Errorf("provider[%d] = %q, want %q (must mirror config.Providers field order)",
				i, got[i].Provider.Name(), name)
		}
	}
}

func TestActiveProvidersOnlyEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Providers.SSH.Enabled = true // docker disabled
	got := activeProviders(cfg, "/home/u", map[string]string{"SSH_AUTH_SOCK": "/run/agent.sock"}, "", nil, nil)
	if len(got) != 1 || got[0].Provider.Name() != "ssh" {
		t.Errorf("expected only ssh, got %v", got)
	}
}

package cli

import (
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers/kubernetes"
)

// The RBAC write-access lint itself lives on kubernetes.Config.Warnings (tested in
// that package); this pins the wiring — sessionWarnings must surface the provider-
// owned kubernetes warnings in the shared banner/validate advisory set.
func TestSessionWarningsSurfaceKubernetesLint(t *testing.T) {
	cfg := &config.Config{}
	cfg.Providers.Kubernetes.Enabled = true
	cfg.Providers.Kubernetes.Permissions = []kubernetes.Permission{{ClusterWide: true, ClusterRole: "edit"}}
	if w := strings.Join(sessionWarnings(cfg, nil), "\n"); !strings.Contains(w, `bound role "edit"`) {
		t.Errorf("sessionWarnings must include the kubernetes RBAC lint, got %q", w)
	}
}

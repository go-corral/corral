package config

import "testing"

func TestKubernetesReadOnlyRolesParse(t *testing.T) {
	cfg, _, err := loadFrom(t, "", "", "providers:\n  kubernetes:\n    enabled: true\n    readOnlyRoles: [view-all, monitor]\n", "")
	if err != nil {
		t.Fatalf("readOnlyRoles must parse: %v", err)
	}
	if len(cfg.Providers.Kubernetes.ReadOnlyRoles) != 2 {
		t.Errorf("readOnlyRoles not parsed: %v", cfg.Providers.Kubernetes.ReadOnlyRoles)
	}
}

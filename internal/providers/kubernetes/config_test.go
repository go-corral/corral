package kubernetes

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-corral/corral/internal/health"
)

func TestKubernetesPermissionValidationMatrix(t *testing.T) {
	sel := &LabelSelector{MatchLabels: map[string]string{"a": "b"}}
	for _, tc := range []struct {
		name string
		perm Permission
		ok   bool
	}{
		{"clusterWide+clusterRole", Permission{ClusterWide: true, ClusterRole: "view"}, true},
		{"selector+role", Permission{NamespaceSelector: sel, Role: "r"}, true},
		{"selector+clusterRole", Permission{NamespaceSelector: sel, ClusterRole: "edit"}, true},
		{"clusterWide+role (invalid)", Permission{ClusterWide: true, Role: "r"}, false},
		{"no scope", Permission{ClusterRole: "view"}, false},
		{"both scopes", Permission{ClusterWide: true, NamespaceSelector: sel, ClusterRole: "view"}, false},
		{"no role", Permission{ClusterWide: true}, false},
		{"both roles", Permission{ClusterWide: true, ClusterRole: "view", Role: "r"}, false},
	} {
		err := tc.perm.validate()
		if tc.ok && err != nil {
			t.Errorf("%s: should be valid, got %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: should be invalid", tc.name)
		}
	}
}

// --- mode: managed (default) | preProvisioned ---

func TestKubernetesEffectiveMode(t *testing.T) {
	for in, want := range map[string]string{
		"":                 ModeManaged, // absent from defaultsYAML on purpose
		ModeManaged:        ModeManaged,
		ModePreProvisioned: ModePreProvisioned,
	} {
		if got := (Config{Mode: in}).EffectiveMode(); got != want {
			t.Errorf("Config{Mode: %q}.EffectiveMode() = %q, want %q", in, got, want)
		}
	}
}

// The namespace default lives in code, not in defaultsYAML — that is what lets
// preProvisioned mode reject a genuinely unset serviceAccountNamespace.
func TestKubernetesEffectiveServiceAccountNamespace(t *testing.T) {
	if got := (Config{}).EffectiveServiceAccountNamespace(); got != "corral" {
		t.Errorf("unset serviceAccountNamespace must default to corral, got %q", got)
	}
	if got := (Config{ServiceAccountNamespace: "corral-team-a"}).EffectiveServiceAccountNamespace(); got != "corral-team-a" {
		t.Errorf("explicit serviceAccountNamespace must win, got %q", got)
	}
}

// Validate is strict and mode-aware, and (like tokenLifetime) runs even when the provider
// is disabled — a malformed block is caught before it is switched on.
func TestKubernetesModeValidation(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string // substring of the expected error; "" = must validate
	}{
		{"empty mode == managed", Config{}, ""},
		{"managed", Config{Mode: ModeManaged}, ""},
		{"managed keeps the namespace default", Config{Mode: ModeManaged, Permissions: []Permission{{ClusterWide: true, ClusterRole: "view"}}}, ""},
		{"preProvisioned with explicit namespace", Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a"}, ""},
		{"preProvisioned needs an explicit namespace", Config{Mode: ModePreProvisioned}, "serviceAccountNamespace is required"},
		{"preProvisioned forbids permissions", Config{
			Mode:                    ModePreProvisioned,
			ServiceAccountNamespace: "corral-team-a",
			Permissions:             []Permission{{ClusterWide: true, ClusterRole: "view"}},
		}, "does not manage RBAC"},
		{"unknown mode", Config{Mode: "adhoc"}, "is not valid"},
		// Values are case-sensitive lowerCamelCase, like every other config value.
		{"wrong case", Config{Mode: "preprovisioned", ServiceAccountNamespace: "corral-team-a"}, "is not valid"},
		{"disabled still validates", Config{Enabled: false, Mode: "adhoc"}, "is not valid"},
	} {
		err := tc.cfg.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: should validate, got %v", tc.name, err)
		case tc.want != "" && err == nil:
			t.Errorf("%s: should be rejected", tc.name)
		case tc.want != "" && err != nil && !strings.Contains(err.Error(), tc.want):
			t.Errorf("%s: error should mention %q, got %v", tc.name, tc.want, err)
		}
	}
}

// preProvisioned mode binds nothing, so the role lint has nothing to judge — not even the
// in-code default permission (which Mint never consults there either). The Permissions here
// could not survive Validate; they prove the skip is unconditional.
func TestWarningsPreProvisionedSkipsRoleLint(t *testing.T) {
	cfg := Config{
		Enabled:                 true,
		Mode:                    ModePreProvisioned,
		ServiceAccountNamespace: "corral-team-a",
		Permissions:             []Permission{{ClusterWide: true, ClusterRole: "cluster-admin"}},
	}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("preProvisioned mode must not lint roles corral does not bind, got %v", w)
	}
}

// Grants is the `corral validate` intent line — it must not claim corral manages RBAC in a
// mode where the cluster admin does.
func TestKubernetesGrantsModeAware(t *testing.T) {
	if g := (Config{}).Grants(); !strings.Contains(g, "RBAC") || strings.Contains(g, "pre-provisioned") {
		t.Errorf("managed Grants should describe corral-managed RBAC, got %q", g)
	}
	g := Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a"}.Grants()
	if !strings.Contains(g, "pre-provisioned") || !strings.Contains(g, "cluster admin") {
		t.Errorf("preProvisioned Grants should name the pre-provisioned namespace and the admin, got %q", g)
	}
}

// The read-only role set always contains the built-in `view`, and configured roles union
// with it (so adding a custom role never drops `view`).
func TestEffectiveReadOnlyRoles(t *testing.T) {
	ro := Config{}.EffectiveReadOnlyRoles()
	if !ro["view"] || !ro["infra-view"] || len(ro) != 2 {
		t.Errorf("default read-only roles must be exactly {view, infra-view}, got %v", ro)
	}
	ro = Config{ReadOnlyRoles: []string{"view-all", "view"}}.EffectiveReadOnlyRoles()
	if !ro["view"] || !ro["view-all"] {
		t.Errorf("configured roles must union with view, got %v", ro)
	}
}

// --- Warnings: the RBAC write-access lint ---

func warnContains(ws []health.Check, role string) bool {
	want := health.Check{State: health.Warn, Label: "kubernetes", Value: `role "` + role + `" is not a known read-only role`,
		Reason: "confirm it grants no write or delete access, or add it to providers.kubernetes.readOnlyRoles"}
	return slices.Contains(ws, want)
}

func warnCfg(perms []Permission, readOnly []string) Config {
	return Config{Enabled: true, Permissions: perms, ReadOnlyRoles: readOnly}
}

// A bound role that is not known-read-only warns (write access needs explicit approval).
func TestWarningsWriteRole(t *testing.T) {
	cfg := warnCfg([]Permission{{ClusterWide: true, ClusterRole: "edit"}}, nil)
	if w := cfg.Warnings(); !warnContains(w, "edit") {
		t.Errorf("expected a warning for the write-capable role 'edit', got %v", w)
	}
}

// The default read-only `view` bind is silent.
func TestWarningsViewSilent(t *testing.T) {
	cfg := warnCfg([]Permission{{ClusterWide: true, ClusterRole: "view"}}, nil)
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("the read-only 'view' role must not warn, got %v", w)
	}
}

// A custom role listed in readOnlyRoles is suppressed (and `view` is still implied).
func TestWarningsCustomReadOnly(t *testing.T) {
	cfg := warnCfg([]Permission{
		{ClusterWide: true, ClusterRole: "view-all"},
		{ClusterWide: true, ClusterRole: "view"},
	}, []string{"view-all"})
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("a configured read-only role must be suppressed, got %v", w)
	}
}

// A namespaced Role (not just clusterRole) is also checked.
func TestWarningsNamespacedRole(t *testing.T) {
	cfg := warnCfg([]Permission{
		{NamespaceSelector: &LabelSelector{}, Role: "admin"},
	}, nil)
	if w := cfg.Warnings(); !warnContains(w, "admin") {
		t.Errorf("a namespaced write Role must warn, got %v", w)
	}
}

// A disabled provider warns about nothing.
func TestWarningsDisabled(t *testing.T) {
	cfg := warnCfg([]Permission{{ClusterWide: true, ClusterRole: "cluster-admin"}}, nil)
	cfg.Enabled = false
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("a disabled kubernetes provider must not warn, got %v", w)
	}
}

func TestKubernetesTokenLifetimeDefault(t *testing.T) {
	k := Config{}
	if got := k.EffectiveTokenLifetime(); got != 8*time.Hour {
		t.Errorf("Config{}.EffectiveTokenLifetime() = %v, want 8h", got)
	}
}

func TestKubernetesTokenLifetimeExplicit(t *testing.T) {
	k := Config{TokenLifetime: "1h"}
	if got := k.EffectiveTokenLifetime(); got != 1*time.Hour {
		t.Errorf("Config{TokenLifetime: '1h'}.EffectiveTokenLifetime() = %v, want 1h", got)
	}
}

func TestKubernetesTokenLifetimeVarious(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want time.Duration
	}{
		{"", 8 * time.Hour},
		{"1h", 1 * time.Hour},
		{"2h30m", 2*time.Hour + 30*time.Minute},
		{"24h", 24 * time.Hour},
		{"90m", 90 * time.Minute},
	} {
		k := Config{TokenLifetime: tc.val}
		if got := k.EffectiveTokenLifetime(); got != tc.want {
			t.Errorf("TokenLifetime: %q = %v, want %v", tc.val, got, tc.want)
		}
	}
}

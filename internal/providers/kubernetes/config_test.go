package kubernetes

import (
	"path/filepath"
	"reflect"
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

// --- clusters: inherit-or-replace ---

func TestEffectiveClusters(t *testing.T) {
	top := []Permission{{NamespaceSelector: &LabelSelector{MatchLabels: map[string]string{"team": "platform"}}, ClusterRole: "edit"}}
	own := []Permission{{ClusterWide: true, ClusterRole: "view"}}
	for _, tc := range []struct {
		name string
		cfg  Config
		want []ResolvedCluster
	}{
		{"no clusters gives current", Config{Enabled: true, Mode: ModeManaged, Permissions: top},
			[]ResolvedCluster{{Key: ImplicitCluster, Implicit: true, Default: true, Config: Config{Enabled: true, Mode: ModeManaged, Permissions: top}}}},
		{"cluster permissions replace the top-level list", Config{Permissions: top, Clusters: map[string]Cluster{"prod": {Permissions: own}}},
			[]ResolvedCluster{{Key: "prod", Config: Config{Permissions: own}}}},
		{"cluster without permissions inherits them", Config{Permissions: top, Mode: ModeManaged, Clusters: map[string]Cluster{"staging": {Default: true}}},
			[]ResolvedCluster{{Key: "staging", Default: true, Config: Config{Permissions: top, Mode: ModeManaged}}}},
		{"enabled and optional inherit when unset", Config{Enabled: true, Optional: true, Clusters: map[string]Cluster{"a": {}}},
			[]ResolvedCluster{{Key: "a", Config: Config{Enabled: true, Optional: true}}}},
		{"enabled and optional override when set", Config{Enabled: true, Optional: false, Clusters: map[string]Cluster{"a": {Enabled: new(false), Optional: new(true)}}},
			[]ResolvedCluster{{Key: "a", Config: Config{Enabled: false, Optional: true}}}},
		{"a declared cluster is the default only when it sets default", Config{Clusters: map[string]Cluster{"a": {Kubeconfig: Kubeconfig{Path: "/k", Context: "c"}, Mode: ModePreProvisioned, ServiceAccountNamespace: "ns"}}},
			[]ResolvedCluster{{Key: "a", Kubeconfig: Kubeconfig{Path: "/k", Context: "c"}, Config: Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "ns"}}}},
		{"sorted by key", Config{Clusters: map[string]Cluster{"zeta": {}, "alpha": {}, "mid": {}}},
			[]ResolvedCluster{{Key: "alpha"}, {Key: "mid"}, {Key: "zeta"}}},
	} {
		if got := tc.cfg.EffectiveClusters(); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: EffectiveClusters() = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestKubeconfigResolvedPath(t *testing.T) {
	for in, want := range map[string]string{
		"":             "",
		"kube/dev.yml": "/src/app/kube/dev.yml",
		"/etc/../k":    "/k",
	} {
		if got := (Kubeconfig{Path: in}).ResolvedPath("/src/app"); got != want {
			t.Errorf("ResolvedPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClustersValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string // exact error; "" = must validate
	}{
		{"inherited preProvisioned mode with cluster permissions",
			Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a", Clusters: map[string]Cluster{"prod": {Permissions: []Permission{{ClusterWide: true, ClusterRole: "view"}}}}},
			"providers.kubernetes.clusters.prod.permissions: not allowed in mode preProvisioned — corral does not manage RBAC in this mode (a cluster admin binds the target-namespace roles to group system:serviceaccounts:<serviceAccountNamespace>); remove the list or switch to mode managed"},
		{"inherited preProvisioned mode and namespace", Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a", Clusters: map[string]Cluster{"prod": {}}}, ""},
		{"cluster overrides the top-level mode", Config{Mode: ModePreProvisioned, Clusters: map[string]Cluster{"prod": {Mode: ModeManaged}}}, ""},
		{"cluster permission names the cluster key",
			Config{Clusters: map[string]Cluster{"prod": {Permissions: []Permission{{ClusterRole: "view"}}}}},
			"providers.kubernetes.clusters.prod.permissions[0]: set either clusterWide: true or namespaceSelector"},
		{"cluster tokenLifetime names the cluster key", Config{Clusters: map[string]Cluster{"prod": {TokenLifetime: "48h"}}},
			`providers.kubernetes.clusters.prod.tokenLifetime: "48h" exceeds the 24h maximum`},
		{"same kubeconfig source twice",
			Config{Clusters: map[string]Cluster{"a": {Kubeconfig: Kubeconfig{Path: "/home/u/.kube/config"}}, "b": {Kubeconfig: Kubeconfig{Path: "/home/u/.kube/./config"}}}},
			"providers.kubernetes.clusters: a and b use the same kubeconfig.path and kubeconfig.context; set a different source for one of them"},
		{"same path, other context", Config{Clusters: map[string]Cluster{"a": {Kubeconfig: Kubeconfig{Path: "/k"}}, "b": {Kubeconfig: Kubeconfig{Path: "/k", Context: "dev"}}}}, ""},
		{"two defaults", Config{Clusters: map[string]Cluster{"staging": {Default: true, Kubeconfig: Kubeconfig{Context: "s"}}, "prod": {Default: true, Kubeconfig: Kubeconfig{Context: "p"}}}},
			"providers.kubernetes.clusters: more than one cluster sets default: true (prod, staging); set it on at most one"},
		{"disabled cluster still counts as a default", Config{Clusters: map[string]Cluster{
			"prod":    {Enabled: new(false), Default: true, Kubeconfig: Kubeconfig{Context: "p"}},
			"staging": {Enabled: new(true), Default: true, Kubeconfig: Kubeconfig{Context: "s"}},
		}}, "providers.kubernetes.clusters: more than one cluster sets default: true (prod, staging); set it on at most one"},
	} {
		err := tc.cfg.Validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: should validate, got %v", tc.name, err)
		case tc.want != "" && (err == nil || err.Error() != tc.want):
			t.Errorf("%s: error = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestWarningsNameTheCluster(t *testing.T) {
	cfg := Config{Enabled: true, Clusters: map[string]Cluster{
		"prod":    {},
		"staging": {Permissions: []Permission{{ClusterWide: true, ClusterRole: "edit"}}},
	}}
	want := []health.Check{{State: health.Warn, Label: "kubernetes/staging", Value: `role "edit" is not a known read-only role`,
		Reason: "confirm it grants no write or delete access, or add it to providers.kubernetes.clusters.staging.readOnlyRoles"}}
	if w := cfg.Warnings(); !slices.Equal(w, want) {
		t.Errorf("Warnings() = %+v, want %+v", w, want)
	}
}

func TestWarningsSkipDisabledCluster(t *testing.T) {
	cfg := Config{Enabled: true, Clusters: map[string]Cluster{
		"staging": {Enabled: new(false), Permissions: []Permission{{ClusterWide: true, ClusterRole: "edit"}}},
	}}
	if w := cfg.Warnings(); len(w) != 0 {
		t.Errorf("a disabled cluster must not warn, got %v", w)
	}
}

func TestGrantsDescribeClusters(t *testing.T) {
	cfg := Config{Enabled: true, Clusters: map[string]Cluster{
		"prod":    {},
		"staging": {Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a"},
		"old":     {Enabled: new(false)},
	}}
	want := "per-session ServiceAccount + a scoped kubeconfig token on 2 clusters (prod: managed, staging: preProvisioned)"
	if g := cfg.Grants(); g != want {
		t.Errorf("Grants() = %q, want %q", g, want)
	}
}

// Files returns the resolved Path, or the absolute $KUBECONFIG files without empty entries.
func TestKubeconfigFiles(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	list := string(filepath.ListSeparator)
	t.Setenv("KUBECONFIG", "a.yml"+list+list+"/abs/b.yml"+list)
	if got, want := (Kubeconfig{}).Files(""), []string{filepath.Join(dir, "a.yml"), "/abs/b.yml"}; !slices.Equal(got, want) {
		t.Errorf("Files() = %v, want %v", got, want)
	}
	if got, want := (Kubeconfig{Path: "kube/dev.yml"}).Files("/work"), []string{"/work/kube/dev.yml"}; !slices.Equal(got, want) {
		t.Errorf("Files(/work) = %v, want %v", got, want)
	}
}

func TestClusterEnabledAndOptional(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		cfg                     Config
		wantEnabled, wantOption bool
	}{
		{"implicit disabled", Config{}, false, true},
		{"implicit enabled", Config{Enabled: true}, true, false},
		{"profile enables one cluster", Config{Clusters: map[string]Cluster{"prod": {}, "staging": {Enabled: new(true)}}}, true, false},
		{"all clusters disabled", Config{Enabled: true, Clusters: map[string]Cluster{"prod": {Enabled: new(false)}}}, false, true},
		{"enabled clusters optional", Config{Enabled: true, Clusters: map[string]Cluster{"a": {Optional: new(true)}, "b": {Enabled: new(false)}}}, true, true},
		{"one enabled cluster required", Config{Enabled: true, Optional: true, Clusters: map[string]Cluster{"a": {}, "b": {Optional: new(false)}}}, true, false},
	} {
		if got := tc.cfg.AnyClusterEnabled(); got != tc.wantEnabled {
			t.Errorf("%s: AnyClusterEnabled = %v, want %v", tc.name, got, tc.wantEnabled)
		}
		if got := tc.cfg.EnabledClustersOptional(); got != tc.wantOption {
			t.Errorf("%s: EnabledClustersOptional = %v, want %v", tc.name, got, tc.wantOption)
		}
	}
}

func TestGCClusters(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want []string
	}{
		{"implicit disabled", Config{}, nil},
		{"implicit enabled", Config{Enabled: true}, []string{ImplicitCluster}},
		{"declared, enabled or not", Config{Clusters: map[string]Cluster{"prod": {}, "staging": {Enabled: new(true)}}}, []string{"prod", "staging"}},
	} {
		var got []string
		for _, c := range tc.cfg.GCClusters() {
			got = append(got, c.Key)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: GCClusters = %v, want %v", tc.name, got, tc.want)
		}
	}
}

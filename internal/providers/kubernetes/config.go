package kubernetes

import (
	"cmp"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"k8s.io/client-go/tools/clientcmd"

	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/providers/hooks"
)

// Config configures the kubernetes credential-minter: corral provisions a per-session
// ServiceAccount, binds it per the permissions list, mints a short-lived token, and binds a
// minimal kubeconfig into the sandbox.
type Config struct {
	Enabled  bool `yaml:"enabled"`
	Optional bool `yaml:"optional"`
	// Mode selects who owns the session identity's RBAC. ModeManaged (default) creates bindings;
	// ModePreProvisioned creates only the identity in an admin-prepared namespace.
	Mode string `yaml:"mode"`
	// TokenLifetime is the requested SA-token duration; default 8h, max 24h. The cluster may cap
	// it lower; the provider honors the server's returned expiry.
	TokenLifetime string `yaml:"tokenLifetime"`
	// As impersonates this user for provisioning calls only (kubectl --as); the minted SA token
	// is independent.
	As string `yaml:"as"`
	// ServiceAccountNamespace holds the per-session SA. Managed mode defaults to corral and
	// creates it if missing. PreProvisioned mode requires an explicit existing namespace.
	ServiceAccountNamespace string `yaml:"serviceAccountNamespace"`
	// Permissions are the RBAC grants for the session SA. Empty => one cluster-wide bind to the
	// built-in `view` ClusterRole. The default stays in code because YAML lists merge additively.
	// PreProvisioned mode rejects any entry.
	Permissions []Permission `yaml:"permissions"`
	// ReadOnlyRoles suppresses the write-access warning for operator-verified roles, in addition
	// to the built-in `view` and `infra-view` ClusterRoles.
	ReadOnlyRoles []string `yaml:"readOnlyRoles"`
	// Clusters replaces the implicit current-context cluster when it declares at least one
	// cluster. The fields above are defaults for each cluster.
	Clusters map[string]Cluster `yaml:"clusters"`
}

// Cluster is one entry of Config.Clusters. A set value replaces the top-level value; an empty
// string or list, or a nil Enabled/Optional, inherits it. Default is not inherited.
type Cluster struct {
	Enabled                 *bool        `yaml:"enabled"`
	Optional                *bool        `yaml:"optional"`
	Default                 bool         `yaml:"default"`
	Kubeconfig              Kubeconfig   `yaml:"kubeconfig"`
	Mode                    string       `yaml:"mode"`
	TokenLifetime           string       `yaml:"tokenLifetime"`
	As                      string       `yaml:"as"`
	ServiceAccountNamespace string       `yaml:"serviceAccountNamespace"`
	Permissions             []Permission `yaml:"permissions"`
	ReadOnlyRoles           []string     `yaml:"readOnlyRoles"`
}

// Kubeconfig selects a cluster's host kubeconfig. An empty Path uses the default loading rules
// ($KUBECONFIG, then ~/.kube/config); an empty Context uses that kubeconfig's current context.
type Kubeconfig struct {
	Path    string `yaml:"path"`
	Context string `yaml:"context"`
}

// ResolvedPath anchors a relative Path at dir, the current directory of the corral command. An
// empty Path stays empty.
func (k Kubeconfig) ResolvedPath(dir string) string {
	if k.Path == "" {
		return ""
	}
	return hooks.ResolveExec(k.Path, dir)
}

// Files returns the kubeconfig files the cluster loads: the resolved Path, or for an empty Path
// the absolute files of the default loading rules ($KUBECONFIG, then ~/.kube/config). client-go
// skips an empty $KUBECONFIG entry, so Files does too.
func (k Kubeconfig) Files(dir string) []string {
	if k.Path != "" {
		return []string{k.ResolvedPath(dir)}
	}
	var files []string
	for _, f := range clientcmd.NewDefaultClientConfigLoadingRules().GetLoadingPrecedence() {
		if f == "" {
			continue
		}
		if abs, err := filepath.Abs(f); err == nil {
			f = abs
		}
		files = append(files, f)
	}
	return files
}

// ImplicitCluster is the key of the cluster that EffectiveClusters returns when Clusters is empty.
const ImplicitCluster = "current"

// ResolvedCluster is one cluster with the top-level defaults applied.
type ResolvedCluster struct {
	Key string
	// Implicit marks the ImplicitCluster built from the top-level fields.
	Implicit   bool
	Kubeconfig Kubeconfig
	Default    bool
	// Config holds the effective settings, including Enabled and Optional. Its Clusters is nil.
	Config Config
}

// prefix is the config key that errors and warnings name for this cluster.
func (c ResolvedCluster) prefix() string {
	if c.Implicit {
		return "providers.kubernetes"
	}
	return "providers.kubernetes.clusters." + c.Key
}

// EffectiveClusters returns the declared clusters sorted by key, or the ImplicitCluster when
// none is declared.
func (k Config) EffectiveClusters() []ResolvedCluster {
	base := k
	base.Clusters = nil
	if len(k.Clusters) == 0 {
		return []ResolvedCluster{{Key: ImplicitCluster, Implicit: true, Default: true, Config: base}}
	}
	out := make([]ResolvedCluster, 0, len(k.Clusters))
	for _, key := range slices.Sorted(maps.Keys(k.Clusters)) {
		c := k.Clusters[key]
		eff := base
		if c.Enabled != nil {
			eff.Enabled = *c.Enabled
		}
		if c.Optional != nil {
			eff.Optional = *c.Optional
		}
		eff.Mode = cmp.Or(c.Mode, base.Mode)
		eff.TokenLifetime = cmp.Or(c.TokenLifetime, base.TokenLifetime)
		eff.As = cmp.Or(c.As, base.As)
		eff.ServiceAccountNamespace = cmp.Or(c.ServiceAccountNamespace, base.ServiceAccountNamespace)
		if len(c.Permissions) > 0 {
			eff.Permissions = c.Permissions
		}
		if len(c.ReadOnlyRoles) > 0 {
			eff.ReadOnlyRoles = c.ReadOnlyRoles
		}
		out = append(out, ResolvedCluster{Key: key, Kubeconfig: c.Kubeconfig, Default: c.Default, Config: eff})
	}
	return out
}

// Permission is one RBAC grant. Exactly one scope (clusterWide XOR namespaceSelector) and exactly
// one role (clusterRole XOR role). clusterWide requires a ClusterRole.
type Permission struct {
	ClusterWide       bool           `yaml:"clusterWide"`
	NamespaceSelector *LabelSelector `yaml:"namespaceSelector"`
	ClusterRole       string         `yaml:"clusterRole"`
	Role              string         `yaml:"role"`
}

// LabelSelector is the YAML form of a Kubernetes label selector (yaml.v3 ignores
// metav1.LabelSelector's JSON tags). An empty selector matches all namespaces.
type LabelSelector struct {
	MatchLabels      map[string]string          `yaml:"matchLabels"`
	MatchExpressions []LabelSelectorRequirement `yaml:"matchExpressions"`
}

type LabelSelectorRequirement struct {
	Key      string   `yaml:"key"`
	Operator string   `yaml:"operator"` // In | NotIn | Exists | DoesNotExist
	Values   []string `yaml:"values"`
}

const MaxTokenLifetime = 24 * time.Hour

const (
	ModeManaged        = "managed"
	ModePreProvisioned = "preProvisioned"
)

// defaultServiceAccountNamespace is the managed-mode fallback. It lives here rather than in
// defaultsYAML so preProvisioned mode can tell "unset" from "set to corral".
const defaultServiceAccountNamespace = "corral"

func (k Config) EffectiveMode() string {
	if k.Mode == "" {
		return ModeManaged
	}
	return k.Mode
}

func (k Config) EffectiveServiceAccountNamespace() string {
	if k.ServiceAccountNamespace == "" {
		return defaultServiceAccountNamespace
	}
	return k.ServiceAccountNamespace
}

func (k Config) Grants() string {
	clusters := k.EffectiveClusters()
	if clusters[0].Implicit {
		return clusters[0].Config.grants()
	}
	var parts []string
	for _, c := range clusters {
		if c.Config.Enabled {
			parts = append(parts, c.Key+": "+c.Config.EffectiveMode())
		}
	}
	noun := "clusters"
	if len(parts) == 1 {
		noun = "cluster"
	}
	return fmt.Sprintf("per-session ServiceAccount + a scoped kubeconfig token on %d %s (%s)", len(parts), noun, strings.Join(parts, ", "))
}

func (k Config) grants() string {
	if k.EffectiveMode() == ModePreProvisioned {
		return "per-session ServiceAccount in a pre-provisioned namespace + a scoped kubeconfig token (RBAC owned by the cluster admin)"
	}
	return "per-session ServiceAccount + RBAC + a scoped kubeconfig token"
}

func (k Config) EffectivePermissions() []Permission {
	if len(k.Permissions) > 0 {
		return k.Permissions
	}
	return []Permission{{ClusterWide: true, ClusterRole: "view"}}
}

// EffectiveReadOnlyRoles returns the set of role names treated as read-only: the built-in `view`
// and `infra-view` ClusterRoles always, unioned with operator-configured ReadOnlyRoles. Union (not
// replace) so adding a custom role never drops the built-ins and starts spurious warnings.
func (k Config) EffectiveReadOnlyRoles() map[string]bool {
	out := map[string]bool{"view": true, "infra-view": true}
	for _, r := range k.ReadOnlyRoles {
		if r != "" {
			out[r] = true
		}
	}
	return out
}

func (k Config) EffectiveTokenLifetime() time.Duration {
	if k.TokenLifetime == "" {
		return 8 * time.Hour
	}
	if d, err := time.ParseDuration(k.TokenLifetime); err == nil && d > 0 {
		return d
	}
	return 8 * time.Hour
}

// Warnings returns the advisory RBAC write-access lint, shared by the `run` startup banner and
// `corral validate`. Warn-and-allow: a write grant is legitimate when approved. preProvisioned
// mode binds no role (the grants are the cluster admin's), so there is nothing to lint.
func (k Config) Warnings() []health.Check {
	var w []health.Check
	for _, c := range k.EffectiveClusters() {
		if !c.Config.Enabled || c.Config.EffectiveMode() == ModePreProvisioned {
			continue
		}
		label := "kubernetes"
		if !c.Implicit {
			label += "/" + c.Key
		}
		readOnly := c.Config.EffectiveReadOnlyRoles()
		warned := map[string]bool{}
		for _, p := range c.Config.EffectivePermissions() {
			role := p.ClusterRole
			if role == "" {
				role = p.Role
			}
			if role == "" || readOnly[role] || warned[role] {
				continue
			}
			warned[role] = true
			w = append(w, health.Check{State: health.Warn, Label: label, Value: fmt.Sprintf("role %q is not a known read-only role", role),
				Reason: "confirm it grants no write or delete access, or add it to " + c.prefix() + ".readOnlyRoles"})
		}
	}
	return w
}

// Validate checks the structural rules that don't need a cluster. Runs even when disabled.
// Each error names the key the operator wrote: the top-level fields, each cluster's own fields,
// then the rules across fields on each cluster's effective settings.
func (k Config) Validate() error {
	if err := validateFields("providers.kubernetes", k.Mode, k.TokenLifetime, k.Permissions); err != nil {
		return err
	}
	keys := slices.Sorted(maps.Keys(k.Clusters))
	for _, key := range keys {
		c := k.Clusters[key]
		if err := validateFields("providers.kubernetes.clusters."+key, c.Mode, c.TokenLifetime, c.Permissions); err != nil {
			return err
		}
	}
	for _, c := range k.EffectiveClusters() {
		if err := c.Config.validateMode(c.prefix()); err != nil {
			return err
		}
	}

	var defaults []string
	type source struct{ path, context string }
	seen := map[source]string{}
	for _, key := range keys {
		c := k.Clusters[key]
		if c.Default {
			defaults = append(defaults, key)
		}
		// Relative paths share one anchor, so the cleaned path identifies the file.
		src := source{c.Kubeconfig.Path, c.Kubeconfig.Context}
		if src.path != "" {
			src.path = filepath.Clean(src.path)
		}
		if first, ok := seen[src]; ok {
			return fmt.Errorf("providers.kubernetes.clusters: %s and %s use the same kubeconfig.path and kubeconfig.context; set a different source for one of them", first, key)
		}
		seen[src] = key
	}
	if len(defaults) > 1 {
		return fmt.Errorf("providers.kubernetes.clusters: more than one cluster sets default: true (%s); set it on at most one", strings.Join(defaults, ", "))
	}
	return nil
}

func validateFields(prefix, mode, tokenLifetime string, perms []Permission) error {
	if tokenLifetime != "" {
		d, err := time.ParseDuration(tokenLifetime)
		switch {
		case err != nil:
			return fmt.Errorf("%s.tokenLifetime: %q is not a valid duration (e.g. 8h, 90m): %w", prefix, tokenLifetime, err)
		case d <= 0:
			return fmt.Errorf("%s.tokenLifetime: %q must be positive", prefix, tokenLifetime)
		case d > MaxTokenLifetime:
			return fmt.Errorf("%s.tokenLifetime: %q exceeds the 24h maximum", prefix, tokenLifetime)
		}
	}
	switch mode {
	case "", ModeManaged, ModePreProvisioned:
	default:
		return fmt.Errorf("%s.mode: %q is not valid (use %s or %s)", prefix, mode, ModeManaged, ModePreProvisioned)
	}
	for i, p := range perms {
		if err := p.validate(); err != nil {
			return fmt.Errorf("%s.permissions[%d]: %w", prefix, i, err)
		}
	}
	return nil
}

func (k Config) validateMode(prefix string) error {
	if k.EffectiveMode() != ModePreProvisioned {
		return nil
	}
	// corral manages no RBAC here (so a permissions list would be silently ignored), and the
	// pre-provisioned namespace is the grant (so it must be named, never defaulted).
	if len(k.Permissions) > 0 {
		return fmt.Errorf("%s.permissions: not allowed in mode %s — corral does not manage RBAC in this mode (a cluster admin binds the target-namespace roles to group system:serviceaccounts:<serviceAccountNamespace>); remove the list or switch to mode %s", prefix, ModePreProvisioned, ModeManaged)
	}
	if k.ServiceAccountNamespace == "" {
		return fmt.Errorf("%s.serviceAccountNamespace is required in mode %s: name the namespace a cluster admin pre-provisioned for corral (e.g. corral-team-a)", prefix, ModePreProvisioned)
	}
	return nil
}

func (p Permission) validate() error {
	hasNS := p.NamespaceSelector != nil
	switch {
	case p.ClusterWide && hasNS:
		return fmt.Errorf("clusterWide and namespaceSelector are mutually exclusive")
	case !p.ClusterWide && !hasNS:
		return fmt.Errorf("set either clusterWide: true or namespaceSelector")
	}
	hasCR, hasRole := p.ClusterRole != "", p.Role != ""
	if hasCR == hasRole {
		return fmt.Errorf("set exactly one of clusterRole or role")
	}
	if p.ClusterWide && !hasCR {
		return fmt.Errorf("clusterWide: true requires clusterRole (a ClusterRoleBinding cannot reference a namespaced Role)")
	}
	return nil
}

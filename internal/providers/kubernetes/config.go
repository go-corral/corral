package kubernetes

import (
	"fmt"
	"time"
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
func (k Config) Warnings() []string {
	if !k.Enabled || k.EffectiveMode() == ModePreProvisioned {
		return nil
	}
	readOnly := k.EffectiveReadOnlyRoles()
	warned := map[string]bool{}
	var w []string
	for _, p := range k.EffectivePermissions() {
		role := p.ClusterRole
		if role == "" {
			role = p.Role
		}
		if role == "" || readOnly[role] || warned[role] {
			continue
		}
		warned[role] = true
		w = append(w, fmt.Sprintf("kubernetes: bound role %q is not a known read-only role — confirm it grants no write/delete access (a write grant needs explicit approval), or add it to providers.kubernetes.readOnlyRoles to silence this", role))
	}
	return w
}

// Validate checks the structural rules that don't need a cluster. Runs even when disabled.
func (k Config) Validate() error {
	if k.TokenLifetime != "" {
		d, err := time.ParseDuration(k.TokenLifetime)
		switch {
		case err != nil:
			return fmt.Errorf("providers.kubernetes.tokenLifetime: %q is not a valid duration (e.g. 8h, 90m): %w", k.TokenLifetime, err)
		case d <= 0:
			return fmt.Errorf("providers.kubernetes.tokenLifetime: %q must be positive", k.TokenLifetime)
		case d > MaxTokenLifetime:
			return fmt.Errorf("providers.kubernetes.tokenLifetime: %q exceeds the 24h maximum", k.TokenLifetime)
		}
	}
	switch k.Mode {
	case "", ModeManaged:
	case ModePreProvisioned:
		// corral manages no RBAC here (so a permissions list would be silently ignored), and the
		// pre-provisioned namespace is the grant (so it must be named, never inherited).
		if len(k.Permissions) > 0 {
			return fmt.Errorf("providers.kubernetes.permissions: not allowed in mode %s — corral does not manage RBAC in this mode (a cluster admin binds the target-namespace roles to group system:serviceaccounts:<serviceAccountNamespace>); remove the list or switch to mode %s", ModePreProvisioned, ModeManaged)
		}
		if k.ServiceAccountNamespace == "" {
			return fmt.Errorf("providers.kubernetes.serviceAccountNamespace is required in mode %s: name the namespace a cluster admin pre-provisioned for corral (e.g. corral-team-a)", ModePreProvisioned)
		}
	default:
		return fmt.Errorf("providers.kubernetes.mode: %q is not valid (use %s or %s)", k.Mode, ModeManaged, ModePreProvisioned)
	}
	for i, p := range k.Permissions {
		if err := p.validate(); err != nil {
			return fmt.Errorf("providers.kubernetes.permissions[%d]: %w", i, err)
		}
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

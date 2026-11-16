// Package registry is the single, ordered enumeration of corral's feature
// providers. One table means a provider cannot be half-registered (parsing but
// silently never activating). The order is the canonical provider declaration
// order: contributions apply in this order, collisions are attributed to it, and
// cleanup unwinds its reverse. A drift-guard test pins it to the config.Providers
// struct-field order, after the config sections.
package registry

import (
	"io"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/docker"
	"github.com/go-corral/corral/internal/providers/gitlab"
	"github.com/go-corral/corral/internal/providers/home"
	"github.com/go-corral/corral/internal/providers/hooks"
	"github.com/go-corral/corral/internal/providers/kubernetes"
	"github.com/go-corral/corral/internal/providers/ssh"
)

// Deps carries the per-launch host inputs a provider constructor may need.
type Deps struct {
	Home    string
	Host    map[string]string
	WorkDir string
	// HomeDir is the resolved private-home directory ("" when the home provider is disabled).
	HomeDir string
	// ApprovedKubeconfigs maps a gated kubeconfig file to the hex SHA-256 the operator approved.
	// The kubernetes provider loads such a file only from bytes with that hash.
	ApprovedKubeconfigs map[string]string
	// SessionHookPresenter optionally renders preStart output in the launch UI.
	SessionHookPresenter hooks.Presenter
	// SessionHookLog receives the session-hooks provider's attribution lines.
	SessionHookLog io.Writer
}

// Registration describes one provider to every derived view. A nil optional func
// means "no".
type Registration struct {
	Name          string
	Enabled       func(cfg *config.Config) bool
	Optional      func(cfg *config.Config) bool
	Grants        func(cfg *config.Config) string
	FailurePolicy func(cfg *config.Config) string
	Warnings      func(cfg *config.Config) []health.Check
	Build         func(cfg *config.Config, d Deps) providers.Provider
	Probe         func(d Deps) providers.Provider
}

var registry = []Registration{
	{
		Name:          "hooks",
		Enabled:       func(c *config.Config) bool { return c.Providers.Hooks.Enabled() },
		Grants:        func(c *config.Config) string { return c.Providers.Hooks.Grants() },
		FailurePolicy: func(c *config.Config) string { return c.Providers.Hooks.FailurePolicy() },
		Build: func(c *config.Config, d Deps) providers.Provider {
			return hooks.New(c.Providers.Hooks, c.EffectiveAgent(), d.SessionHookPresenter, d.SessionHookLog)
		},
	},
	{
		Name:     "docker",
		Enabled:  func(c *config.Config) bool { return c.Providers.Docker.Enabled },
		Optional: func(c *config.Config) bool { return c.Providers.Docker.Optional },
		Grants:   func(c *config.Config) string { return c.Providers.Docker.Grants() },
		Warnings: func(c *config.Config) []health.Check { return c.Providers.Docker.Warnings() },
		Build: func(c *config.Config, d Deps) providers.Provider {
			return docker.New(d.Home)
		},
		Probe: func(d Deps) providers.Provider { return docker.New(d.Home) },
	},
	{
		Name:     "ssh",
		Enabled:  func(c *config.Config) bool { return c.Providers.SSH.Enabled },
		Optional: func(c *config.Config) bool { return c.Providers.SSH.Optional },
		Grants:   func(c *config.Config) string { return c.Providers.SSH.Grants() },
		Build: func(c *config.Config, d Deps) providers.Provider {
			return ssh.New(d.Home, d.Host["SSH_AUTH_SOCK"], config.AlwaysBlockedExpanded(d.Home))
		},
		Probe: func(d Deps) providers.Provider {
			return ssh.New(d.Home, d.Host["SSH_AUTH_SOCK"], config.AlwaysBlockedExpanded(d.Home))
		},
	},
	{
		Name:    "home",
		Enabled: func(c *config.Config) bool { return c.Providers.Home.Enabled },
		Grants:  func(c *config.Config) string { return c.Providers.Home.Grants() },
		Build: func(c *config.Config, d Deps) providers.Provider {
			return home.New(d.HomeDir)
		},
	},
	{
		Name:     "kubernetes",
		Enabled:  func(c *config.Config) bool { return c.Providers.Kubernetes.AnyClusterEnabled() },
		Optional: func(c *config.Config) bool { return c.Providers.Kubernetes.EnabledClustersOptional() },
		Grants:   func(c *config.Config) string { return c.Providers.Kubernetes.Grants() },
		Warnings: func(c *config.Config) []health.Check { return c.Providers.Kubernetes.Warnings() },
		Build: func(c *config.Config, d Deps) providers.Provider {
			return kubernetes.New(c.Providers.Kubernetes, d.Home, d.WorkDir, d.ApprovedKubeconfigs)
		},
		Probe: func(d Deps) providers.Provider {
			return kubernetes.New(kubernetes.Config{}, d.Home, d.WorkDir, nil)
		},
	},
	{
		Name:     "gitlab",
		Enabled:  func(c *config.Config) bool { return c.Providers.Gitlab.Enabled },
		Optional: func(c *config.Config) bool { return c.Providers.Gitlab.Optional },
		Grants:   func(c *config.Config) string { return c.Providers.Gitlab.Grants() },
		Build: func(c *config.Config, d Deps) providers.Provider {
			return gitlab.New(c.Providers.Gitlab, d.Host)
		},
		Probe: func(d Deps) providers.Provider {
			return gitlab.New(gitlab.Config{}, d.Host)
		},
	},
}

// Names returns every registered provider name in canonical order.
func Names() []string {
	out := make([]string, len(registry))
	for i, e := range registry {
		out[i] = e.Name
	}
	return out
}

// Features returns the enabled feature providers in canonical order, with each
// one's optionality.
func Features(cfg *config.Config, d Deps) []providers.Active {
	var out []providers.Active
	for _, e := range registry {
		if !e.Enabled(cfg) {
			continue
		}
		a := providers.Active{Provider: e.Build(cfg, d)}
		if e.Optional != nil {
			a.Optional = e.Optional(cfg)
		}
		out = append(out, a)
	}
	return out
}

// Known returns every host-probeable provider regardless of config, in canonical
// order. doctor probes the ones the config enables.
func Known(d Deps) []providers.Provider {
	var out []providers.Provider
	for _, e := range registry {
		if e.Probe != nil {
			out = append(out, e.Probe(d))
		}
	}
	return out
}

// View is a config-level summary of one enabled provider for `validate`. Grants and any
// granular FailurePolicy are authored by the provider's Config type; an empty FailurePolicy
// selects the standard provider-level setup behavior derived from Optional.
type View struct {
	Name          string
	Optional      bool
	Grants        string
	FailurePolicy string
}

// Views returns the intent view of the enabled feature providers, in canonical
// order.
func Views(cfg *config.Config) []View {
	var out []View
	for _, e := range registry {
		if e.Grants == nil || !e.Enabled(cfg) {
			continue
		}
		v := View{Name: e.Name, Grants: e.Grants(cfg)}
		if e.Optional != nil {
			v.Optional = e.Optional(cfg)
		}
		if e.FailurePolicy != nil {
			v.FailurePolicy = e.FailurePolicy(cfg)
		}
		out = append(out, v)
	}
	return out
}

// ConfigWarnings returns every feature provider's config-derived advisory lints in
// canonical order.
func ConfigWarnings(cfg *config.Config) []health.Check {
	var out []health.Check
	for _, e := range registry {
		if e.Warnings != nil {
			out = append(out, e.Warnings(cfg)...)
		}
	}
	return out
}

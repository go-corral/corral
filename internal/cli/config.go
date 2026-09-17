package cli

import (
	"os"
	"strings"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
)

// envMap snapshots the process environment as a map.
func envMap() map[string]string {
	environ := os.Environ()
	m := make(map[string]string, len(environ))
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[k] = v
		}
	}
	return m
}

// loadConfig loads the layered config. GlobalPath honors sandbox.GlobalConfigEnvVar
// so the in-sandbox hook reads the file the launcher pinned.
func loadConfig(profiles []string) (*config.Config, []config.Source, error) {
	return config.Load(config.LoadOptions{
		Profiles:   profiles,
		GlobalPath: os.Getenv(sandbox.GlobalConfigEnvVar),
	})
}

// checkResolvedPathGrants runs the symlink-resolving half of the providers.paths
// always-blocked guard (launcher-only — reads host state, fail-closed).
func checkResolvedPathGrants(cfg *config.Config, home string) error {
	return cfg.Providers.Paths.ValidateResolved(config.AlwaysBlockedExpanded(home))
}

// pinGlobalConfig pins the resolved global config path into the sandbox env so the
// in-sandbox hook reads the same file the launcher loaded. Grants it read-only.
func pinGlobalConfig(spec *sandbox.SandboxSpec, sources []config.Source) {
	for _, s := range sources {
		if s.Kind == "global" && s.Path != "" {
			if spec.SetEnv == nil {
				spec.SetEnv = map[string]string{}
			}
			spec.SetEnv[sandbox.GlobalConfigEnvVar] = s.Path
			spec.Mounts = append(spec.Mounts, sandbox.Mount{Src: s.Path, ReadOnly: true, Optional: true})
			return
		}
	}
}

// specParams maps a loaded config to sandbox.DefaultParams. config is the single source
// of truth for blocked paths, extra directories, and env policy.
func specParams(cfg *config.Config, home, project string, host map[string]string, commandBin string) sandbox.DefaultParams {
	net := sandbox.NetOpen
	if cfg.Net == config.NetNone {
		net = sandbox.NetNone
	}
	// Home provider: sandbox's $HOME is the private dir; Home stays the real home so
	// baseline $HOME-token rules keep allowing the real paths. Empty SandboxHome => HOME == Home.
	var sandboxHome string
	if dir, ok := homeDir(cfg, home, host); ok {
		sandboxHome = dir
	}
	launch := cfg.AgentLaunch()
	return sandbox.DefaultParams{
		Home:           home,
		SandboxHome:    sandboxHome,
		ProjectDir:     project,
		Net:            net,
		Hostname:       cfg.Hostname,
		AgentBinDir:    agents.BinDir(commandBin),
		AgentEnv:       cfg.AgentEnv(),
		TempEnvAliases: launch.TempEnvAliases,
		AgentRules:     agentRules(cfg.AgentConfigPaths()),
		// AlwaysBlockedMaskPaths, not AlwaysBlockedExpanded: an always-blocked dir that is
		// itself a host symlink must be masked at its real path too.
		BlockedPaths:   config.AlwaysBlockedMaskPaths(home),
		AgentConfigDir: cfg.AgentConfigDir(home, host),
		EnvPassthrough: cfg.Providers.Env.Passthrough,
		HostEnv:        host,
	}
}

// agentRules maps the selected agent's out-of-config-dir grants onto sandbox.Rule,
// so they compile through the same path as the embedded baseline.
func agentRules(paths []agents.ConfigPath) []sandbox.Rule {
	if len(paths) == 0 {
		return nil
	}
	rules := make([]sandbox.Rule, len(paths))
	for i, p := range paths {
		rules[i] = sandbox.Rule{
			Path:        p.Path,
			Description: p.Description,
			Writeable:   p.Writeable,
			Archs:       p.Archs,
			Recursive:   p.Recursive,
			Regex:       p.Regex,
			Optional:    p.Optional,
		}
	}
	return rules
}

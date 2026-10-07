package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/policy"
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
// so commands inside the sandbox read the file the launcher pinned.
func loadConfig(profiles []string) (*config.Config, []config.Source, error) {
	if len(profiles) == 0 {
		p, err := sessionProfiles()
		if err != nil {
			return nil, nil, err
		}
		profiles = p
	}
	return config.Load(config.LoadOptions{
		Profiles:   profiles,
		GlobalPath: os.Getenv(sandbox.GlobalConfigEnvVar),
	})
}

// sessionProfiles parses sandbox.ProfilesEnvVar.
func sessionProfiles() ([]string, error) {
	v := os.Getenv(sandbox.ProfilesEnvVar)
	if v == "" {
		return nil, nil
	}
	names := strings.Split(v, ",")
	if slices.Contains(names, "") {
		return nil, fmt.Errorf("%s=%q: empty profile name", sandbox.ProfilesEnvVar, v)
	}
	return names, nil
}

// checkResolvedPathGrants runs the symlink-resolving half of the providers.paths
// always-blocked guard (launcher-only — reads host state, fail-closed).
func checkResolvedPathGrants(cfg *config.Config, home string) error {
	return cfg.Providers.Paths.ValidateResolved(config.AlwaysBlockedExpanded(home))
}

// pinGlobalConfig pins the resolved global config path into the sandbox env so
// commands inside the sandbox read the same file the launcher loaded. Grants it read-only.
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

// prepareAuditDir checks and creates the directory of a custom policy.audit.path on the host.
// The self-protect gate guards the log's directory, so a directory that is or contains the
// home directory is refused.
func prepareAuditDir(cfg *config.Config, home string, dryRun bool) error {
	p := cfg.Policy.Audit.Path
	if p == "" {
		return nil
	}
	dir := filepath.Dir(p)
	if pathutil.AtOrUnderClean(home, dir) {
		return fmt.Errorf("policy.audit.path %q: directory %q is or contains the home directory; use a dedicated directory", p, dir)
	}
	// Check where MkdirAll would create it: behind a symlinked ancestor, that can be an
	// always-blocked path.
	real, err := policy.CanonicalizeRoot(dir, "")
	if err != nil {
		return fmt.Errorf("policy.audit.path %q: %w", p, err)
	}
	for _, f := range config.AlwaysBlockedExpanded(home) {
		if pathutil.AtOrUnder(dir, f) {
			return fmt.Errorf("policy.audit.path %q: directory %q overlaps the always-blocked path %q", p, dir, f)
		}
		if pathutil.AtOrUnder(real, pathutil.Resolve(f)) {
			return fmt.Errorf("policy.audit.path %q: directory %q resolves into the always-blocked path %q", p, dir, f)
		}
		// A symlinked directory resolves elsewhere, and the self-protect gate guards the resolved
		// directory, so its target must not contain an always-blocked path.
		if real != dir && pathutil.Under(pathutil.Resolve(f), real) {
			return fmt.Errorf("policy.audit.path %q: directory %q resolves to %q, which contains the always-blocked path %q", p, dir, real, f)
		}
	}
	if dryRun {
		return nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("policy.audit.path %q: %w", p, err)
	}
	return nil
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

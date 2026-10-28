package opencode

import "github.com/go-corral/corral/internal/agents/spec"

type Config struct{}

var _ spec.AgentConfig = Config{}

// SandboxEnv disables opencode's self-update, which cannot replace the read-only binary inside
// the sandbox.
func (Config) SandboxEnv() map[string]string {
	return map[string]string{"OPENCODE_DISABLE_AUTOUPDATE": "1"}
}

func (Config) ValidationFields() []spec.BannerField { return nil }

// LaunchArgs is empty: opencode routes its subcommands by the first argument, so arguments
// placed before the `corral run -- ...` arguments would hide the subcommand.
func (Config) LaunchArgs() []string { return nil }

package opencode

import "github.com/go-corral/corral/internal/agents/spec"

// Config is opencode's config-owned settings surface.
type Config struct {
	spec.Args `yaml:",inline"`
}

var _ spec.AgentConfig = Config{}

func (Config) SandboxEnv() map[string]string {
	return map[string]string{"OPENCODE_DISABLE_AUTOUPDATE": "1"}
}

func (c Config) ValidationFields() []spec.BannerField { return c.ArgsFields() }

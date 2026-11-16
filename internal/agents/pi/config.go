package pi

import "github.com/go-corral/corral/internal/agents/spec"

// Config is pi's config-owned settings surface.
type Config struct {
	spec.Args `yaml:",inline"`
}

var _ spec.AgentConfig = Config{}

// SandboxEnv sets PI_OFFLINE=1, which disables pi's startup network operations. Those
// cannot work inside corral: ~/.ssh is always blocked and masked, so the git fetch only
// emits a host-key prompt and an "update available" banner.
func (Config) SandboxEnv() map[string]string {
	return map[string]string{"PI_OFFLINE": "1"}
}

func (c Config) ValidationFields() []spec.BannerField { return c.ArgsFields() }

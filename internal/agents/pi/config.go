package pi

import "github.com/go-corral/corral/internal/agents/spec"

// Config is pi's config-owned settings surface. pi has no knobs yet; the type exists so pi
// owns its config surface like every agent and provider.
type Config struct{}

var _ spec.AgentConfig = Config{}

// SandboxEnv sets PI_OFFLINE=1, which disables pi's startup network operations. Those
// cannot work inside corral: ~/.ssh is always blocked and masked, so the git fetch only
// emits a host-key prompt and an "update available" banner.
func (Config) SandboxEnv() map[string]string {
	return map[string]string{"PI_OFFLINE": "1"}
}

func (Config) BannerFields() []spec.BannerField     { return nil }
func (Config) ValidationFields() []spec.BannerField { return nil }

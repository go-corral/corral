package cli

import (
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
)

// TestApplyHookAgentHonorsPinnedAgent verifies the in-sandbox hook resolves its self-protect /
// audit target from the agent the launcher pinned (CORRAL_AGENT), so a `corral run <agent>`
// positional that bypasses the config file is still honored. An unknown or unset value leaves
// the config's agent in place (defensive / host no-op).
func TestApplyHookAgentHonorsPinnedAgent(t *testing.T) {
	cases := []struct {
		name   string
		pin    string
		config string
		want   string
	}{
		{"pinned pi overrides claude config", "pi", "claude", "pi"},
		{"unknown pin ignored", "bogus", "claude", "claude"},
		{"unset pin is a no-op", "", "pi", "pi"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(sandbox.AgentEnvVar, tc.pin)
			cfg := &config.Config{Agent: tc.config}
			applyHookAgent(cfg)
			if got := cfg.EffectiveAgent(); got != tc.want {
				t.Errorf("EffectiveAgent() = %q, want %q (pin=%q config=%q)", got, tc.want, tc.pin, tc.config)
			}
		})
	}
}

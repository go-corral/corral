package config

import (
	"testing"

	"github.com/go-corral/corral/internal/agents"
)

func TestValidateAgent(t *testing.T) {
	home := t.TempDir()

	if err := (&Config{Agent: "codex"}).Validate(home); err == nil {
		t.Error("Validate accepted an unregistered agent; want a fail-closed error")
	}
	for _, ok := range []string{"", "claude"} {
		if err := (&Config{Agent: ok}).Validate(home); err != nil {
			t.Errorf("Validate(agent=%q) = %v, want nil", ok, err)
		}
	}
}

func TestEffectiveAgentDefault(t *testing.T) {
	if got := (&Config{}).EffectiveAgent(); got != agents.Default {
		t.Errorf("EffectiveAgent() with no agent set = %q, want %q", got, agents.Default)
	}
	if got := (&Config{Agent: "claude"}).EffectiveAgent(); got != "claude" {
		t.Errorf("EffectiveAgent() = %q, want claude", got)
	}
}

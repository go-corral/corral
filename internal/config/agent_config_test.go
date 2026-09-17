package config

import (
	"reflect"
	"testing"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/agents/claude"
	"github.com/go-corral/corral/internal/agents/pi"
)

// drift guard: agentConfig() must dispatch every registered agent to its own config-owned
// settings surface (the agent-owned Config type embedded in the Agents struct), so the sandbox
// env and banner fields come from the selected agent's knobs — never silently from claude's.
// The expected map pins each agent name to its concrete Config type; a newly registered agent
// missing here (or one whose agentConfig returns the wrong type) fails instead of falling back.
func TestAgentConfigDispatch(t *testing.T) {
	want := map[string]reflect.Type{
		"claude": reflect.TypeOf(claude.Config{}),
		"pi":     reflect.TypeOf(pi.Config{}),
	}
	for _, name := range agents.Known() {
		wantType, ok := want[name]
		if !ok {
			t.Errorf("registered agent %q is missing from the expected agentConfig map; wire its "+
				"Config type into config.agentConfig and add it here", name)
			continue
		}
		cfg := &Config{Agent: name}
		if got := reflect.TypeOf(cfg.agentConfig()); got != wantType {
			t.Errorf("agentConfig() for agent %q = %v, want %v", name, got, wantType)
		}
	}
}

package claude

import (
	"testing"

	"github.com/go-corral/corral/internal/agents/spec"
)

func TestValidationFields(t *testing.T) {
	for bits := range 64 {
		cfg := Config{
			ClaudeaiConnectors: bits&1 != 0,
			Telemetry:          bits&2 != 0,
			ErrorReporting:     bits&4 != 0,
			FeedbackSurvey:     bits&8 != 0,
			AttributionHeader:  bits&16 != 0,
			AgentView:          bits&32 != 0,
		}
		fields := cfg.ValidationFields()
		want := 5
		if !cfg.AttributionHeader {
			want++
		}
		if len(fields) != want {
			t.Fatalf("toggles %06b: got %d fields, want %d", bits, len(fields), want)
		}
		env := cfg.SandboxEnv()
		for i, pair := range [][2]string{
			{"Connectors", "ENABLE_CLAUDEAI_MCP_SERVERS"},
			{"Telemetry", "DISABLE_TELEMETRY"},
			{"Error reporting", "DISABLE_ERROR_REPORTING"},
			{"Feedback survey", "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY"},
			{"Agent view", "CLAUDE_CODE_DISABLE_AGENT_VIEW"},
			{"Attribution header", "CLAUDE_CODE_ATTRIBUTION_HEADER"},
		} {
			if i >= len(fields) {
				continue
			}
			f := fields[i]
			value := "on"
			if _, disabled := env[pair[1]]; disabled {
				value = "off"
			}
			if f.Label != pair[0] || f.Value != value {
				t.Errorf("toggles %06b: field %d = %+v, want %s: %s", bits, i, f, pair[0], value)
			}
		}
	}
}

func TestValidationFieldsArgs(t *testing.T) {
	fields := Config{AttributionHeader: true, Args: spec.Args{Args: []string{"--model", "sonnet"}}}.ValidationFields()
	last := fields[len(fields)-1]
	if last.Label != "Args" || last.Value != "--model sonnet" {
		t.Errorf("last field = %+v, want Args: --model sonnet", last)
	}
	for _, f := range (Config{AttributionHeader: true}).ValidationFields() {
		if f.Label == "Args" {
			t.Errorf("Args field shown without args: %+v", f)
		}
	}
}

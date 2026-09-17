package claude

import "testing"

func TestValidationFields(t *testing.T) {
	for bits := range 32 {
		cfg := Config{
			ClaudeaiConnectors: bits&1 != 0,
			Telemetry:          bits&2 != 0,
			ErrorReporting:     bits&4 != 0,
			FeedbackSurvey:     bits&8 != 0,
			AttributionHeader:  bits&16 != 0,
		}
		fields := cfg.ValidationFields()
		want := 4
		if !cfg.AttributionHeader {
			want++
		}
		if len(fields) != want {
			t.Fatalf("toggles %05b: got %d fields, want %d", bits, len(fields), want)
		}
		env := cfg.SandboxEnv()
		for i, pair := range [][2]string{
			{"Connectors", "ENABLE_CLAUDEAI_MCP_SERVERS"},
			{"Telemetry", "DISABLE_TELEMETRY"},
			{"Error reporting", "DISABLE_ERROR_REPORTING"},
			{"Feedback survey", "CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY"},
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
				t.Errorf("toggles %05b: field %d = %+v, want %s: %s", bits, i, f, pair[0], value)
			}
		}
	}
}

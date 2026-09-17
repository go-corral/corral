package claude

import (
	"strings"

	"github.com/go-corral/corral/internal/agents/spec"
)

type Config struct {
	ClaudeaiConnectors bool `yaml:"claudeaiConnectors"`
	Telemetry          bool `yaml:"telemetry"`
	ErrorReporting     bool `yaml:"errorReporting"`
	FeedbackSurvey     bool `yaml:"feedbackSurvey"`
	AttributionHeader  bool `yaml:"attributionHeader"`
}

var _ spec.AgentConfig = Config{}

// SandboxEnv is claude's deny-by-default connectors + phone-home policy: unless explicitly
// enabled, the agent sets Claude Code's own kill-switch env var.
func (c Config) SandboxEnv() map[string]string {
	env := map[string]string{}
	if !c.ClaudeaiConnectors {
		env["ENABLE_CLAUDEAI_MCP_SERVERS"] = "false"
	}
	if !c.Telemetry {
		env["DISABLE_TELEMETRY"] = "1"
	}
	if !c.ErrorReporting {
		env["DISABLE_ERROR_REPORTING"] = "1"
	}
	if !c.FeedbackSurvey {
		env["CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY"] = "1"
	}
	if !c.AttributionHeader {
		env["CLAUDE_CODE_ATTRIBUTION_HEADER"] = "0"
	}
	if len(env) == 0 {
		return nil
	}
	return env
}

func (c Config) BannerFields() []spec.BannerField {
	fields := []spec.BannerField{c.connectorsField(), c.phoneHomeField()}
	if !c.AttributionHeader {
		fields = append(fields, spec.BannerField{Label: "attribution", Value: "off"})
	}
	return fields
}

func (c Config) ValidationFields() []spec.BannerField {
	toggle := func(label string, enabled bool) spec.BannerField {
		value := "off"
		if enabled {
			value = "on"
		}
		return spec.BannerField{Label: label, Value: value}
	}
	fields := []spec.BannerField{
		toggle("Connectors", c.ClaudeaiConnectors),
		toggle("Telemetry", c.Telemetry),
		toggle("Error reporting", c.ErrorReporting),
		toggle("Feedback survey", c.FeedbackSurvey),
	}
	if !c.AttributionHeader {
		fields = append(fields, toggle("Attribution header", false))
	}
	return fields
}

func (c Config) connectorsField() spec.BannerField {
	if c.ClaudeaiConnectors {
		return spec.BannerField{Label: "connectors", Value: "on"}
	}
	return spec.BannerField{Label: "connectors", Value: "off"}
}

func (c Config) phoneHomeField() spec.BannerField {
	var enabled []string
	if c.Telemetry {
		enabled = append(enabled, "telemetry")
	}
	if c.ErrorReporting {
		enabled = append(enabled, "errors")
	}
	if c.FeedbackSurvey {
		enabled = append(enabled, "survey")
	}
	switch len(enabled) {
	case 0:
		return spec.BannerField{Label: "phone-home", Value: "off"}
	case 3:
		return spec.BannerField{Label: "phone-home", Value: "on"}
	default:
		return spec.BannerField{Label: "phone-home", Value: "partial (" + strings.Join(enabled, ", ") + ")"}
	}
}

package policy

import (
	"strings"
	"testing"
)

// awsKeyFixture is a format-valid AWS access key id (AKIA + 16 [0-9A-Z]) used to
// trip the always-on known-format detector without embedding a PEM block (which would
// make this very test file unreadable through corral's own Read gate).
const awsKeyFixture = "AKIA" + "QQQQQQQQQQQQQQQQ"

// The PreToolUse secret-scan deny message must carry the incident-response next step
// so the user is told to rotate/revoke + report — not just that it was blocked.
func TestSecretScanRuleAppendsIncidentHint(t *testing.T) {
	r := &SecretScanRule{}
	d, matched, err := r.Evaluate(toolEvent(t, "Write", map[string]any{"content": "key=" + awsKeyFixture}))
	if err != nil || !matched || d.Action != Deny {
		t.Fatalf("expected a deny, got matched=%v action=%v err=%v", matched, d.Action, err)
	}
	if !strings.Contains(d.Reason, IncidentHint) {
		t.Errorf("deny reason must contain the default incident hint %q; got %q", IncidentHint, d.Reason)
	}
	if strings.Contains(d.Reason, awsKeyFixture) {
		t.Errorf("deny reason must NOT contain the secret value: %q", d.Reason)
	}
}

// A configured policy.incidentHint (org runbook/contact) overrides the default wording.
func TestSecretScanRuleIncidentHintOverride(t *testing.T) {
	const custom = "Follow RUNBOOK-7 and page #sec-oncall."
	r := &SecretScanRule{IncidentHint: custom}
	d, matched, err := r.Evaluate(toolEvent(t, "Write", map[string]any{"content": awsKeyFixture}))
	if err != nil || !matched || d.Action != Deny {
		t.Fatalf("expected a deny, got matched=%v action=%v err=%v", matched, d.Action, err)
	}
	if !strings.Contains(d.Reason, custom) {
		t.Errorf("deny reason must contain the configured hint %q; got %q", custom, d.Reason)
	}
	if strings.Contains(d.Reason, IncidentHint) {
		t.Errorf("a configured hint must REPLACE the default, not append it; got %q", d.Reason)
	}
}

// The PostToolUse withhold marker (ingress) must also carry the incident next step,
// and the optional override must reach it.
func TestRunPostToolUseMarkerHasIncidentHint(t *testing.T) {
	ev := `{"hook_event_name":"PostToolUse","tool_name":"mcp__db__get","tool_response":"the value is ` + awsKeyFixture + `"}`

	for _, tc := range []struct {
		name string
		hint string
		want string
	}{
		{"default", "", IncidentHint},
		{"override", "Follow RUNBOOK-7.", "Follow RUNBOOK-7."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errw strings.Builder
			code := RunPostToolUseHook(0, 0, tc.hint, nil, strings.NewReader(ev), NewPostToolUseGate(&out), &errw)
			if code != ExitAllow {
				t.Fatalf("withhold rides in the JSON (exit 0); got %d", code)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Errorf("withhold marker must contain %q; got %q", tc.want, out.String())
			}
			if strings.Contains(out.String(), awsKeyFixture) {
				t.Errorf("withhold marker must not echo the secret value: %q", out.String())
			}
		})
	}
}

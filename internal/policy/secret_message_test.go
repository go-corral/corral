package policy

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

// awsKeyFixture is a format-valid AWS access key id (AKIA + 16 [0-9A-Z]) used to
// trip the always-on known-format detector without embedding a PEM block (which would
// make this very test file unreadable through corral's own Read gate).
const awsKeyFixture = "AKIA" + "QQQQQQQQQQQQQQQQ"

// The secret-scan reason names the kind of secret and nothing else: no value, no final period.
func TestSecretScanRuleReason(t *testing.T) {
	r := &SecretScanRule{}
	d, matched, err := r.Evaluate(toolEvent(t, "Write", map[string]any{"content": "key=" + awsKeyFixture}))
	if err != nil || !matched || d.Action != Deny {
		t.Fatalf("expected a deny, got matched=%v action=%v err=%v", matched, d.Action, err)
	}
	if want := "the content being written contains an AWS access key id"; d.Reason != want {
		t.Errorf("deny reason = %q, want %q", d.Reason, want)
	}
}

// A credential in a tool output is withheld with the layer marker and the fix, never the value.
func TestRunPostToolUseWithheldMarker(t *testing.T) {
	ev := `{"hook_event_name":"PostToolUse","tool_name":"mcp__db__get","tool_response":"the value is ` + awsKeyFixture + `"}`
	var out, errw strings.Builder
	if code := RunPostToolUseHook(0, 0, nil, strings.NewReader(ev), NewPostToolUseGate(&out), &errw); code != ExitAllow {
		t.Fatalf("withhold rides in the JSON (exit 0); got %d", code)
	}
	want := "output withheld by corral policy [hook:response-secret]: the mcp__db__get output contained an AWS access key id. The call ran. Fix: " + responseSecretFix
	if !strings.Contains(out.String(), want) {
		t.Errorf("withhold marker must contain %q; got %q", want, out.String())
	}
	if strings.Contains(out.String(), awsKeyFixture) {
		t.Errorf("withhold marker must not echo the secret value: %q", out.String())
	}
}

// An output that corral cannot scan is withheld with the fail-closed marker.
func TestRunPostToolUseUnscannedMarker(t *testing.T) {
	var out, errw strings.Builder
	RunPostToolUseHook(0, 0, nil, strings.NewReader("{not json"), NewPostToolUseGate(&out), &errw)
	want := "output withheld by corral policy [hook:fail-closed]: corral could not scan the output (cannot parse hook event). The call ran. Fix: Tell the user the error."
	if !strings.Contains(out.String(), want) {
		t.Errorf("withhold marker must contain %q; got %q", want, out.String())
	}
}

// A call that corral cannot check is blocked with the fail-closed marker and its fix.
func TestRunHookFailClosedMessage(t *testing.T) {
	var errBuf bytes.Buffer
	if code := RunHookWith(NewEngine(), strings.NewReader("{not json"), io.Discard, &errBuf, PresentJSON); code != ExitBlock {
		t.Fatalf("expected block (2), got %d", code)
	}
	got := errBuf.String()
	if !strings.HasPrefix(got, "corral: blocked by corral policy [hook:fail-closed]: cannot parse hook event: ") || !strings.HasSuffix(got, ". Fix: "+failClosedFix+"\n") {
		t.Errorf("fail-closed message = %q", got)
	}
}

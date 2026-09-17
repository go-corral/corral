package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// JSON-escape boundary coverage. ResponseBytes hands the scanner the raw JSON bytes of a
// tool response, so a credential written right after a newline inside a string appears as
// `...removed.\n\nghp_…`: the byte immediately before the token is the 'n' of the `\n`
// escape into a word character, defeating the leading \b anchor in every known-format regex,
// letting a token embedded in a tool response slip past the PostToolUse ingress scan (a
// fail-open). scanSecrets now also scans a backslash-decoded copy.
//
// Fixtures build the token prefixes at runtime (concatenation) so no contiguous live
// credential sits in this source file — the scanner would otherwise block reading it.
func TestScanSecretsJSONEscapedBoundary(t *testing.T) {
	ghToken := "gh" + "p_" + "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZab" // ghp_ + 38 alnum (>=36)
	awsKey := "AK" + "IA" + "ABCDEFGHIJKLMNOP"                        // AKIA + 16

	cases := []struct {
		name    string
		data    string
		wantHit bool
		wantKnd SecretKind
	}{
		// The exact shape that escaped: token right after an escaped blank line in a JSON
		// string value. This is what ResponseBytes delivers for a multi-line text field.
		{
			name:    "github token after escaped newline in json string",
			data:    `{"description":"Demo token left here.\n\n` + ghToken + `"}`,
			wantHit: true,
			wantKnd: KindGitHubToken,
		},
		// Other escapes whose trailing byte is a word char defeat the leading \b too: an
		// escaped tab ends in 't', a unicode-escaped space ends in a hex digit. Both need
		// the decode (the latter also exercises the parseHex4 branch).
		{"github token after escaped tab", `{"d":"x\t` + ghToken + `"}`, true, KindGitHubToken},
		{"aws key after \\u0020 escaped space", `{"d":"x\u0020` + awsKey + `"}`, true, KindAWSKey},
		// Control: the same token after a real space matches on the raw scan; it must
		// keep matching (the decoded re-scan is purely additive).
		{"github token after literal space still matches", "note " + ghToken, true, KindGitHubToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, hit := scanSecrets([]byte(tc.data), 0) // entropy off: known-format detectors only
			if hit != tc.wantHit {
				t.Fatalf("hit=%v, want %v (kind=%q) for %q", hit, tc.wantHit, res.kind, tc.data)
			}
			if hit && res.kind != tc.wantKnd {
				t.Errorf("kind=%q, want %q", res.kind, tc.wantKnd)
			}
		})
	}
}

// End-to-end through the real PostToolUse ingress path, in the faithful nested-JSON shape
// that MCP tools produce: a server serializes its whole result object into a content "text"
// field (so a multi-line value's newline becomes a `\n` escape), then the hook event is
// JSON-encoded again (so that `\n` becomes `\\n` on the wire). The token therefore arrives
// doubly escaped and must still be withheld, not allowed. A single decode pass does not catch
// this; the fixed-point loop does.
func TestPostToolUseWithholdsTokenAfterEscapedNewline(t *testing.T) {
	ghToken := "gh" + "p_" + "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZab"
	// A tool result object with a multi-line text field holding the token after a blank line.
	// Marshalling it once produces the stringified result that rides in the "text" field.
	result, err := json.Marshal(map[string]any{
		"record": map[string]string{
			"description": "Token left here - will be removed.\n\n" + ghToken,
		},
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	resp, err := json.Marshal([]map[string]string{
		{"type": "text", "text": string(result)}, // stringified JSON -> double encoding
	})
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	event, err := json.Marshal(map[string]any{
		"hook_event_name": "PostToolUse",
		"tool_name":       "mcp__server__getRecord",
		"tool_response":   json.RawMessage(resp),
	})
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}

	var out, errw strings.Builder
	code := RunPostToolUseHook(0, 0, "", nil, strings.NewReader(string(event)), NewPostToolUseGate(&out), &errw)
	if code != ExitAllow { // ingress withholds via updatedToolOutput, not exit 2
		t.Fatalf("exit code=%d, want ExitAllow (%d)", code, ExitAllow)
	}
	if strings.Contains(out.String(), ghToken) {
		t.Fatalf("withheld response still leaked the token: %s", out.String())
	}
	if !strings.Contains(out.String(), "withheld") {
		t.Fatalf("expected a withheld-marker replacement, got: %s", out.String())
	}
}

package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestSecretScannerParity validates the user-reported concern that "the secret scanner
// works differently in different situations" (e.g. a GitHub token blocked from an MCP
// response but not recognized in a prompt). Every entry point — the UserPromptSubmit
// prompt scan (ScanPromptText), the PostToolUse MCP-response scan (ScanResponseBytes), the
// PreToolUse MCP-argument scan (SecretScanRule.evalMCPArgs) and the write scan
// (SecretScanRule.evalWrite) — must reach the same verdict on the same bytes, because all
// of them funnel through scanSecrets. This test feeds one battery of samples through all
// four and asserts they agree, so a future change that diverges one path is caught.
//
// Samples are assembled at runtime (concatenation / strings.Repeat) so no full credential
// literal appears in this source file — otherwise corral's own write/secret gate would block
// committing it. The sample values are never printed on failure (kind/index only), to keep
// the "report the kind, never the value" invariant.
func TestSecretScannerParity(t *testing.T) {
	secrets := []struct {
		name string
		want SecretKind
		val  string
	}{
		{"github-classic-pat", KindGitHubToken, "ghp_" + strings.Repeat("A", 40)},
		{"github-oauth", KindGitHubToken, "gho_" + strings.Repeat("b", 36)},
		{"github-fine-grained", KindGitHubToken, "github_pat_" + strings.Repeat("C", 60)},
		{"pem-begin", KindPEMPrivateKey, "-----BEGIN " + "OPENSSH PRIVATE KEY-----"},
		{"aws-akia", KindAWSKey, "AKIA" + strings.Repeat("Z", 16)},
		{"jwt", KindJWT, "eyJ" + strings.Repeat("a", 12) + ".eyJ" + strings.Repeat("b", 12) + "." + strings.Repeat("c", 12)},
		{"slack", KindSlackToken, "xoxb-" + strings.Repeat("1", 14)},
		{"google-api", KindGoogleAPIKey, "AIza" + strings.Repeat("d", 35)},
		{"stripe-live", KindStripeKey, "sk_live_" + strings.Repeat("e", 20)},
	}
	benign := []struct {
		name string
		val  string
	}{
		{"prose", "please summarize the architecture doc and suggest next steps"},
		{"short-ghp", "ghp_tooShort"}, // below the 36-char body bar: must not hit anywhere
		{"git-sha", "commit " + strings.Repeat("a", 40)},
	}

	// scanAll runs the four real entry points over one input and returns their hit verdicts
	// plus the kinds the two byte-oriented scanners reported, so the caller can assert
	// parity. evalMCPArgs sees the raw bytes (it scans tool_input directly); evalWrite sees
	// the bytes embedded in a JSON write payload, mirroring a real Write tool call.
	scanAll := func(t *testing.T, val string) (promptHit, respHit, mcpHit, writeHit bool, promptKind, respKind SecretKind) {
		t.Helper()
		pk, ph := ScanPromptText([]byte(val), 0, 0)
		rk, rh := ScanResponseBytes([]byte(val), 0)

		rule := &SecretScanRule{}
		mcpEv := &HookEvent{ToolName: "mcp__server__tool", ToolInput: json.RawMessage(val)}
		_, mh, err := rule.evalMCPArgs(mcpEv)
		if err != nil {
			t.Fatalf("evalMCPArgs error: %v", err)
		}
		writeInput, _ := json.Marshal(map[string]string{"content": val})
		writeEv := &HookEvent{ToolName: "Write", ToolInput: writeInput}
		_, wh, err := rule.evalWrite(writeEv)
		if err != nil {
			t.Fatalf("evalWrite error: %v", err)
		}
		return ph, rh, mh, wh, pk, rk
	}

	for _, s := range secrets {
		t.Run("secret/"+s.name, func(t *testing.T) {
			ph, rh, mh, wh, pk, rk := scanAll(t, s.val)
			if !ph || !rh || !mh || !wh {
				t.Errorf("entry points disagree on a %s: prompt=%v response=%v mcpArgs=%v write=%v (all must be true)",
					s.name, ph, rh, mh, wh)
			}
			if pk != s.want || rk != s.want {
				t.Errorf("%s: kind mismatch — prompt=%q response=%q want=%q", s.name, pk, rk, s.want)
			}
		})
	}
	for _, b := range benign {
		t.Run("benign/"+b.name, func(t *testing.T) {
			ph, rh, mh, wh, _, _ := scanAll(t, b.val)
			if ph || rh || mh || wh {
				t.Errorf("entry points disagree on benign %s: prompt=%v response=%v mcpArgs=%v write=%v (all must be false)",
					b.name, ph, rh, mh, wh)
			}
		})
	}

	// Parity must also hold under the opt-in entropy heuristic: a high-entropy token that
	// only the entropy bar catches must be seen identically by the prompt and response
	// scanners (the two that take an explicit threshold).
	t.Run("entropy-parity", func(t *testing.T) {
		highEntropy := "Zx9" + strings.Repeat("Q7vK2mNpY", 4) // mixed, long, no known prefix
		const thr = 3.0
		_, ph := ScanPromptText([]byte(highEntropy), thr, 0)
		_, rh := ScanResponseBytes([]byte(highEntropy), thr)
		if ph != rh {
			t.Errorf("entropy scan disagrees: prompt=%v response=%v (must match at threshold %.1f)", ph, rh, thr)
		}
	})
}

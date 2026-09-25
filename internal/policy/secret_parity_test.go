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
		{"atlassian-api", KindAtlassian, "ATATT3" + strings.Repeat("f", 177) + "=0A1B2C3D"},
		{"anthropic-api", KindAnthropicKey, "sk-ant-" + "api03-" + strings.Repeat("f", 93) + "AA"},
		{"anthropic-oauth", KindAnthropicKey, "sk-ant-" + "oat01-" + strings.Repeat("g", 95)},
		{"openai-project", KindOpenAIKey, "sk-" + "proj-" + strings.Repeat("h", 74) + "T3Blbk" + "FJ" + strings.Repeat("i", 74)},
		{"openai-legacy", KindOpenAIKey, "sk-" + strings.Repeat("j", 20) + "T3Blbk" + "FJ" + strings.Repeat("k", 20)},
		{"huggingface", KindHuggingFace, "hf_" + strings.Repeat("l", 34)},
		{"groq", KindGroqKey, "gsk_" + strings.Repeat("m", 52)},
		{"xai", KindXAIKey, "xai-" + strings.Repeat("n", 80)},
		{"openrouter", KindOpenRouterKey, "sk-or-" + "v1-" + strings.Repeat("0", 64)},
		{"perplexity", KindPerplexityKey, "pplx-" + strings.Repeat("o", 48)},
		{"vault", KindVaultToken, "hvs." + strings.Repeat("f", 90)},
		{"terraform", KindTerraform, strings.Repeat("g", 14) + ".atlas" + "v1." + strings.Repeat("h", 67)},
		{"grafana-sa", KindGrafanaToken, "glsa_" + strings.Repeat("i", 32) + "_" + strings.Repeat("0", 8)},
		{"digitalocean", KindDigitalOcean, "dop_" + "v1_" + strings.Repeat("1", 64)},
		{"tailscale", KindTailscaleKey, "tskey-" + "auth-" + "k12345CNTRL-" + strings.Repeat("j", 32)},
		{"databricks", KindDatabricks, "dapi" + strings.Repeat("2", 32)},
		{"pulumi", KindPulumiToken, "pul-" + strings.Repeat("3", 40)},
		{"doppler", KindDopplerToken, "dp." + "pt." + strings.Repeat("k", 43)},
		{"heroku", KindHerokuKey, "HRKU-" + "AA" + strings.Repeat("l", 58)},
		{"flyio", KindFlyToken, "fo1_" + strings.Repeat("m", 43)},
		{"cloudflare-origin-ca", KindCloudflareKey, "v1.0-" + strings.Repeat("4", 24) + "-" + strings.Repeat("5", 146)},
		{"1password-secret-key", KindOnePassword, "A3-" + "ABC123-" + "DEF456GHI78-" + "JKL90-" + "MNO12-" + "PQR34"},
		{"age", KindAgeKey, "AGE-SECRET-" + "KEY-1" + strings.Repeat("Q", 58)},
		{"sentry-user", KindSentryToken, "sntryu_" + strings.Repeat("6", 64)},
		{"npm", KindNpmToken, "npm_" + strings.Repeat("f", 36)},
		{"pypi", KindPyPIToken, "pypi-" + "AgEIcHlwaS5vcmc" + strings.Repeat("g", 60)},
		{"rubygems", KindRubyGemsKey, "rubygems_" + strings.Repeat("0", 48)},
		{"docker-pat", KindDockerToken, "dckr_" + "pat_" + strings.Repeat("h", 27)},
		{"artifactory", KindArtifactory, "AKCp" + strings.Repeat("i", 69)},
		{"gitlab-pat", KindGitLabToken, "glpat-" + strings.Repeat("f", 20)},
		{"gitlab-job", KindGitLabToken, "glcbt-" + "64_" + strings.Repeat("g", 20)},
		{"gitlab-runner-registration", KindGitLabToken, "GR1348941" + strings.Repeat("h", 20)},
		{"gitlab-session", KindGitLabToken, "_gitlab_session=" + strings.Repeat("0", 32)},
		{"sendgrid", KindSendGridKey, "SG." + strings.Repeat("f", 22) + "." + strings.Repeat("g", 43)},
		{"shopify", KindShopifyToken, "shpat_" + strings.Repeat("0", 32)},
		{"linear", KindLinearKey, "lin_" + "api_" + strings.Repeat("h", 40)},
		{"notion", KindNotionToken, "ntn_" + strings.Repeat("1", 11) + strings.Repeat("i", 35)},
		{"postman", KindPostmanKey, "PMAK-" + strings.Repeat("2", 24) + "-" + strings.Repeat("3", 34)},
		{"dynatrace", KindDynatrace, "dt0c01." + strings.Repeat("j", 24) + "." + strings.Repeat("k", 64)},
	}
	benign := []struct {
		name string
		val  string
	}{
		{"prose", "please summarize the architecture doc and suggest next steps"},
		{"short-ghp", "ghp_tooShort"}, // below the 36-char body bar: must not hit anywhere
		{"git-sha", "commit " + strings.Repeat("a", 40)},
		{"kebab-slug", "risk-admin-dashboard-configuration-and-settings-refactor"},
		{"gitlab-prefix-in-prose", "set glpat-token in the CI settings"},
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

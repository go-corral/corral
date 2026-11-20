package enforce

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/policy"
)

// PromptSecretWarn scans the submitted prompt for secret material. On a hit it emits a soft
// warn-and-resubmit notice and audit-logs the decision through aud when set (kind only, never
// the prompt or value).
func PromptSecretWarn(ev *policy.HookEvent, entropy float64, aud policy.AuditFunc, stdout io.Writer) (int, bool) {
	if ev == nil || ev.Prompt == "" {
		return policy.ExitAllow, false
	}
	kind, hit := policy.ScanPromptText([]byte(ev.Prompt), entropy, 0)
	if !hit {
		return policy.ExitAllow, false
	}
	// Resubmit-once per distinct prompt.
	marker := PromptSecretMarkerPath(ev.SessionID, ev.Prompt)
	if _, err := os.Stat(marker); err == nil {
		return policy.ExitAllow, true
	}
	// Best-effort marker write; failure only risks warning again.
	if f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600); err == nil {
		_ = f.Close()
	}
	auditPromptSecret(aud, ev, kind)
	return policy.WriteUserPromptBlock(stdout, promptSecretWarning(kind)), true
}

// auditPromptSecret records the prompt-secret-scan decision under its own recover.
func auditPromptSecret(aud policy.AuditFunc, ev *policy.HookEvent, kind policy.SecretKind) {
	if aud == nil {
		return
	}
	defer func() { _ = recover() }()
	aud(ev, policy.Decision{
		Action: policy.Deny,
		Rule:   "prompt-secret-scan",
		Reason: fmt.Sprintf("the submitted prompt appears to contain %s", kind),
	})
}

// PromptSecretMarkerPath is the per-(session,prompt) marker under $TMPDIR. Hashing the
// prompt gives resubmit-once-per-distinct-prompt.
func PromptSecretMarkerPath(sessionID, prompt string) string {
	sum := sha256.Sum256([]byte(prompt))
	return filepath.Join(os.TempDir(), "corral-promptsecret-"+SanitizeMarkerComponent(sessionID)+"-"+hex.EncodeToString(sum[:8]))
}

// SanitizeMarkerComponent maps an untrusted session id to a safe filename component,
// capped at 128 bytes.
func SanitizeMarkerComponent(s string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
	if len(safe) > 128 {
		safe = safe[:128]
	}
	return safe
}

// promptSecretWarning is the user-facing notice when a submitted prompt appears to contain a
// credential. Advisory: the prompt is swallowed and resubmitting proceeds. Names only the kind.
func promptSecretWarning(kind policy.SecretKind) string {
	return strings.Join([]string{
		fmt.Sprintf("⚠  corral: your prompt appears to contain %s — it was NOT sent.", kind),
		"   A secret typed into a prompt goes straight to the model provider. Remove or",
		"   pseudonymize it and resubmit. (To send this prompt anyway, just resubmit it.)",
	}, "\n")
}

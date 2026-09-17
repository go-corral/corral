package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// promptAWSKey is a format-valid AWS access key id (AKIA + 16 [0-9A-Z]) — a known-format
// secret the scanner always catches, without embedding a PEM block (which would make this
// file unreadable through corral's own Read gate).
const promptAWSKey = "AKIA" + "QQQQQQQQQQQQQQQQ"

// promptEvent builds a UserPromptSubmit hook event JSON with proper escaping.
func promptEvent(sessionID, prompt string) string {
	b, _ := json.Marshal(map[string]string{"session_id": sessionID, "prompt": prompt})
	return string(b)
}

// isolatePromptHook points the per-prompt marker ($TMPDIR) and the audit log
// (CLAUDE_CONFIG_DIR) at a throwaway dir so the test neither collides with real markers
// nor writes a real audit line. Sandboxed so the presence-warning path stays out of the way —
// the secret scan runs regardless of sandbox state.
func isolatePromptHook(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(sandbox.SandboxEnvVar, "1")
	t.Setenv("TMPDIR", dir)
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
}

// A prompt carrying a secret is swallowed with a warning that names the kind and the
// incident next step — and never echoes the secret value.
func TestUserPromptSubmitWarnsOnSecret(t *testing.T) {
	isolatePromptHook(t)

	var out strings.Builder
	code := runUserPromptSubmitHook(strings.NewReader(promptEvent("s1", "here is my key "+promptAWSKey)), &out)
	if code != 0 {
		t.Fatalf("the warning rides in JSON → exit 0, got %d", code)
	}
	for _, want := range []string{`"decision"`, `"block"`, "AWS access key id", "rotate/revoke"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("a secret-bearing prompt must warn (missing %q):\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), promptAWSKey) {
		t.Errorf("the warning must NOT echo the secret value:\n%s", out.String())
	}
}

// Warn-and-resubmit: resubmitting the same secret-bearing prompt proceeds silently (the
// false-positive escape hatch — the user is never locked out).
func TestUserPromptSubmitResubmitSameSecretProceeds(t *testing.T) {
	isolatePromptHook(t)
	ev := promptEvent("s1", "key "+promptAWSKey)

	var first strings.Builder
	if code := runUserPromptSubmitHook(strings.NewReader(ev), &first); code != 0 {
		t.Fatalf("first submit → exit 0, got %d", code)
	}
	if !strings.Contains(first.String(), `"block"`) {
		t.Fatalf("first submit must warn, got %q", first.String())
	}

	var second strings.Builder
	if code := runUserPromptSubmitHook(strings.NewReader(ev), &second); code != 0 {
		t.Errorf("resubmit must allow (exit 0), got %d", code)
	}
	if second.String() != "" {
		t.Errorf("resubmit of the SAME prompt must not warn again, got %q", second.String())
	}
}

// A different secret-bearing prompt warns again (its marker hash differs), so a real
// second leak is not silently suppressed by the first prompt's marker.
func TestUserPromptSubmitDifferentSecretWarnsAgain(t *testing.T) {
	isolatePromptHook(t)

	var first strings.Builder
	runUserPromptSubmitHook(strings.NewReader(promptEvent("s1", "key one "+promptAWSKey)), &first)
	if !strings.Contains(first.String(), `"block"`) {
		t.Fatalf("first must warn, got %q", first.String())
	}

	var second strings.Builder
	runUserPromptSubmitHook(strings.NewReader(promptEvent("s1", "key two "+promptAWSKey)), &second)
	if !strings.Contains(second.String(), `"block"`) {
		t.Errorf("a different secret-bearing prompt must warn again, got %q", second.String())
	}
}

// A clean prompt is never caught by the secret scan: sandboxed → falls through to silence.
func TestUserPromptSubmitCleanPromptNotFlagged(t *testing.T) {
	isolatePromptHook(t)

	var out strings.Builder
	if code := runUserPromptSubmitHook(strings.NewReader(promptEvent("s1", "please refactor the parser")), &out); code != 0 {
		t.Fatalf("clean sandboxed prompt → exit 0, got %d", code)
	}
	if out.String() != "" {
		t.Errorf("a clean prompt must not be flagged, got %q", out.String())
	}
}

// TestPresenceAckSilencesWarningButKeepsScan covers the warning-only acknowledgment. With it set on an
// unsandboxed session the presence warning is gone, no marker is written — but a
// secret-bearing prompt is still caught, because the scan runs before the ack is consulted.
func TestPresenceAckSilencesWarningButKeepsScan(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	t.Setenv(sandbox.SandboxEnvVar, "") // not sandboxed
	t.Setenv(sandbox.PresenceAckEnvVar, "1")

	// A clean prompt: silently allowed, and nothing is persisted for it.
	var clean strings.Builder
	if code := runUserPromptSubmitHook(strings.NewReader(promptEvent("ack1", "hello")), &clean); code != 0 {
		t.Fatalf("acked session must allow, got %d", code)
	}
	if s := clean.String(); s != "" {
		t.Errorf("acked session must emit no presence warning, got:\n%s", s)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("the ack path must write no marker, found %d entries", len(entries))
	}

	// The secret scan is untouched by the ack.
	var secret strings.Builder
	runUserPromptSubmitHook(strings.NewReader(promptEvent("ack2", "key "+promptAWSKey)), &secret)
	if !strings.Contains(secret.String(), "AWS access key id") {
		t.Errorf("the ack must NOT disable the prompt secret scan:\n%s", secret.String())
	}
	if strings.Contains(secret.String(), promptAWSKey) {
		t.Errorf("the warning must not echo the secret:\n%s", secret.String())
	}
}

// TestPresenceAckStrictValues: only 1/true silence the warning. A "0"/"false"/garbage value
// must not — reading those as "acknowledged" is the kind of surprise that leaves someone
// believing they are warned when they are not.
func TestPresenceAckStrictValues(t *testing.T) {
	for _, tc := range []struct {
		value      string
		wantWarned bool
	}{
		{"1", false}, {"true", false}, {"TRUE", false}, {" true ", false},
		{"0", true}, {"false", true}, {"yes", true}, {"", true},
	} {
		t.Run("value="+tc.value, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("TMPDIR", dir)
			t.Setenv("CLAUDE_CONFIG_DIR", dir)
			t.Setenv(sandbox.SandboxEnvVar, "")
			t.Setenv(sandbox.PresenceAckEnvVar, tc.value)

			var out strings.Builder
			runUserPromptSubmitHook(strings.NewReader(promptEvent("s", "hello")), &out)
			warned := strings.Contains(out.String(), "NOT sandboxed")
			if warned != tc.wantWarned {
				t.Errorf("value %q: warned=%v, want %v\n%s", tc.value, warned, tc.wantWarned, out.String())
			}
		})
	}
}

// TestHooksDisabledStandsDownOutsideSandboxOnly: the kill switch allows every event on a bare
// launch, and is ignored inside corral's own sandbox — the precedence that keeps it from ever
// becoming an in-sandbox enforcement switch.
func TestHooksDisabledStandsDownOutsideSandboxOnly(t *testing.T) {
	t.Run("bare launch disables the hooks", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("TMPDIR", dir)
		t.Setenv("CLAUDE_CONFIG_DIR", dir)
		t.Setenv(sandbox.SandboxEnvVar, "")
		t.Setenv(sandbox.DisableHooksEnvVar, "1")
		if !sandbox.HooksDisabled() {
			t.Fatal("HooksDisabled must be true for a bare launch with the switch on")
		}
	})
	t.Run("inside the sandbox the marker wins", func(t *testing.T) {
		t.Setenv(sandbox.SandboxEnvVar, "1")
		t.Setenv(sandbox.DisableHooksEnvVar, "1")
		if sandbox.HooksDisabled() {
			t.Error("the kill switch must be IGNORED inside corral's own sandbox")
		}
	})
	t.Run("strict values", func(t *testing.T) {
		t.Setenv(sandbox.SandboxEnvVar, "")
		for _, off := range []string{"0", "false", "yes", ""} {
			t.Setenv(sandbox.DisableHooksEnvVar, off)
			if sandbox.HooksDisabled() {
				t.Errorf("value %q must NOT disable the hooks", off)
			}
		}
		for _, on := range []string{"1", "true", "TRUE", " 1 "} {
			t.Setenv(sandbox.DisableHooksEnvVar, on)
			if !sandbox.HooksDisabled() {
				t.Errorf("value %q must disable the hooks", on)
			}
		}
	})
}

// TestHooksDisabledBlocksNothingAndAuditsOnce: cmdHook allows every event while the switch is
// on, and records exactly one audit line for the session (not one per tool call).
func TestHooksDisabledBlocksNothingAndAuditsOnce(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("CLAUDE_CONFIG_DIR", dir)
	t.Setenv("HOME", dir)
	t.Setenv(sandbox.SandboxEnvVar, "")
	t.Setenv(sandbox.DisableHooksEnvVar, "1")

	// Every event allows — including the ones that fail closed by default.
	for _, ev := range []string{"pre-tool-use", "post-tool-use", "session-start", "user-prompt-submit", "bogus-event"} {
		if code := cmdHook([]string{ev}); code != 0 {
			t.Errorf("event %q must allow while hooks are disabled, got %d", ev, code)
		}
	}

	// Exactly one "hooks-disabled" audit line for all of those invocations.
	var found int
	for _, e := range mustReadDirFiles(t, dir) {
		found += strings.Count(e, `"hooks-disabled"`)
	}
	if found != 1 {
		t.Errorf("want exactly 1 hooks-disabled audit line, got %d", found)
	}
}

// mustReadDirFiles returns the contents of every regular file directly under dir.
func mustReadDirFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, string(b))
	}
	return out
}

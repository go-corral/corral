package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
)

// The SessionStart hook is registered globally, so it also fires for a claude
// running outside the sandbox. It must stay silent there (no CORRAL_SANDBOX marker) rather than
// misinform an unsandboxed session that it is sandboxed.
func TestSessionStartHookSilentWhenUnsandboxed(t *testing.T) {
	t.Setenv(sandbox.SandboxEnvVar, "") // not sandboxed

	var buf strings.Builder
	code := runSessionStartHook(strings.NewReader(`{"hook_event_name":"SessionStart","source":"startup"}`), &buf)
	if code != 0 {
		t.Errorf("session-start must always allow (exit 0), got %d", code)
	}
	if buf.String() != "" {
		t.Errorf("unsandboxed session-start must emit nothing, got: %q", buf.String())
	}
}

// Inside the sandbox it injects a SessionStart additionalContext note. The note must
// name the masked secret dirs — the whole point is letting the model avoid wasting
// turns probing hidden paths.
func TestSessionStartHookInjectsNoteWhenSandboxed(t *testing.T) {
	t.Setenv(sandbox.SandboxEnvVar, "1")

	var buf strings.Builder
	code := runSessionStartHook(strings.NewReader(""), &buf)
	if code != 0 {
		t.Errorf("session-start must allow (exit 0), got %d", code)
	}
	out := buf.String()
	for _, want := range []string{`"hookEventName"`, "SessionStart", "additionalContext", "corral", "~/.ssh", "~/.gnupg", "~/.aws", "~/.kube", "~/.config/gcloud", "~/.azure"} {
		if !strings.Contains(out, want) {
			t.Errorf("sandboxed session-start note missing %q:\n%s", want, out)
		}
	}
}

// The note is short and factual. The macOS /tmp→$TMPDIR line rides the backend-notes channel,
// not the base note, so with no backend note supplied the base note carries no $TMPDIR line on
// any OS — sandboxSystemNote does not branch on runtime.GOOS.
func TestSandboxSystemNote(t *testing.T) {
	note := sandboxSystemNote("", "")
	for _, want := range []string{"corral", "~/.ssh", "~/.gnupg", "~/.aws", "~/.kube", "~/.config/gcloud", "~/.azure", "policy-checked"} {
		if !strings.Contains(note, want) {
			t.Errorf("sandbox note missing %q:\n%s", want, note)
		}
	}
	if strings.Contains(note, "$TMPDIR") {
		t.Errorf("base note must not include the backend /tmp line without a backend note:\n%s", note)
	}
}

// The base note redirects scratch files to a project-local scratchpad/: the harness's /tmp
// scratchpad path is unreachable (Linux fresh tmpfs) or invisible (macOS session $TMPDIR)
// inside the sandbox, so files meant for the user must land in the writable working dir. This
// bullet is backend-agnostic (no $TMPDIR / no runtime.GOOS branch), so it must be present on
// every OS with no backend note supplied.
func TestSandboxSystemNoteRedirectsScratchToWorkdir(t *testing.T) {
	note := sandboxSystemNote("", "")
	for _, want := range []string{"scratchpad/", "not /tmp"} {
		if !strings.Contains(note, want) {
			t.Errorf("base note missing scratch-file guidance %q:\n%s", want, note)
		}
	}
}

// A backend note (the launcher-set CORRAL_BACKEND_NOTES value) renders as a bullet, appended
// to the base note before any provider notes — the seatbelt backend's /tmp/$TMPDIR line rides
// this channel. Blank lines are dropped, exactly like the provider channel.
func TestSandboxSystemNoteAppendsBackendNotes(t *testing.T) {
	base := sandboxSystemNote("", "")
	note := sandboxSystemNote("/tmp is not accessible; use the directory named by $TMPDIR for temporary files.\n\n", "")
	if !strings.HasPrefix(note, base) {
		t.Errorf("backend notes must only append to the base note:\n%s", note)
	}
	if !strings.Contains(note, "\n- /tmp is not accessible; use the directory named by $TMPDIR for temporary files.") {
		t.Errorf("backend note must render as a bullet:\n%s", note)
	}
	if strings.Contains(note, "\n- \n") || strings.HasSuffix(note, "- ") {
		t.Errorf("blank note lines must be dropped:\n%s", note)
	}
}

// Backend notes come before provider notes: the environment quirk the model needs first, then
// the session's minted capabilities.
func TestSandboxSystemNoteBackendBeforeProvider(t *testing.T) {
	note := sandboxSystemNote("BACKEND-NOTE", "PROVIDER-NOTE")
	bi, pi := strings.Index(note, "BACKEND-NOTE"), strings.Index(note, "PROVIDER-NOTE")
	if bi < 0 || pi < 0 || bi > pi {
		t.Errorf("backend note must render before provider note:\n%s", note)
	}
}

// Provider notes (the launcher-set CORRAL_PROVIDER_NOTES value, one note per line) are
// appended to the note as extra bullets; blank lines are dropped. An empty value — no
// active provider contributed a note — appends nothing (covered above).
func TestSandboxSystemNoteAppendsProviderNotes(t *testing.T) {
	base := sandboxSystemNote("", "")
	note := sandboxSystemNote("", "GITLAB_TOKEN holds a scoped token (expires 2026-07-03)\n\n$HOME is sandbox-private\n")
	if !strings.HasPrefix(note, base) {
		t.Errorf("provider notes must only append to the base note:\n%s", note)
	}
	for _, want := range []string{
		"\n- GITLAB_TOKEN holds a scoped token (expires 2026-07-03)",
		"\n- $HOME is sandbox-private",
	} {
		if !strings.Contains(note, want) {
			t.Errorf("note missing provider bullet %q:\n%s", want, note)
		}
	}
	if strings.Contains(note, "\n- \n") || strings.HasSuffix(note, "- ") {
		t.Errorf("blank note lines must be dropped:\n%s", note)
	}
}

// The launcher pre-formats provider notes as "- <provider>: <note>" markdown bullets;
// the hook must pass those through, not double-bullet them.
func TestSandboxSystemNoteKeepsPreBulletedLines(t *testing.T) {
	note := sandboxSystemNote("", "- home: $HOME is sandbox-private\n- gitlab: GITLAB_TOKEN holds a scoped token")
	if !strings.Contains(note, "\n- home: $HOME is sandbox-private\n") {
		t.Errorf("pre-bulleted provider note must be appended verbatim:\n%s", note)
	}
	if strings.Contains(note, "- - ") {
		t.Errorf("pre-bulleted lines must not be double-bulleted:\n%s", note)
	}
}

// End-to-end through the hook: the session-start note carries the provider notes the
// launcher put into the sandbox env.
func TestSessionStartHookInjectsProviderNotes(t *testing.T) {
	t.Setenv(sandbox.SandboxEnvVar, "1")
	t.Setenv(sandbox.ProviderNotesEnvVar, "KUBECONFIG holds a minted ServiceAccount credential")

	var buf strings.Builder
	if code := runSessionStartHook(strings.NewReader(""), &buf); code != 0 {
		t.Errorf("session-start must allow (exit 0), got %d", code)
	}
	if !strings.Contains(buf.String(), "KUBECONFIG holds a minted ServiceAccount credential") {
		t.Errorf("session-start note missing the provider note:\n%s", buf.String())
	}
}

// End-to-end through the hook: the session-start note carries the backend note the launcher
// put into the sandbox env (the seatbelt backend's /tmp/$TMPDIR line rides CORRAL_BACKEND_NOTES).
func TestSessionStartHookInjectsBackendNotes(t *testing.T) {
	t.Setenv(sandbox.SandboxEnvVar, "1")
	t.Setenv(sandbox.BackendNotesEnvVar, "/tmp is not accessible; use the directory named by $TMPDIR for temporary files.")

	var buf strings.Builder
	if code := runSessionStartHook(strings.NewReader(""), &buf); code != 0 {
		t.Errorf("session-start must allow (exit 0), got %d", code)
	}
	if !strings.Contains(buf.String(), "$TMPDIR") {
		t.Errorf("session-start note missing the backend note:\n%s", buf.String())
	}
}

// Inside the sandbox, the presence warning stays silent — there is nothing to warn about.
func TestUserPromptSubmitSilentWhenSandboxed(t *testing.T) {
	t.Setenv(sandbox.SandboxEnvVar, "1") // sandboxed

	var buf strings.Builder
	if code := runUserPromptSubmitHook(strings.NewReader(`{"session_id":"s1","prompt":"hi"}`), &buf); code != 0 {
		t.Errorf("sandboxed → allow (exit 0), got %d", code)
	}
	if buf.String() != "" {
		t.Errorf("sandboxed → no warning, got %q", buf.String())
	}
}

// When not sandboxed, the first prompt of a session is swallowed with a bright warning; a later
// prompt in the same session proceeds (resubmit-once via the per-session marker).
func TestUserPromptSubmitWarnsOnceWhenUnsandboxed(t *testing.T) {
	t.Setenv(sandbox.SandboxEnvVar, "") // not sandboxed
	t.Setenv("TMPDIR", t.TempDir())     // isolate the per-session marker
	event := `{"session_id":"sess-abc","prompt":"do a thing"}`

	var first strings.Builder
	if code := runUserPromptSubmitHook(strings.NewReader(event), &first); code != 0 {
		t.Errorf("the warning rides in JSON → exit 0, got %d", code)
	}
	for _, want := range []string{`"decision"`, `"block"`, "NOT sandboxed", "corral run"} {
		if !strings.Contains(first.String(), want) {
			t.Errorf("first unsandboxed prompt must warn (missing %q):\n%s", want, first.String())
		}
	}

	// Same session, second prompt → marker present → proceed silently.
	var second strings.Builder
	if code := runUserPromptSubmitHook(strings.NewReader(event), &second); code != 0 {
		t.Errorf("resubmit must allow (exit 0), got %d", code)
	}
	if second.String() != "" {
		t.Errorf("resubmit must not warn again, got %q", second.String())
	}

	// A different session warns again (independent marker).
	var other strings.Builder
	_ = runUserPromptSubmitHook(strings.NewReader(`{"session_id":"sess-xyz"}`), &other)
	if !strings.Contains(other.String(), `"block"`) {
		t.Errorf("a new session must warn again, got %q", other.String())
	}
}

func TestHookBlocksConfiguredPath(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// Config blocks /data/vault — a path outside the always-blocked floor, so this proves
	// config-driven blocking, not the built-in floor.
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte("providers: {block: {directories: [/data/vault]}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	withStdin(t, preToolUseEvent(t, proj, "/data/vault/creds"), func() {
		code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
	})
	if code != policy.ExitBlock {
		t.Errorf("config-driven blocked path not enforced: code=%d", code)
	}
	// A path outside any blocked dir is allowed.
	withStdin(t, preToolUseEvent(t, proj, filepath.Join(proj, "ok.txt")), func() {
		code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
	})
	if code != policy.ExitAllow {
		t.Errorf("non-blocked path should allow: code=%d", code)
	}
}

func TestHookMalformedConfigFailsClosed(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// Malformed YAML (unclosed list) must make the hook fail closed, not allow.
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte("providers:\n  block: {directories: [/data/vault\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	withStdin(t, preToolUseEvent(t, proj, filepath.Join(proj, "anything")), func() {
		code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
	})
	if code != policy.ExitBlock {
		t.Errorf("malformed config must fail closed: got %d, want %d", code, policy.ExitBlock)
	}
}

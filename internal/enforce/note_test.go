package enforce

import (
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
)

// The note is short and factual. The macOS /tmp→$TMPDIR line rides the backend-notes channel,
// not the base note, so with no backend note supplied the base note carries no $TMPDIR line.
func TestSystemNote(t *testing.T) {
	note := SystemNote("linux", "1.2.3", "", "")
	if first, _, _ := strings.Cut(note, "\n"); !strings.Contains(first, "corral 1.2.3") {
		t.Errorf("first line must name the version: %q", first)
	}
	for _, p := range config.AlwaysBlockedPaths {
		if !strings.Contains(note, "`"+p+"`") {
			t.Errorf("note missing always-blocked %q:\n%s", p, note)
		}
	}
	for _, want := range []string{"No setting can open them", "`os`", "`hook`", "[hook:<rule>]", "checks your own tool calls", "not what the started processes do", "propose the named fix", "propose a `providers.paths.ro` grant to read or a `providers.paths.rw` grant to write", "output withheld by corral policy [hook:<rule>]", "In Claude Code, `dangerouslyDisableSandbox` removes only its own per-command sandbox"} {
		if !strings.Contains(note, want) {
			t.Errorf("note missing %q:\n%s", want, note)
		}
	}
	if strings.Contains(note, "$TMPDIR") {
		t.Errorf("base note must not include the backend /tmp line without a backend note:\n%s", note)
	}
}

// A silent sandbox deny reads differently on each platform, and the note names only the local form.
func TestSystemNoteSilentDenyPerPlatform(t *testing.T) {
	linux := []string{"No such file or directory", "File content masked by corral", "Read-only file system", "sandbox-private storage"}
	darwin := []string{"Operation not permitted"}
	for goos, tc := range map[string]struct{ want, not []string }{
		"linux":  {linux, darwin},
		"darwin": {darwin, linux},
	} {
		note := SystemNote(goos, "dev", "", "")
		for _, s := range tc.want {
			if !strings.Contains(note, s) {
				t.Errorf("%s: note must name %q:\n%s", goos, s, note)
			}
		}
		for _, s := range tc.not {
			if strings.Contains(note, s) {
				t.Errorf("%s: note must not name %q:\n%s", goos, s, note)
			}
		}
	}
}

// The base note redirects scratch files to a project-local scratchpad/: the harness's /tmp
// scratchpad path is unreachable (Linux fresh tmpfs) or invisible (macOS session $TMPDIR)
// inside the sandbox, so files meant for the user must land in the writable working dir. This
// bullet is backend-agnostic (no $TMPDIR / no runtime.GOOS branch), so it must be present on
// every OS with no backend note supplied.
func TestSystemNoteRedirectsScratchToWorkdir(t *testing.T) {
	note := SystemNote("linux", "dev", "", "")
	for _, want := range []string{"scratchpad/", "not /tmp"} {
		if !strings.Contains(note, want) {
			t.Errorf("base note missing scratch-file guidance %q:\n%s", want, note)
		}
	}
}

// A backend note (the launcher-set CORRAL_BACKEND_NOTES value) renders as a bullet, appended
// to the base note before any provider notes — the seatbelt backend's /tmp/$TMPDIR line rides
// this channel. Blank lines are dropped, exactly like the provider channel.
func TestSystemNoteAppendsBackendNotes(t *testing.T) {
	base := SystemNote("linux", "dev", "", "")
	note := SystemNote("linux", "dev", "/tmp is not accessible; use the directory named by $TMPDIR for temporary files.\n\n", "")
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
func TestSystemNoteBackendBeforeProvider(t *testing.T) {
	note := SystemNote("linux", "dev", "BACKEND-NOTE", "PROVIDER-NOTE")
	bi, pi := strings.Index(note, "BACKEND-NOTE"), strings.Index(note, "PROVIDER-NOTE")
	if bi < 0 || pi < 0 || bi > pi {
		t.Errorf("backend note must render before provider note:\n%s", note)
	}
}

// Provider notes (the launcher-set CORRAL_PROVIDER_NOTES value, one note per line) are
// appended to the note as extra bullets; blank lines are dropped. An empty value — no
// active provider contributed a note — appends nothing (covered above).
func TestSystemNoteAppendsProviderNotes(t *testing.T) {
	base := SystemNote("linux", "dev", "", "")
	note := SystemNote("linux", "dev", "", "GITLAB_TOKEN holds a scoped token (expires 2026-07-03)\n\n$HOME is sandbox-private\n")
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
func TestSystemNoteKeepsPreBulletedLines(t *testing.T) {
	note := SystemNote("linux", "dev", "", "- home: $HOME is sandbox-private\n- gitlab: GITLAB_TOKEN holds a scoped token")
	if !strings.Contains(note, "\n- home: $HOME is sandbox-private\n") {
		t.Errorf("pre-bulleted provider note must be appended verbatim:\n%s", note)
	}
	if strings.Contains(note, "- - ") {
		t.Errorf("pre-bulleted lines must not be double-bulleted:\n%s", note)
	}
}

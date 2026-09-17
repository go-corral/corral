package claude

import (
	"os"
	"path/filepath"
	"testing"
)

// claudeTUIMode reads the "tui" key from settings.json and fails safe (empty) on a
// missing/unset/unparseable value.
func TestClaudeTUIMode(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	cases := []struct {
		name string
		path string
		want string
	}{
		{"explicit default", write("default.json", `{"tui":"default"}`), "default"},
		{"explicit fullscreen", write("full.json", `{"tui":"fullscreen"}`), "fullscreen"},
		{"key absent", write("absent.json", `{"theme":"dark"}`), ""},
		{"malformed json", write("bad.json", `{not json`), ""},
		{"missing file", filepath.Join(dir, "nope.json"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := claudeTUIMode(tc.path); got != tc.want {
				t.Errorf("claudeTUIMode = %q, want %q", got, tc.want)
			}
		})
	}
}

// fullscreenBannerWarning warns (and thereby gates the launch) for every TUI value except an
// explicit "default" — including unset and unreadable, which must err toward warning so the
// banner is never silently lost behind the alternate screen.
func TestFullscreenBannerWarning(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Only an explicit "default" is banner-safe → no warning.
	if w := fullscreenBannerWarning(write("default.json", `{"tui":"default"}`)); len(w) != 0 {
		t.Errorf("tui=default must not warn, got %v", w)
	}

	// Everything else warns — err toward showing the notice.
	for _, tc := range []struct {
		name, path string
	}{
		{"fullscreen", write("full.json", `{"tui":"fullscreen"}`)},
		{"unset", write("unset.json", `{}`)},
		{"missing file", filepath.Join(dir, "nope.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := fullscreenBannerWarning(tc.path)
			if len(w) != 1 {
				t.Fatalf("expected exactly one warning, got %v", w)
			}
			if w[0] == "" {
				t.Error("warning text must be non-empty")
			}
		})
	}
}

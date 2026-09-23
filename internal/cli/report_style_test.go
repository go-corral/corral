package cli

import (
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
)

func TestWriteStyledGrantSection(t *testing.T) {
	var out strings.Builder
	writeGrantSection(&out, report.NewStyle(true, false), "Extra read-only", []string{
		"/srv/projects", "/srv/projects/example", "/srv/reference/a\x1b[22m",
	}, "/home/user")
	want := "\n  Extra read-only · 3 grants · \x1b[2m[grant] marks configured paths\x1b[0m\n" +
		"    \x1b[2m/srv/\x1b[0m\n" +
		"    ├── \x1b[1mprojects\x1b[0m  [grant]\n" +
		"    │   └── \x1b[1mexample\x1b[0m  [grant]\n" +
		"    └── \x1b[1m\"reference/a\\x1b[22m\"\x1b[0m  [grant]\n"
	if out.String() != want {
		t.Errorf("styled grants = %q, want %q", out.String(), want)
	}
}

func TestWriteGrantSectionWithoutStyling(t *testing.T) {
	var out strings.Builder
	writeGrantSection(&out, report.NewStyle(false, false), "Extra read-only", []string{
		"/srv/projects", "/srv/projects/example", "/srv/reference/handbook",
	}, "/home/user")
	want := "\n  Extra read-only · 3 grants · [grant] marks configured paths\n" +
		"    /srv/\n" +
		"    ├── projects  [grant]\n" +
		"    │   └── example  [grant]\n" +
		"    └── reference/handbook  [grant]\n"
	if out.String() != want {
		t.Errorf("plain grants = %q, want %q", out.String(), want)
	}
}

func TestWriteReportHeading(t *testing.T) {
	for _, tt := range []struct {
		styled bool
		want   string
	}{
		{true, "\n\x1b[1mFilesystem\x1b[0m\n"},
		{false, "\nFilesystem\n"},
	} {
		var out strings.Builder
		writeReportHeading(&out, report.NewStyle(tt.styled, false), "Filesystem")
		if out.String() != tt.want {
			t.Errorf("styled=%t: heading = %q, want %q", tt.styled, out.String(), tt.want)
		}
	}
}

// Captured stdout is a pipe, so this exercises the redirected case only; the env switches are
// covered by TestResolveColor in the report package.
func TestValidatePlainOutputWhenRedirected(t *testing.T) {
	trustRepo(t, "providers:\n  paths:\n    ro: [~/docs, ~/docs/reference, ~/code]\n")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	out := captureStdout(t, func() { cmdValidate(nil) })
	if strings.Contains(out, "\x1b") {
		t.Errorf("redirected output contains ANSI escapes:\n%q", out)
	}
	if strings.Count(out, "  [grant]\n") != 3 || !strings.Contains(out, "[grant] marks configured paths") {
		t.Errorf("plain output lost grant attribution:\n%s", out)
	}
}

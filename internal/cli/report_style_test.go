package cli

import (
	"strings"
	"testing"
)

// Captured stdout is a pipe, so this exercises the redirected case only; the env switches are
// covered by TestResolveColor in the report package.
func TestValidatePlainOutputWhenRedirected(t *testing.T) {
	trustRepo(t, "providers:\n  paths:\n    ro: [~/docs, ~/docs/reference, ~/code]\n")
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	out := captureStdout(t, func() { cmdValidate(nil, "test") })
	if strings.Contains(out, "\x1b") {
		t.Errorf("redirected output contains ANSI escapes:\n%q", out)
	}
	if strings.Count(out, "ro   providers.paths.ro\n") != 3 {
		t.Errorf("plain output lost grant attribution:\n%s", out)
	}
}

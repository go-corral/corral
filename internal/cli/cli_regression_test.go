package cli

import (
	"flag"
	"strings"
	"testing"
)

// An unknown command prints usage to stderr and returns exit code 2.
func TestMainDispatchUnknownCommand(t *testing.T) {
	errOut := captureStderr(t, func() {
		code := Main([]string{"badcmd"}, "test-version")
		if code != 2 {
			t.Errorf("unknown cmd: got exit code %d, want 2", code)
		}
	})

	if !strings.Contains(errOut, "unknown command") || !strings.Contains(errOut, "badcmd") {
		t.Errorf("stderr must contain 'unknown command' and command name, got: %q", errOut)
	}
	if !strings.Contains(errOut, "Usage:") {
		t.Errorf("stderr must contain usage, got: %q", errOut)
	}
}

// No arguments prints usage to stdout and returns exit code 0.
func TestMainNoArgs(t *testing.T) {
	usage := captureStdout(t, func() {
		code := Main([]string{}, "test-version")
		if code != 0 {
			t.Errorf("no args: got exit code %d, want 0", code)
		}
	})

	if !strings.Contains(usage, "Usage:") || !strings.Contains(usage, "corral") {
		t.Errorf("stdout must contain usage, got: %q", usage)
	}
}

// A bad flag returns (2, false).
func TestParseFlagsError(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	code, ok := parseFlags(fs, []string{"-badflg"})
	if code != 2 {
		t.Errorf("bad flag: got code %d, want 2", code)
	}
	if ok {
		t.Errorf("bad flag: got ok=true, want false (should not proceed)")
	}
}

// The -h flag returns (0, false): the caller stops at 0, not 2.
func TestParseFlagsHelp(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	code, ok := parseFlags(fs, []string{"-h"})
	if code != 0 {
		t.Errorf("help flag: got code %d, want 0", code)
	}
	if ok {
		t.Errorf("help flag: got ok=true, want false (caller stops at 0, not 2)")
	}
}

// A subcommand -h returns 0 via parseFlags → flag.ErrHelp.
func TestMainSubcommandHelpFlag(t *testing.T) {
	_ = captureStderr(t, func() {
		code := Main([]string{"run", "-h"}, "test-version")
		if code != 0 {
			t.Errorf("run -h: got exit code %d, want 0 (flag.ErrHelp)", code)
		}
	})
}

// TestParseFlagsValidArgs: valid args return (0, true) so caller proceeds
func TestParseFlagsValidArgs(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("foo", "", "test flag")

	code, ok := parseFlags(fs, []string{"-foo", "bar"})
	if code != 0 || !ok {
		t.Errorf("valid args: got (%d, %v), want (0, true)", code, ok)
	}
}

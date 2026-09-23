package cli

import (
	"flag"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
)

// An unknown command prints usage to stderr and returns exit code 2.
func TestMainDispatchUnknownCommand(t *testing.T) {
	errOut := captureStderr(t, func() {
		code := Main([]string{"badcmd"}, "test-version")
		if code != 2 {
			t.Errorf("unknown cmd: got exit code %d, want 2", code)
		}
	})

	if !strings.Contains(errOut, `✗ unknown command "badcmd"`) {
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

func TestWriteUsage(t *testing.T) {
	var unicode, ascii strings.Builder
	writeUsage(&unicode, report.NewStyle(false, false))
	writeUsage(&ascii, report.NewStyle(false, true))
	want := "corral   sandbox claude or pi and enforce policy on their tool calls\n" +
		"\n" +
		"Usage: corral <command> [flags]\n" +
		"\n" +
		"commands ─────────────────────────────────────────────────────────\n" +
		"    run             Launch the configured agent inside the sandbox\n" +
		"    hook            Hook enforcer (invoked by Claude Code; reads JSON on stdin)\n" +
		"    sync            Register corral's hooks with an agent; --remove undoes it\n" +
		"    gc              Preview and reap provider resources of crashed sessions\n" +
		"    validate        Check the config and show the policy the sandbox enforces\n" +
		"    doctor          Check that this host can run corral and is wired up\n" +
		"    update          Check for and install a newer corral release in place\n" +
		"    uninstall       Show corral's on-system footprint; --apply removes it\n" +
		"                    binary and config stay\n" +
		"    version         Print the version\n" +
		"\n" +
		"Run \"corral <command> -h\" for command-specific flags.\n"
	if unicode.String() != want {
		t.Errorf("usage:\n%s\nwant:\n%s", unicode.String(), want)
	}
	wantASCII := "corral   sandbox claude or pi and enforce policy on their tool calls\n" +
		"\n" +
		"Usage: corral <command> [flags]\n" +
		"\n" +
		"commands ---------------------------------------------------------\n" +
		"     run            Launch the configured agent inside the sandbox\n" +
		"     hook           Hook enforcer (invoked by Claude Code; reads JSON on stdin)\n" +
		"     sync           Register corral's hooks with an agent; --remove undoes it\n" +
		"     gc             Preview and reap provider resources of crashed sessions\n" +
		"     validate       Check the config and show the policy the sandbox enforces\n" +
		"     doctor         Check that this host can run corral and is wired up\n" +
		"     update         Check for and install a newer corral release in place\n" +
		"     uninstall      Show corral's on-system footprint; --apply removes it\n" +
		"                    binary and config stay\n" +
		"     version        Print the version\n" +
		"\n" +
		"Run \"corral <command> -h\" for command-specific flags.\n"
	if ascii.String() != wantASCII {
		t.Errorf("ASCII usage:\n%s\nwant:\n%s", ascii.String(), wantASCII)
	}
	for _, ln := range strings.Split(unicode.String(), "\n") {
		if n := len([]rune(ln)); n > report.LineMax {
			t.Errorf("line is %d columns, want at most %d: %q", n, report.LineMax, ln)
		}
	}
}

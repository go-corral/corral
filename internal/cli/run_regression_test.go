package cli

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// An empty string is single-quoted to the empty word (two apostrophes).
func TestShellQuoteEmptyString(t *testing.T) {
	result := shellQuote([]string{""})
	if result != "''" {
		t.Errorf("empty string: got %q, want ''", result)
	}
}

// Special chars are safely quoted. shellQuote delegates to
// mvdan.cc/sh/v3/syntax.Quote (LangBash), which minimally quotes — a word that needs no
// quoting comes back bare, and it picks single vs. double vs. $'...' quoting per input —
// so these are exact expected outputs from that quoter, not just "contains a quote".
func TestShellQuoteSpecialChars(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"pipe", []string{"echo|cat"}, "'echo|cat'"},
		{"redirect", []string{"echo > file"}, "'echo > file'"},
		{"glob", []string{"*.txt"}, "'*.txt'"},
		{"backtick", []string{"`cmd`"}, "'`cmd`'"},
		{"backslash", []string{"path\\to\\file"}, "'path\\to\\file'"},
		{"mixed", []string{"$HOME/file"}, "'$HOME/file'"},
		{"space", []string{"hello world"}, "'hello world'"},
		{"single-quote", []string{"it's"}, `"it's"`},  // minimal quoting: double quotes need no escaping here
		{"plain", []string{"plainword"}, "plainword"}, // no special chars: rendered bare, no quoting at all
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := shellQuote(c.argv)
			if result != c.want {
				t.Errorf("shellQuote(%q) = %q, want %q", c.argv[0], result, c.want)
			}
		})
	}
}

// A control character in argv (e.g. a bare \r smuggled in via a hook/env value) must render
// quoted, not leak unquoted into the copy-pasteable command. mvdan's LangBash quoting renders
// these as $'...' ANSI-C escapes, covering \r, \v, \f and friends.
func TestShellQuoteControlChars(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want string
	}{
		{"carriage-return", []string{"with\rcr"}, `$'with\rcr'`},
		{"vertical-tab", []string{"with\vvt"}, `$'with\vvt'`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			result := shellQuote(c.argv)
			if result != c.want {
				t.Errorf("shellQuote(%q) = %q, want %q", c.argv[0], result, c.want)
			}
			// The regression this guards against: the control char must never appear
			// unescaped/unquoted in the output.
			if strings.ContainsAny(result, "\r\v") {
				t.Errorf("shellQuote(%q) = %q still contains a raw control byte", c.argv[0], result)
			}
		})
	}
}

// An exec.ExitError with a non-zero status returns the child's code.
func TestExitCodeNonzero(t *testing.T) {
	// Test the actual exitCode by running a subprocess that exits with various codes.
	for _, want := range []int{0, 1, 5, 42} {
		t.Run(fmt.Sprintf("exit_%d", want), func(t *testing.T) {
			cmd := exec.Command("sh", "-c", fmt.Sprintf("exit %d", want))
			err := cmd.Run()
			code := exitCode(err)
			if code != want {
				t.Errorf("exit %d: got code %d, want %d", want, code, want)
			}
		})
	}
}

// An exec.ExitError from a signal returns 128 + signal number.
func TestExitCodeSignalMapping(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping signal test in short mode")
	}
	// This test sends actual signals, which may not work in all environments.
	// Use sh -c 'kill -TERM $$' to send SIGTERM to the process
	cmd := exec.Command("sh", "-c", "kill -TERM $$")
	err := cmd.Run()
	code := exitCode(err)
	// SIGTERM is signal 15, so we expect 128 + 15 = 143
	expectedCode := 128 + 15
	if code != expectedCode {
		t.Errorf("SIGTERM: got code %d, want %d (128 + 15)", code, expectedCode)
	}
}

// waitStatus is the single place the child's exit code and the signaled flag are derived
// (the SessionExit runSupervised hands post-session hooks). Assert both halves for the
// three cases: clean exit, non-zero exit, and signal kill — the code half must still match
// exitCode's long-standing contract.
func TestWaitStatusDerivesCodeAndSignaled(t *testing.T) {
	if code, sig := waitStatus(nil); code != 0 || sig {
		t.Errorf("waitStatus(nil) = (%d,%v), want (0,false)", code, sig)
	}
	for _, want := range []int{1, 5, 42} {
		err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", want)).Run()
		if code, sig := waitStatus(err); code != want || sig {
			t.Errorf("waitStatus(exit %d) = (%d,%v), want (%d,false)", want, code, sig, want)
		}
	}
	if testing.Short() {
		t.Skip("skipping the signal half in short mode")
	}
	err := exec.Command("sh", "-c", "kill -TERM $$").Run()
	if code, sig := waitStatus(err); code != 128+15 || !sig {
		t.Errorf("waitStatus(SIGTERM) = (%d,%v), want (143,true)", code, sig)
	}
}

// A second angle on the non-zero-status exit code, tested directly.
func TestExitCodeLogic(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		want    int
		comment string
	}{
		{"nil error", nil, 0, "no error = exit 0"},
		{"non-ExitError", errors.New("other"), 1, "non-ExitError gets fatalf'd, returns 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "non-ExitError" {
				// This path calls fatalf which writes to os.Stderr and returns 1
				// Capture stderr to verify fatalf was called with the correct format.
				stderr := captureStderr(t, func() {
					code := exitCode(c.err)
					if code != 1 {
						t.Errorf("non-ExitError: got code %d, want 1", code)
					}
				})
				if !strings.Contains(stderr, "✗ sandbox wait:") {
					t.Errorf("fatalf must be called with 'sandbox wait:' message, got: %q", stderr)
				}
				if !strings.Contains(stderr, "other") {
					t.Errorf("fatalf stderr must contain error message 'other', got: %q", stderr)
				}
			} else {
				code := exitCode(c.err)
				if code != c.want {
					t.Errorf("%s: got code %d, want %d (%s)", c.name, code, c.want, c.comment)
				}
			}
		})
	}
}

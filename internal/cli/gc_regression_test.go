package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A config load error returns non-zero via fatalf.
func TestCmdGCConfigLoadError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create a project with an invalid config file
	projDir := filepath.Join(home, "proj")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(projDir)

	// Write an invalid config file (YAML syntax error)
	configFile := filepath.Join(projDir, ".corral.yml")
	if err := os.WriteFile(configFile, []byte("invalid: yaml: [syntax"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Capture stderr to verify error message
	errOut := captureStderr(t, func() {
		code := cmdGC([]string{})
		if code == 0 {
			t.Errorf("cmdGC with invalid config: got exit code 0, want non-zero")
		}
	})

	if !strings.Contains(errOut, "✗ load config:") {
		t.Errorf("cmdGC error must be reported via fatalf, got stderr: %q", errOut)
	}
}

// An os.UserHomeDir failure returns non-zero.
func TestCmdGCHomeLookupError(t *testing.T) {
	// os.UserHomeDir errors on unix when HOME is empty; t.Setenv restores it afterward.
	t.Setenv("HOME", "")

	// Capture stderr
	errOut := captureStderr(t, func() {
		code := cmdGC([]string{})
		if code == 0 {
			t.Errorf("cmdGC with no HOME: got exit code 0, want non-zero")
		}
	})

	// The actual error message includes the full resolved error
	if !strings.Contains(errOut, "cannot resolve") || !strings.Contains(errOut, "home") {
		t.Logf("error message: %q", errOut)
		// Accept various forms of "home resolution failed"
		if !strings.Contains(errOut, "resolve home") && !strings.Contains(errOut, "HOME") {
			t.Errorf("error should mention home resolution, got: %q", errOut)
		}
	}
}

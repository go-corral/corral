package spec

import (
	"os"
	"path/filepath"
	"testing"
)

// TestBinDir covers the binary-dir resolution feeding the macOS token: empty/relative paths
// yield "" so the optional token is skipped, and a symlinked absolute path is canonicalized.
func TestBinDir(t *testing.T) {
	for _, bin := range []string{"", "claude", "./bin/claude", "bin/claude"} {
		if got := BinDir(bin); got != "" {
			t.Errorf("BinDir(%q) = %q, want \"\" (empty/relative path emits no token)", bin, got)
		}
	}

	// Symlinked absolute binary: canonicalized to the real dir. On macOS t.TempDir() lives
	// under /var (a firmlink to /private/var), so resolve the expectation the same way; on
	// Linux EvalSymlinks is a no-op.
	tmp := t.TempDir()
	real := filepath.Join(tmp, "real-claude")
	if err := os.WriteFile(real, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(tmp, "claude-symlink")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if got := BinDir(link); got != want {
		t.Errorf("BinDir(symlink) = %q, want %q", got, want)
	}
	if got := BinDir(real); got != want {
		t.Errorf("BinDir(absolute) = %q, want %q", got, want)
	}
}

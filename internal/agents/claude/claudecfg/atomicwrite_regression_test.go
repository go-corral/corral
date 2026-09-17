package claudecfg

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAtomicWriteCreateTempFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses filesystem permission checks")
	}
	readOnlyDir := t.TempDir()
	target := filepath.Join(readOnlyDir, "target.json")
	data := []byte("test data")

	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatalf("failed to chmod temp dir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(readOnlyDir, 0o755) // restore for cleanup
	})

	err := atomicWrite(target, data, 0o644)
	if err == nil {
		t.Fatal("expected error from atomicWrite when CreateTemp fails")
	}

	_, statErr := os.Stat(target)
	if !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("target file should not exist after CreateTemp failure, got: %v", statErr)
	}

	// No temp files should be left behind.
	entries, _ := os.ReadDir(readOnlyDir)
	for _, e := range entries {
		if e.Name() != "." && e.Name() != ".." {
			t.Errorf("unexpected file left behind: %s", e.Name())
		}
	}
}

func TestAtomicWriteWriteFails(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target.json")
	data := []byte("test data")

	originalData := []byte("original content")
	if err := os.WriteFile(target, originalData, 0o644); err != nil {
		t.Fatalf("failed to create initial target: %v", err)
	}

	// A directory target forces Rename to fail after the temporary file is written.
	targetAsDir := filepath.Join(targetDir, "target-as-dir")
	if err := os.MkdirAll(targetAsDir, 0o755); err != nil {
		t.Fatalf("failed to create target as dir: %v", err)
	}

	err := atomicWrite(targetAsDir, data, 0o644)
	if err == nil {
		t.Fatal("expected error from atomicWrite when target is a directory")
	}

	info, statErr := os.Stat(targetAsDir)
	if statErr != nil {
		t.Errorf("target dir should still exist, got stat error: %v", statErr)
	}
	if !info.IsDir() {
		t.Errorf("target should still be a directory")
	}

	// Verify no temp files are left behind in the parent directory.
	entries, _ := os.ReadDir(targetDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".corral-settings-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file not cleaned up: %s", e.Name())
		}
	}
}

func TestAtomicWriteSyncSucceeds(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target.json")
	data := []byte("test content that should be synced")

	err := atomicWrite(target, data, 0o644)
	if err != nil {
		t.Fatalf("atomicWrite failed: %v", err)
	}

	written, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("failed to read written file: %v", err)
	}
	if string(written) != string(data) {
		t.Errorf("file content mismatch: got %q, want %q", written, data)
	}

	info, _ := os.Stat(target)
	if info.Mode()&0o644 != 0o644 {
		t.Errorf("file permissions not set correctly: got %o, want 0o644", info.Mode())
	}

	// No temp files should be left behind.
	entries, _ := os.ReadDir(targetDir)
	if len(entries) != 1 {
		t.Errorf("unexpected extra files in target dir: got %d entries, want 1", len(entries))
	}
}

func TestAtomicWriteRenameSucceeds(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target.json")

	for i := 0; i < 3; i++ {
		iterStr := string(rune('0' + i))
		updatedData := []byte("iteration " + iterStr + " content")
		if err := atomicWrite(target, updatedData, 0o644); err != nil {
			t.Fatalf("iteration %d: atomicWrite failed: %v", i, err)
		}

		written, err := os.ReadFile(target)
		if err != nil {
			t.Errorf("iteration %d: failed to read file: %v", i, err)
			continue
		}
		if string(written) != string(updatedData) {
			t.Errorf("iteration %d: content mismatch after atomic write; got %q, want %q",
				i, written, updatedData)
		}
	}
}

// TestAtomicWriteRenameFails covers cleanup and error propagation after a rename failure.
func TestAtomicWriteRenameFails(t *testing.T) {
	targetDir := t.TempDir()
	// A directory target forces Rename to fail.
	targetPath := filepath.Join(targetDir, "target.json")
	if err := os.Mkdir(targetPath, 0o755); err != nil {
		t.Fatalf("failed to create target directory: %v", err)
	}

	data := []byte("test data that will fail to rename")

	err := atomicWrite(targetPath, data, 0o644)
	if err == nil {
		t.Fatal("expected error from atomicWrite when target is a directory")
	}

	info, statErr := os.Stat(targetPath)
	if statErr != nil {
		t.Errorf("target should still exist, got stat error: %v", statErr)
	}
	if !info.IsDir() {
		t.Errorf("target should still be a directory after failed Rename")
	}

	// Verify no temp files are left behind.
	entries, _ := os.ReadDir(targetDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".corral-settings-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file not cleaned up after Rename failure: %s", e.Name())
		}
	}
}

func TestAtomicWriteCleansTempOnSuccess(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target.json")
	data := []byte("test data")

	if err := atomicWrite(target, data, 0o644); err != nil {
		t.Fatalf("atomicWrite failed: %v", err)
	}

	entries, _ := os.ReadDir(targetDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".corral-settings-") && strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("temp file not cleaned up after successful write: %s", e.Name())
		}
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 file in target dir, got %d", len(entries))
	}
}

func TestAtomicWriteCleansTempOnFailure(t *testing.T) {
	targetDir := t.TempDir()
	targetPath := filepath.Join(targetDir, "target.json")
	if err := os.Mkdir(targetPath, 0o755); err != nil {
		t.Fatalf("failed to create target directory: %v", err)
	}

	data := []byte("test data")

	err := atomicWrite(targetPath, data, 0o644)
	if err == nil {
		t.Fatal("expected error from atomicWrite")
	}

	// Verify no temp files are left behind in the parent directory.
	entries, _ := os.ReadDir(targetDir)
	tempCount := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".corral-settings-") && strings.HasSuffix(e.Name(), ".tmp") {
			tempCount++
			t.Errorf("temp file not cleaned up after error: %s", e.Name())
		}
	}
	if tempCount > 0 {
		t.Errorf("found %d uncleaned temp files", tempCount)
	}
}

func TestAtomicWritePermissions(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target.json")
	data := []byte("test")

	err := atomicWrite(target, data, 0o600)
	if err != nil {
		t.Fatalf("atomicWrite failed: %v", err)
	}

	info, _ := os.Stat(target)
	if info.Mode()&0o600 != 0o600 {
		t.Errorf("file permissions: got %o, want at least 0o600", info.Mode()&0o777)
	}
}

// TestAtomicWritePreservesExistingMode ensures perm applies only to new files.
func TestAtomicWritePreservesExistingMode(t *testing.T) {
	targetDir := t.TempDir()
	target := filepath.Join(targetDir, "target.json")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := atomicWrite(target, []byte("new"), 0o644); err != nil {
		t.Fatalf("atomicWrite failed: %v", err)
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("existing file mode not preserved: got %o, want 0600", got)
	}
	if data, _ := os.ReadFile(target); string(data) != "new" {
		t.Errorf("content not replaced: %q", data)
	}
}

// TestAtomicWriteFollowsSymlink ensures updates preserve the link and replace its target.
func TestAtomicWriteFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(real, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	if err := atomicWrite(link, []byte("new"), 0o644); err != nil {
		t.Fatalf("atomicWrite failed: %v", err)
	}

	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("settings.json is no longer a symlink (err=%v mode=%v)", err, fi.Mode())
	}
	if data, err := os.ReadFile(real); err != nil || string(data) != "new" {
		t.Errorf("symlink target not updated: %q err=%v", data, err)
	}
}

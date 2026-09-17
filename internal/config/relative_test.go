package config

import (
	"strings"
	"testing"
)

// Relative paths in security-relevant fields must be rejected at load time: a
// relative path would silently fail to block or mount anything inside the
// sandbox (fail-open). These guard the validation added for that bypass.

func TestRelativeBlockedPathsRejected(t *testing.T) {
	_, _, err := loadFrom(t, "/home/u", "providers: {block: {directories: [relative/secret, ./data]}}", "", "")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative block.directories must be rejected, got %v", err)
	}
	_, _, err = loadFrom(t, "/home/u", "providers: {block: {files: [relative/secret.txt]}}", "", "")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative block.files must be rejected, got %v", err)
	}
}

func TestRelativePathsRejected(t *testing.T) {
	_, _, err := loadFrom(t, "/home/u", "providers:\n  paths:\n    ro: [some/rel/dir]\n", "", "")
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative paths must be rejected, got %v", err)
	}
}

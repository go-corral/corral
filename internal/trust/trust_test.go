package trust

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fixedStore returns a Store rooted at a temp dir with a deterministic clock, so
// approval timestamps are assertable.
func fixedStore(t *testing.T) (*Store, time.Time) {
	t.Helper()
	now := time.Date(2026, 7, 21, 10, 30, 0, 0, time.UTC)
	// Root at a not-yet-created subdir so Approve's MkdirAll is genuinely exercised
	// (and the empty-approve no-op can assert the dir stays absent).
	s := NewStore(filepath.Join(t.TempDir(), "trust"))
	s.now = func() time.Time { return now }
	return s, now
}

func TestCheckNewWhenNoRecord(t *testing.T) {
	s, _ := fixedStore(t)
	got := s.Check([]Entry{{Path: "/repo/.corral.yml", SHA256: "abc"}})
	if len(got) != 1 || got[0].State != StateNew {
		t.Fatalf("want one StateNew result, got %+v", got)
	}
	if !got[0].NeedsApproval() {
		t.Fatalf("new entry must need approval")
	}
}

func TestApproveThenApproved(t *testing.T) {
	s, now := fixedStore(t)
	e := Entry{Path: "/repo/.corral.yml", SHA256: "abc"}
	if err := s.Approve([]Entry{e}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	got := s.Check([]Entry{e})
	if len(got) != 1 || got[0].State != StateApproved {
		t.Fatalf("want StateApproved, got %+v", got)
	}
	if got[0].NeedsApproval() {
		t.Fatalf("approved entry must not need approval")
	}
	if !got[0].ApprovedAt.Equal(now) {
		t.Fatalf("ApprovedAt = %v, want %v", got[0].ApprovedAt, now)
	}
}

func TestChangedWhenHashDiffers(t *testing.T) {
	s, _ := fixedStore(t)
	if err := s.Approve([]Entry{{Path: "/repo/.corral.yml", SHA256: "abc"}}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Same path, different content hash → changed since approval.
	got := s.Check([]Entry{{Path: "/repo/.corral.yml", SHA256: "def"}})
	if len(got) != 1 || got[0].State != StateChanged {
		t.Fatalf("want StateChanged, got %+v", got)
	}
	if !got[0].NeedsApproval() {
		t.Fatalf("changed entry must need approval")
	}
}

func TestPendingFiltersApproved(t *testing.T) {
	s, _ := fixedStore(t)
	approved := Entry{Path: "/repo/.corral.yml", SHA256: "abc"}
	if err := s.Approve([]Entry{approved}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	fresh := Entry{Path: "/repo/.corral.local.yml", SHA256: "xyz"}
	pending := s.Pending([]Entry{approved, fresh})
	if len(pending) != 1 || pending[0].Path != fresh.Path || pending[0].State != StateNew {
		t.Fatalf("want only the fresh local file pending, got %+v", pending)
	}
}

func TestCorruptStateFileTreatedAsUnapproved(t *testing.T) {
	s, _ := fixedStore(t)
	e := Entry{Path: "/repo/.corral.yml", SHA256: "abc"}
	if err := s.Approve([]Entry{e}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	// Corrupt the on-disk record. It must fail toward re-prompt, never silent trust.
	if err := os.WriteFile(s.fileFor(e.Path), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	got := s.Check([]Entry{e})
	if len(got) != 1 || got[0].State != StateNew {
		t.Fatalf("corrupt record must read as StateNew, got %+v", got)
	}
}

func TestEmptyHashRecordTreatedAsUnapproved(t *testing.T) {
	s, _ := fixedStore(t)
	e := Entry{Path: "/repo/.corral.yml", SHA256: "abc"}
	// A well-formed JSON record with no hash is not a valid approval.
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(s.fileFor(e.Path), []byte(`{"path":"/repo/.corral.yml"}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := s.Check([]Entry{e})
	if got[0].State != StateNew {
		t.Fatalf("empty-hash record must read as StateNew, got %+v", got)
	}
}

func TestApproveIsIdempotentRewrite(t *testing.T) {
	s, _ := fixedStore(t)
	e := Entry{Path: "/repo/.corral.yml", SHA256: "abc"}
	if err := s.Approve([]Entry{e}); err != nil {
		t.Fatalf("approve 1: %v", err)
	}
	// Re-approving an unchanged entry is a harmless rewrite, still approved after.
	if err := s.Approve([]Entry{e}); err != nil {
		t.Fatalf("approve 2: %v", err)
	}
	if got := s.Check([]Entry{e}); got[0].State != StateApproved {
		t.Fatalf("want StateApproved after re-approve, got %+v", got)
	}
}

func TestApproveNoEntriesIsNoop(t *testing.T) {
	s, _ := fixedStore(t)
	if err := s.Approve(nil); err != nil {
		t.Fatalf("approve nil: %v", err)
	}
	// Directory must not have been created for an empty approval.
	if _, err := os.Stat(s.dir); !os.IsNotExist(err) {
		t.Fatalf("empty approve must not create the state dir, stat err = %v", err)
	}
}

func TestDistinctPathsGetDistinctFiles(t *testing.T) {
	s, _ := fixedStore(t)
	a := Entry{Path: "/repo-a/.corral.yml", SHA256: "h"}
	b := Entry{Path: "/repo-b/.corral.yml", SHA256: "h"} // same content, different path
	if err := s.Approve([]Entry{a}); err != nil {
		t.Fatalf("approve a: %v", err)
	}
	// b shares a's hash but is a different repo — must still read as new.
	got := s.Check([]Entry{b})
	if got[0].State != StateNew {
		t.Fatalf("distinct path must be independent, got %+v", got)
	}
	if s.fileFor(a.Path) == s.fileFor(b.Path) {
		t.Fatalf("distinct paths must map to distinct state files")
	}
}

func TestDefaultDirXDG(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/xdg/state")
	if got := DefaultDir("/home/u"); got != filepath.Join("/xdg/state", "corral", "trust") {
		t.Fatalf("XDG_STATE_HOME not honored: %s", got)
	}
}

func TestDefaultDirFallback(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	if got := DefaultDir("/home/u"); got != filepath.Join("/home/u", ".local", "state", "corral", "trust") {
		t.Fatalf("fallback wrong: %s", got)
	}
}

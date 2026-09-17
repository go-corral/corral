package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
)

// auditProtectedPaths must cover the resolved log path and every timestamped rotation
// backup present at init (gzip'd or not), so the agent can neither truncate the live log
// nor delete a backup. The lock file is not a backup and must not be conflated.
func TestAuditProtectedPathsIncludesBackups(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "corral-audit.jsonl")
	// Live log + two timestamped backups (one gzip'd) + the lock file.
	for _, name := range []string{
		"corral-audit.jsonl",
		"corral-audit.jsonl.20260101T000000Z",
		"corral-audit.jsonl.20260108T000000Z.gz",
		"corral-audit.jsonl.lock",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &config.Config{}
	got := auditProtectedPaths(cfg, dir)

	// Expect: base + its directory + 2 backups = 4 protected paths; the .lock is excluded.
	if len(got) != 4 {
		t.Fatalf("want 4 protected audit paths (log + dir + 2 backups), got %d: %v", len(got), got)
	}
	canon, _ := policy.CanonicalizeRoot(base, "")
	if got[canon] != "corral's audit log" {
		t.Errorf("base audit log %q not protected: %v", canon, got)
	}
	dc, _ := policy.CanonicalizeRoot(dir, "")
	if got[dc] == "" {
		t.Errorf("audit-log directory %q not protected (rm -rf guard): %v", dir, got)
	}
	for _, b := range []string{"corral-audit.jsonl.20260101T000000Z", "corral-audit.jsonl.20260108T000000Z.gz"} {
		bc, _ := policy.CanonicalizeRoot(filepath.Join(dir, b), "")
		if got[bc] == "" {
			t.Errorf("rotation backup %q not protected: %v", b, got)
		}
	}
	lc, _ := policy.CanonicalizeRoot(base+".lock", "")
	if _, ok := got[lc]; ok {
		t.Errorf("the .lock file must not be treated as a backup: %v", got)
	}
}

// effectiveAuditPath: configured policy.audit.path wins; empty falls back to the default
// under the config dir. Shared by the auditor and the self-protect gate so they agree.
func TestEffectiveAuditPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policy.Audit.Path = "/custom/audit.jsonl"
	if p := effectiveAuditPath(cfg, "/cfgdir"); p != "/custom/audit.jsonl" {
		t.Errorf("configured path should win, got %q", p)
	}
	cfg.Policy.Audit.Path = ""
	if p := effectiveAuditPath(cfg, "/cfgdir"); p != "/cfgdir/corral-audit.jsonl" {
		t.Errorf("default audit path = %q, want /cfgdir/corral-audit.jsonl", p)
	}
}

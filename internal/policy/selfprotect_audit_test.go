package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// The always-on audit log and its rotation backups are self-protected from write/delete
// from inside the sandbox, via the selfProtect extra-protected-paths mechanism that the
// repo-level ignore file also reuses. Reads stay allowed (harmless).
func TestExtraProtectedPathsGuardAuditLog(t *testing.T) {
	dir := t.TempDir()
	logPath, err := Canonicalize(filepath.Join(dir, "corral-audit.jsonl"), "")
	if err != nil {
		t.Fatalf("canonicalize log: %v", err)
	}
	backup, err := Canonicalize(filepath.Join(dir, "corral-audit.jsonl.1"), "")
	if err != nil {
		t.Fatalf("canonicalize backup: %v", err)
	}
	extra := map[string]string{logPath: "corral's audit log", backup: "corral's audit log"}

	// PathPatternRule: a Write/Edit of the log or a rotation backup is denied.
	pp := &PathPatternRule{ExtraProtectedPaths: extra}
	for _, target := range []string{logPath, backup} {
		d, matched, err := pp.Evaluate(toolEvent(t, "Write", map[string]any{"file_path": target, "content": "x"}))
		if err != nil || !matched || d.Action != Deny {
			t.Errorf("Write %q must be denied (audit self-protect); matched=%v action=%v err=%v", target, matched, d.Action, err)
		}
	}
	// A Read of the log is allowed — only writes/deletes are gated.
	if _, matched, err := pp.Evaluate(toolEvent(t, "Read", map[string]any{"file_path": logPath})); err != nil || matched {
		t.Errorf("Read of the audit log must be allowed; matched=%v err=%v", matched, err)
	}

	// BashRule: redirect-over, recursive-rm, and truncate of the log are all denied.
	br := &BashRule{ExtraProtectedPaths: extra}
	for _, cmd := range []string{
		"echo wiped > " + logPath,
		"rm -rf " + logPath,
		"truncate -s 0 " + logPath,
	} {
		d, matched, err := br.Evaluate(bashEvent(t, cmd))
		if err != nil || !matched || d.Action != Deny {
			t.Errorf("bash %q must be denied (audit self-protect); matched=%v action=%v err=%v", cmd, matched, d.Action, err)
		}
	}
}

// A rotation backup created mid-session has a timestamped name that was not known at hook
// init, so it is not in ExtraProtectedPaths. The AuditLogBase prefix guard must still protect
// it (and the .gz form) from delete/truncate/edit; without it, time-based rotation would
// move up to a full interval of history into an unprotected file.
func TestAuditLogBasePrefixGuardsTimestampedBackups(t *testing.T) {
	dir := t.TempDir()
	base, err := Canonicalize(filepath.Join(dir, "corral-audit.jsonl"), "")
	if err != nil {
		t.Fatalf("canonicalize base: %v", err)
	}
	// Backups not present in any extra-paths map — only the prefix guard can catch them.
	rawBackup := filepath.Join(dir, "corral-audit.jsonl.20260101T120000Z")
	gzBackup := filepath.Join(dir, "corral-audit.jsonl.20260101T120000Z.gz")

	pp := &PathPatternRule{AuditLogBase: base}
	for _, target := range []string{rawBackup, gzBackup} {
		d, matched, err := pp.Evaluate(toolEvent(t, "Write", map[string]any{"file_path": target, "content": "x"}))
		if err != nil || !matched || d.Action != Deny {
			t.Errorf("Write of mid-session backup %q must be denied via the prefix guard; matched=%v action=%v err=%v", target, matched, d.Action, err)
		}
	}

	br := &BashRule{AuditLogBase: base}
	for _, cmd := range []string{"rm -rf " + rawBackup, "truncate -s 0 " + gzBackup} {
		d, matched, err := br.Evaluate(bashEvent(t, cmd))
		if err != nil || !matched || d.Action != Deny {
			t.Errorf("bash %q must be denied via the prefix guard; matched=%v action=%v err=%v", cmd, matched, d.Action, err)
		}
	}

	// Sanity: a sibling that merely shares the directory but not the base prefix is not
	// swept up by the guard (no over-blocking of unrelated files).
	other := filepath.Join(dir, "unrelated.txt")
	if _, matched, err := pp.Evaluate(toolEvent(t, "Write", map[string]any{"file_path": other, "content": "x"})); err != nil || matched {
		t.Errorf("an unrelated file must not be caught by the audit prefix guard; matched=%v err=%v", matched, err)
	}
}

// The shell self-protect gates (rm/truncate/shred/find) must resolve a target through an
// in-sandbox symlink before the AuditLogBase prefix guard, so a path that reaches a backup via
// a symlinked ancestor is still caught. This reproduces on Linux the macOS firmlink case
// (/var → /private/var, where t.TempDir lives) that made the raw shell token diverge from
// the canonicalized AuditLogBase — the gates compared the unresolved token and missed.
func TestAuditLogBasePrefixGuardResolvesSymlinkedAncestor(t *testing.T) {
	realDir := t.TempDir()
	base, err := Canonicalize(filepath.Join(realDir, "corral-audit.jsonl"), "")
	if err != nil {
		t.Fatalf("canonicalize base: %v", err)
	}
	// A symlink standing in for the firmlink: linkDir → realDir. A token through it resolves
	// to realDir/… (== base prefix) only after canonicalization; the raw token does not.
	linkDir := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	rawBackup := filepath.Join(linkDir, "corral-audit.jsonl.20260101T120000Z")   // via the symlink
	gzBackup := filepath.Join(linkDir, "corral-audit.jsonl.20260101T120000Z.gz") // via the symlink

	br := &BashRule{AuditLogBase: base}
	for _, cmd := range []string{
		"rm -rf " + rawBackup,
		"truncate -s 0 " + gzBackup,
		"find " + rawBackup + " -delete",
	} {
		d, matched, err := br.Evaluate(bashEvent(t, cmd))
		if err != nil || !matched || d.Action != Deny {
			t.Errorf("bash %q must be denied (prefix guard via symlinked ancestor); matched=%v action=%v err=%v", cmd, matched, d.Action, err)
		}
	}
}

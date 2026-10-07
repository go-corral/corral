package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// legacyAndTarget returns a legacy log path and a target log path in separate directories.
func legacyAndTarget(t *testing.T) (from, to string) {
	t.Helper()
	dir := t.TempDir()
	from = filepath.Join(dir, "legacy", "corral-audit.jsonl")
	to = filepath.Join(dir, "state", "audit", "corral-audit.jsonl")
	if err := os.MkdirAll(filepath.Dir(from), 0o700); err != nil {
		t.Fatal(err)
	}
	return from, to
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestMoveLegacyMovesLogAndBackups(t *testing.T) {
	from, to := legacyAndTarget(t)
	backup := from + ".20260101T000000Z"
	writeFile(t, from, "live\n")
	writeFile(t, backup, "old\n")
	writeFile(t, from+".lock", "")

	if errs := MoveLegacy(from, to); len(errs) != 0 {
		t.Fatalf("MoveLegacy errors: %v", errs)
	}
	if got := readFile(t, to); got != "live\n" {
		t.Errorf("live log content = %q, want %q", got, "live\n")
	}
	if got := readFile(t, filepath.Join(filepath.Dir(to), filepath.Base(backup))); got != "old\n" {
		t.Errorf("backup content = %q, want %q", got, "old\n")
	}
	for _, p := range []string{from, backup} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s must be gone, stat err: %v", p, err)
		}
	}
	// A writer that waits on the legacy lock must keep sharing it with later writers.
	if _, err := os.Lstat(from + ".lock"); err != nil {
		t.Errorf("legacy lock file must stay: %v", err)
	}
}

func TestMoveLegacyWithoutLegacyLogDoesNothing(t *testing.T) {
	from, to := legacyAndTarget(t)
	if errs := MoveLegacy(from, to); len(errs) != 0 {
		t.Fatalf("MoveLegacy errors: %v", errs)
	}
	for _, p := range []string{filepath.Dir(to), from + ".lock"} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s must not be created, stat err: %v", p, err)
		}
	}
}

func TestMoveLegacyLiveLogBecomesBackupOfExistingLog(t *testing.T) {
	from, to := legacyAndTarget(t)
	writeFile(t, from, "legacy\n")
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, to, "new\n")

	if errs := MoveLegacy(from, to); len(errs) != 0 {
		t.Fatalf("MoveLegacy errors: %v", errs)
	}
	if got := readFile(t, to); got != "new\n" {
		t.Errorf("the new live log must be unchanged, got %q", got)
	}
	backups := Backups(to)
	if len(backups) != 1 || readFile(t, backups[0]) != "legacy\n" {
		t.Errorf("the legacy live log must become one backup of the new log, got %v", backups)
	}
}

func TestMoveLegacyKeepsBackupWhoseNameExists(t *testing.T) {
	from, to := legacyAndTarget(t)
	name := filepath.Base(from) + ".20260101T000000Z"
	writeFile(t, filepath.Join(filepath.Dir(from), name), "legacy backup\n")
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(filepath.Dir(to), name), "new backup\n")

	errs := MoveLegacy(from, to)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), name) {
		t.Fatalf("want one error naming %s, got %v", name, errs)
	}
	if got := readFile(t, filepath.Join(filepath.Dir(from), name)); got != "legacy backup\n" {
		t.Errorf("the legacy backup must stay in place, got %q", got)
	}
	if got := readFile(t, filepath.Join(filepath.Dir(to), name)); got != "new backup\n" {
		t.Errorf("the existing backup must be unchanged, got %q", got)
	}
}

func TestMoveLegacyUnwritableTargetKeepsFiles(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	from, to := legacyAndTarget(t)
	backup := from + ".20260101T000000Z"
	writeFile(t, from, "live\n")
	writeFile(t, backup, "old\n")
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(to), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(to), 0o700) })

	errs := MoveLegacy(from, to)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), filepath.Dir(to)) {
		t.Fatalf("want one error naming the target directory, got %v", errs)
	}
	for _, p := range []string{backup, from} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s must stay in place: %v", p, err)
		}
	}
}

func TestMoveLegacyRefusesSymlink(t *testing.T) {
	from, to := legacyAndTarget(t)
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), from); err != nil {
		t.Fatal(err)
	}
	if errs := MoveLegacy(from, to); len(errs) != 1 {
		t.Fatalf("want one error for the symlink, got %v", errs)
	}
	if _, err := os.Lstat(to); !os.IsNotExist(err) {
		t.Errorf("a symlink must not be moved to the live log path, stat err: %v", err)
	}
}

// Writers that log on the legacy and on the new path while the log moves lose no record: each
// record is in the moved files, the new log, or a new legacy log.
func TestMoveLegacyConcurrentWritersLoseNoRecord(t *testing.T) {
	from, to := legacyAndTarget(t)
	writeFile(t, from, "{\"action\":\"allow\"}\n")

	const n = 200
	var wg sync.WaitGroup
	for _, path := range []string{from, to} {
		l := New(Config{}, path)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				if err := l.Log(Record{Action: "allow", Reason: fmt.Sprintf("r%03d", i)}); err != nil {
					t.Errorf("log %d to %s: %v", i, path, err)
				}
			}
		}()
	}
	for i := 0; i < 10; i++ {
		if errs := MoveLegacy(from, to); len(errs) != 0 {
			t.Errorf("MoveLegacy errors: %v", errs)
		}
	}
	wg.Wait()

	var records int
	for _, p := range append(append([]string{from, to}, Backups(from)...), Backups(to)...) {
		if data, err := os.ReadFile(p); err == nil {
			records += strings.Count(string(data), "\n")
		}
	}
	if records != 2*n+1 {
		t.Errorf("records = %d, want %d", records, 2*n+1)
	}
}

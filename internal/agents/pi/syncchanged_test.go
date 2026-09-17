package pi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/agents/spec"
)

// TestPiSyncReportChanged pins SyncReport.Changed for the bridge agent: it tracks the presence
// backstop, the only artifact that outlives a session, and is false on the nothing-to-do paths,
// even though pi's Sync always returns explanatory Messages about its per-launch policy bridge.
// `corral uninstall` reads it as "is corral's enforcement registered here?", so the ever-present
// preamble must not be mistaken for a registration.
func TestPiSyncReportChanged(t *testing.T) {
	home := t.TempDir()
	a := New()
	host := map[string]string{}
	backstop := filepath.Join(home, ".pi", "agent", "extensions", "corral-presence.ts")
	install := spec.SyncInput{Home: home, Host: host}
	remove := spec.SyncInput{Home: home, Host: host, Remove: true}
	dryInstall, dryRemove := install, remove
	dryInstall.DryRun, dryRemove.DryRun = true, true

	// Nothing installed: a removal has nothing to do, in both directions.
	assertPiChanged(t, a, dryRemove, false, "removal dry-run with no backstop installed")
	assertPiChanged(t, a, remove, false, "removal with no backstop installed")

	// An install reports the write it would make, then the one it made.
	assertPiChanged(t, a, dryInstall, true, "install dry-run with no backstop installed")
	if _, err := os.Stat(backstop); !os.IsNotExist(err) {
		t.Errorf("a dry-run install must not write the backstop (stat err = %v)", err)
	}
	assertPiChanged(t, a, install, true, "install with no backstop installed")

	// Up to date: nothing to do, in both directions.
	assertPiChanged(t, a, install, false, "re-install over an up-to-date backstop")
	assertPiChanged(t, a, dryInstall, false, "re-install dry-run over an up-to-date backstop")

	// Installed: a removal reports the deletion it would make, then the one it made, then no-ops.
	assertPiChanged(t, a, dryRemove, true, "removal dry-run with the backstop installed")
	if _, err := os.Stat(backstop); err != nil {
		t.Errorf("a dry-run removal must not delete the backstop: %v", err)
	}
	assertPiChanged(t, a, remove, true, "removal with the backstop installed")
	assertPiChanged(t, a, remove, false, "second removal of the same backstop")

	// A stale (content-drifted) copy is a pending write too.
	if err := os.WriteFile(backstop, []byte("// stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	assertPiChanged(t, a, dryInstall, true, "install dry-run over a stale backstop")
}

func assertPiChanged(t *testing.T, a spec.Agent, in spec.SyncInput, want bool, what string) {
	t.Helper()
	report, err := a.Sync(in)
	if err != nil {
		t.Fatalf("%s: Sync: %v", what, err)
	}
	if report.Changed != want {
		t.Errorf("%s: Changed = %v, want %v (messages: %v)", what, report.Changed, want, report.Messages)
	}
}

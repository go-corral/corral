package claude

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/agents/spec"
)

// TestClaudeSyncReportChanged pins SyncReport.Changed across claude's whole sync matrix: it is
// true exactly when the settings file was (or, under DryRun, would be) written, and false on the
// nothing-to-do paths. `corral uninstall` reads it as "is corral's enforcement registered here?",
// so a false positive would make it claim a registration that is not there.
func TestClaudeSyncReportChanged(t *testing.T) {
	home := t.TempDir()
	a := New()
	host := map[string]string{}
	settings := filepath.Join(home, ".claude", "settings.json")
	install := spec.SyncInput{Home: home, Host: host, BinaryPath: "/usr/local/bin/corral"}
	remove := spec.SyncInput{Home: home, Host: host, Remove: true}

	// Nothing registered yet: a removal is a no-op in both directions.
	dry := remove
	dry.DryRun = true
	assertChanged(t, a, dry, false, "removal dry-run over an absent settings.json")
	assertChanged(t, a, remove, false, "removal over an absent settings.json")
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Errorf("a removal must not create settings.json (stat err = %v)", err)
	}

	// A registration reports the write it would make, and then the one it made.
	dryInstall := install
	dryInstall.DryRun = true
	assertChanged(t, a, dryInstall, true, "registration dry-run on a fresh home")
	if _, err := os.Stat(settings); !os.IsNotExist(err) {
		t.Errorf("a dry-run registration must not write settings.json (stat err = %v)", err)
	}
	assertChanged(t, a, install, true, "registration on a fresh home")

	// Already registered: nothing to do, in both directions.
	assertChanged(t, a, install, false, "re-registration over an up-to-date settings.json")
	assertChanged(t, a, dryInstall, false, "re-registration dry-run over an up-to-date settings.json")

	// Registered: a removal reports the strip it would make, then the one it made, then no-ops.
	assertChanged(t, a, dry, true, "removal dry-run over a registered settings.json")
	assertChanged(t, a, remove, true, "removal over a registered settings.json")
	assertChanged(t, a, remove, false, "second removal over the same settings.json")
	assertChanged(t, a, dry, false, "removal dry-run over a de-registered settings.json")
}

func assertChanged(t *testing.T, a spec.Agent, in spec.SyncInput, want bool, what string) {
	t.Helper()
	report, err := a.Sync(in)
	if err != nil {
		t.Fatalf("%s: Sync: %v", what, err)
	}
	if report.Changed != want {
		t.Errorf("%s: Changed = %v, want %v (messages: %v)", what, report.Changed, want, report.Messages)
	}
}

package pi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/agents/spec"
)

// TestPiSyncInstallsPresenceBackstop pins pi's Sync: a dry-run reports without writing, a real
// run installs the presence backstop under <agentdir>/extensions, and a second run is a no-op.
func TestPiSyncInstallsPresenceBackstop(t *testing.T) {
	home := t.TempDir()
	a := New()
	dst := filepath.Join(home, ".pi", "agent", "extensions", "corral-presence.ts")

	// Dry-run: reports a would-install, writes nothing.
	rep, err := a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}, DryRun: true})
	if err != nil {
		t.Fatalf("pi Sync dry-run: %v", err)
	}
	if !containsLine(rep.Messages, "would install") {
		t.Errorf("pi Sync dry-run messages = %v, want a would-install line", rep.Messages)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("pi Sync dry-run must not write the backstop (stat err = %v)", err)
	}

	// Real run: installs the file.
	if _, err := a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}}); err != nil {
		t.Fatalf("pi Sync: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("pi Sync should install the backstop at %s: %v", dst, err)
	}

	// Idempotent: a second run is a no-op.
	rep, err = a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}})
	if err != nil {
		t.Fatalf("pi Sync (2nd): %v", err)
	}
	if !containsLine(rep.Messages, "already up to date") {
		t.Errorf("pi Sync (2nd) messages = %v, want already-up-to-date", rep.Messages)
	}
}

// TestPiSyncRemove pins pi's de-registration: it deletes the presence backstop it installed (the
// only artifact that outlives a session — the policy bridge is per-launch), reports the no-op when
// none is installed, writes nothing under --dry-run, and leaves the extensions directory alone
// because that belongs to pi, not corral.
func TestPiSyncRemove(t *testing.T) {
	home := t.TempDir()
	a := New()
	extDir := filepath.Join(home, ".pi", "agent", "extensions")
	dst := filepath.Join(extDir, "corral-presence.ts")

	// Nothing installed: a no-op, and the preamble still explains the per-launch bridge.
	rep, err := a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}, Remove: true})
	if err != nil {
		t.Fatalf("pi Sync --remove (nothing installed): %v", err)
	}
	if !containsLine(rep.Messages, "not installed — nothing to remove") {
		t.Errorf("pi Sync --remove messages = %v, want a nothing-to-remove line", rep.Messages)
	}
	if !containsLine(rep.Messages, "needs no de-registration") {
		t.Errorf("pi Sync --remove should explain the per-launch bridge, got %v", rep.Messages)
	}

	// Install it, then a dry-run removal: reported, but the file stays.
	if _, err := a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}}); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	rep, err = a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}, Remove: true, DryRun: true})
	if err != nil {
		t.Fatalf("pi Sync --remove --dry-run: %v", err)
	}
	if !containsLine(rep.Messages, "would delete the presence backstop") {
		t.Errorf("dry-run removal messages = %v, want a would-delete line", rep.Messages)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("dry-run removal must not delete the backstop: %v", err)
	}

	// Real removal: the file goes, the extensions dir stays.
	rep, err = a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}, Remove: true})
	if err != nil {
		t.Fatalf("pi Sync --remove: %v", err)
	}
	if !containsLine(rep.Messages, "deleted the presence backstop at "+dst) {
		t.Errorf("removal messages = %v, want a deleted line naming %s", rep.Messages, dst)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("the backstop should be gone (stat err = %v)", err)
	}
	if _, err := os.Stat(extDir); err != nil {
		t.Errorf("pi's extensions dir must survive corral's removal: %v", err)
	}

	// Idempotent, and reversible: removing again is a no-op, and a plain sync reinstalls.
	rep, err = a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}, Remove: true})
	if err != nil {
		t.Fatalf("pi Sync --remove (2nd): %v", err)
	}
	if !containsLine(rep.Messages, "not installed — nothing to remove") {
		t.Errorf("second removal = %v, want a nothing-to-remove line", rep.Messages)
	}
	if _, err := a.Sync(spec.SyncInput{Home: home, Host: map[string]string{}}); err != nil {
		t.Fatalf("re-sync after removal: %v", err)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, presenceSource) {
		t.Errorf("a re-sync must reinstall the embedded backstop (got %d bytes)", len(got))
	}
}

// TestPiLaunchWarningsBackstop pins pi's launch advisory: warn when the presence backstop is not
// installed, fall silent once it is synced.
func TestPiLaunchWarningsBackstop(t *testing.T) {
	home := t.TempDir()
	pi := New()
	in := spec.StatusInput{Home: home, Host: map[string]string{}}

	if w := pi.LaunchWarnings(in); len(w) != 1 || w[0].Value != "presence backstop not installed" || w[0].Fix != "corral sync pi" {
		t.Errorf("pi LaunchWarnings (no backstop) = %v, want a not-installed warning", w)
	}
	if _, err := pi.Sync(spec.SyncInput{Home: home, Host: map[string]string{}}); err != nil {
		t.Fatalf("pi Sync: %v", err)
	}
	if w := pi.LaunchWarnings(in); len(w) != 0 {
		t.Errorf("pi LaunchWarnings must fall silent once installed, got %v", w)
	}
}

// TestPiSyncUpdatesStaleBackstop pins pi's stale path: an existing-but-outdated backstop is
// reported as an update (not a fresh install) and rewritten to the current embedded content.
func TestPiSyncUpdatesStaleBackstop(t *testing.T) {
	home := t.TempDir()
	pi := New()
	dst := filepath.Join(home, ".pi", "agent", "extensions", "corral-presence.ts")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("// outdated\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Dry-run on a stale file → "would update" (not "would install"), still writes nothing.
	rep, err := pi.Sync(spec.SyncInput{Home: home, Host: map[string]string{}, DryRun: true})
	if err != nil {
		t.Fatalf("pi Sync dry-run (stale): %v", err)
	}
	if !containsLine(rep.Messages, "would update the presence backstop") {
		t.Errorf("stale dry-run messages = %v, want a would-update line", rep.Messages)
	}

	// Real run → "updated" and the file now matches the embedded source.
	rep, err = pi.Sync(spec.SyncInput{Home: home, Host: map[string]string{}})
	if err != nil {
		t.Fatalf("pi Sync (stale): %v", err)
	}
	if !containsLine(rep.Messages, "updated the presence backstop") {
		t.Errorf("stale sync messages = %v, want an updated line", rep.Messages)
	}
	if got, _ := os.ReadFile(dst); !bytes.Equal(got, presenceSource) {
		t.Errorf("stale backstop must be rewritten to the embedded source (got %d bytes)", len(got))
	}
}

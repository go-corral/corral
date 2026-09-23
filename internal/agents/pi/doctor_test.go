package pi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/spec"
	"github.com/go-corral/corral/internal/health"
)

// TestPiDoctor exercises pi's readiness report: the policy bridge check (always OK, since the
// bridge is embedded) plus the presence backstop's three install states — not installed, out of
// date, and installed.
func TestPiDoctor(t *testing.T) {
	pi := New()
	backstop := func(home string) string {
		return filepath.Join(home, ".pi", "agent", "extensions", "corral-presence.ts")
	}
	checks := func(home string) []health.Check {
		t.Helper()
		got := pi.Doctor(spec.StatusInput{Home: home, Host: map[string]string{}})
		if len(got) != 2 {
			t.Fatalf("pi Doctor must return the bridge and backstop checks; got %+v", got)
		}
		bridge := got[0]
		if bridge.State != health.OK || bridge.Label != "policy bridge" || !strings.HasPrefix(bridge.Value, "embedded (") || bridge.Fix != "" {
			t.Errorf("pi Doctor: got %+v, want an embedded policy-bridge check", bridge)
		}
		return got
	}

	// Fresh home: backstop not installed.
	fresh := t.TempDir()
	want := health.Check{State: health.Warn, Label: "presence backstop", Value: "not installed",
		Reason: "it warns when pi runs without corral", Fix: "corral sync pi"}
	if got := checks(fresh)[1]; got != want {
		t.Errorf("pi Doctor (fresh): got %+v, want %+v", got, want)
	}

	// Stale backstop (wrong content) → out of date, naming the file.
	stale := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(backstop(stale)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backstop(stale), []byte("// outdated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want = health.Check{State: health.Warn, Label: "presence backstop", Value: "out of date", Reason: backstop(stale), Fix: "corral sync pi"}
	if got := checks(stale)[1]; got != want {
		t.Errorf("pi Doctor (stale): got %+v, want %+v", got, want)
	}

	// Installed via Sync → installed.
	installed := t.TempDir()
	if _, err := pi.Sync(spec.SyncInput{Home: installed, Host: map[string]string{}}); err != nil {
		t.Fatalf("pi Sync: %v", err)
	}
	want = health.Check{Label: "presence backstop", Value: "installed"}
	if got := checks(installed)[1]; got != want {
		t.Errorf("pi Doctor (synced): got %+v, want %+v", got, want)
	}
}

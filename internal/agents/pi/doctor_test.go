package pi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/agents/spec"
)

// doctorStatuses flattens a DoctorReport into "label: status" lines so containsLine can assert on
// them.
func doctorStatuses(rep spec.DoctorReport) []string {
	out := make([]string, len(rep.Lines))
	for i, l := range rep.Lines {
		out[i] = l.Label + ": " + l.Status
	}
	return out
}

// TestPiDoctor exercises pi's readiness report: the policy bridge line (always present, since the
// bridge is embedded) plus the presence backstop's three install states — not installed, out of
// date, and installed.
func TestPiDoctor(t *testing.T) {
	pi := New()
	report := func(home string) []string {
		return doctorStatuses(pi.Doctor(spec.StatusInput{Home: home, Host: map[string]string{}}))
	}
	backstop := func(home string) string {
		return filepath.Join(home, ".pi", "agent", "extensions", "corral-presence.ts")
	}

	// Fresh home: bridge embedded, backstop not installed.
	fresh := t.TempDir()
	got := report(fresh)
	if !containsLine(got, "policy bridge") || !containsLine(got, "embedded") {
		t.Errorf("pi Doctor: got %v, want an embedded policy-bridge line", got)
	}
	if !containsLine(got, "not installed") {
		t.Errorf("pi Doctor (fresh): got %v, want backstop not-installed", got)
	}

	// Stale backstop (wrong content) → "out of date".
	stale := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(backstop(stale)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backstop(stale), []byte("// outdated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := report(stale); !containsLine(got, "out of date") {
		t.Errorf("pi Doctor (stale): got %v, want backstop out-of-date", got)
	}

	// Installed via Sync → "installed".
	installed := t.TempDir()
	if _, err := pi.Sync(spec.SyncInput{Home: installed, Host: map[string]string{}}); err != nil {
		t.Fatalf("pi Sync: %v", err)
	}
	if got := report(installed); !containsLine(got, "installed (") {
		t.Errorf("pi Doctor (synced): got %v, want backstop installed", got)
	}
}

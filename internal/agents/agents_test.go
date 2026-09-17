package agents

import (
	"slices"
	"testing"
)

func TestLookupKnownAndUnknown(t *testing.T) {
	a, ok := Lookup("claude")
	if !ok {
		t.Fatal(`Lookup("claude") = ok false, want a registered agent`)
	}
	if a.Name() != "claude" {
		t.Errorf("claude agent Name() = %q, want %q", a.Name(), "claude")
	}
	if _, ok := Lookup("nope"); ok {
		t.Error(`Lookup("nope") = ok true, want false for an unknown agent (must fail closed)`)
	}
}

func TestDefaultIsRegistered(t *testing.T) {
	// Drift-guard: the Default literal must always name a registered agent, else the
	// launcher's default selection would fail closed on a perfectly normal launch.
	if _, ok := Lookup(Default); !ok {
		t.Errorf("Default = %q is not a registered agent", Default)
	}
}

// TestKnownIsSortedAndComplete pins the registry's membership and ordering: Known is sorted and
// contains both registered agents. Each agent's own behavior is tested in its package; this is
// the wiring guard that the facade registers them.
func TestKnownIsSortedAndComplete(t *testing.T) {
	got := Known()
	if !slices.IsSorted(got) {
		t.Errorf("Known() = %v, want sorted", got)
	}
	for _, want := range []string{"claude", "pi"} {
		if !slices.Contains(got, want) {
			t.Errorf("Known() = %v, want it to contain %q", got, want)
		}
	}
}

// TestAllReservedEnv pins the registry union config consumes: sorted, deduplicated, the union of
// every agent's ReservedEnv, and free of corral-core (CORRAL_*) markers — those belong to corral,
// not any agent, and config adds them separately.
func TestAllReservedEnv(t *testing.T) {
	got := AllReservedEnv()
	if !slices.IsSorted(got) {
		t.Errorf("AllReservedEnv() = %v, want sorted", got)
	}
	seen := map[string]bool{}
	for _, n := range got {
		if seen[n] {
			t.Errorf("AllReservedEnv() = %v, has duplicate %q", got, n)
		}
		seen[n] = true
	}
	for _, want := range []string{"ENABLE_CLAUDEAI_MCP_SERVERS", "PI_CODING_AGENT_DIR", "PI_CODING_AGENT_SESSION_DIR"} {
		if !seen[want] {
			t.Errorf("AllReservedEnv() = %v, want it to contain %q", got, want)
		}
	}
	for _, core := range []string{"CORRAL_SANDBOX", "CORRAL_GLOBAL_CONFIG", "CORRAL_AGENT", "CORRAL_BIN"} {
		if seen[core] {
			t.Errorf("AllReservedEnv() = %v, must NOT contain corral-core marker %q (config adds those separately)", got, core)
		}
	}
}

package pi

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// TestPiBridgeNodeHarness exercises the embedded pi bridge's own JavaScript logic — the tool
// name/key mapping and pi's asymmetric fail-closed behavior (tool_call throws to block;
// tool_result/user_bash must return a withhold/deny, never throw) — by loading it with a mock
// pi and a fake corral. It is gated on node being present (skipped in pure-Go CI), like the
// live-credential provider tests; the bridge's corral-facing wire is additionally pinned by
// the policy package's hook tests. The pi->bridge direction against a real pi binary needs a
// configured model and is verified by hand (see scratch/pi-phase2-plan.md).
func TestPiBridgeNodeHarness(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping pi bridge harness")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this test's path")
	}
	dir := filepath.Dir(file)
	bridge := filepath.Join(dir, "pi-bridge.ts")
	harness := filepath.Join(dir, "testdata", "bridge_harness.mjs")

	out, err := exec.Command(node, harness, bridge).CombinedOutput()
	if err != nil {
		t.Fatalf("pi bridge harness failed: %v\n%s", err, out)
	}
}

// TestPiPresenceNodeHarness exercises the presence backstop's JS: silent inside corral
// (CORRAL_SANDBOX set), warns once with the removal hint outside corral. Gated on node.
func TestPiPresenceNodeHarness(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping pi presence harness")
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this test's path")
	}
	dir := filepath.Dir(file)
	presence := filepath.Join(dir, "pi-presence.ts")
	harness := filepath.Join(dir, "testdata", "presence_harness.mjs")

	out, err := exec.Command(node, harness, presence).CombinedOutput()
	if err != nil {
		t.Fatalf("pi presence harness failed: %v\n%s", err, out)
	}
}

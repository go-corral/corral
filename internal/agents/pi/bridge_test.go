package pi

import (
	"strings"
	"testing"
)

// TestPiBridgeSourceWellFormed pins the embedded bridge's load-bearing shape so a careless
// edit cannot silently drop a handler or the fail-closed wiring. The bridge is exercised
// end-to-end against a real pi binary by the gated integration test; this is the cheap
// always-on guard.
func TestPiBridgeSourceWellFormed(t *testing.T) {
	src := string(bridgeSource)
	if len(src) == 0 {
		t.Fatal("bridgeSource is empty — the //go:embed of pi-bridge.ts did not take")
	}
	for _, want := range []string{
		"export default",
		`pi.on("tool_call"`,
		`pi.on("tool_result"`,
		`pi.on("user_bash"`,
		`pi.on("input"`,
		`pi.on("before_agent_start"`,
		`"pre-tool-use"`,
		`"post-tool-use"`,
		`"user-prompt-submit"`,
		`"session-start"`,
		"CORRAL_BIN", // the launcher pins corral's path here for the bridge to exec
	} {
		if !strings.Contains(src, want) {
			t.Errorf("embedded pi bridge missing %q", want)
		}
	}
}

// TestPiPresenceSourceWellFormed pins the presence backstop's load-bearing shape: it gates on
// the CORRAL_SANDBOX marker (silent inside corral), self-locates for the removal hint, and
// tells the user how to sandbox / remove it.
func TestPiPresenceSourceWellFormed(t *testing.T) {
	exts := agent{}.globalExtensions()
	if len(exts) == 0 {
		t.Fatal("pi has no global extensions — presence backstop missing")
	}
	src := string(exts[0].Content)
	for _, want := range []string{
		"export default",
		`pi.on("input"`,
		"CORRAL_SANDBOX",   // silent inside corral
		"fileURLToPath",    // self-locate for the removal hint
		"corral run pi",    // how to sandbox
		"delete this file", // removal hint
		"NOT sandboxed",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("embedded pi presence backstop missing %q", want)
		}
	}
}

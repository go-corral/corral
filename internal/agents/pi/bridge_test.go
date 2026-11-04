package pi

import (
	"testing"

	"github.com/go-corral/corral/internal/agents/internal/agenttest"
	"github.com/go-corral/corral/internal/sandbox"
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
	agenttest.AssertContains(t, "embedded pi bridge", src,
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
		sandbox.SidecarSocketEnvVar, // the launcher sets the sidecar socket here for the bridge
	)
}

func TestPiBridgeFailureTexts(t *testing.T) {
	agenttest.AssertFailureTexts(t, "embedded pi bridge", string(bridgeSource))
}

// TestPiPresenceSourceWellFormed pins the presence backstop's load-bearing shape: it gates on
// the CORRAL_SANDBOX marker (silent inside corral), self-locates for the removal hint, and
// tells the user how to sandbox / remove it.
func TestPiPresenceSourceWellFormed(t *testing.T) {
	exts := agent{}.globalExtensions()
	if len(exts) == 0 {
		t.Fatal("pi has no global extensions — presence backstop missing")
	}
	agenttest.AssertContains(t, "embedded pi presence backstop", string(exts[0].Content),
		"export default",
		`pi.on("input"`,
		"CORRAL_SANDBOX",   // silent inside corral
		"fileURLToPath",    // self-locate for the removal hint
		"corral run pi",    // how to sandbox
		"delete this file", // removal hint
		"NOT sandboxed",
	)
}

package opencode

import (
	"testing"

	"github.com/go-corral/corral/internal/agents/internal/agenttest"
)

// TestOpencodePresenceNodeHarness runs the presence backstop against a mock V2 ctx. The harness
// sets and clears CORRAL_SANDBOX itself.
func TestOpencodePresenceNodeHarness(t *testing.T) {
	agenttest.RunNode(t, nil, "testdata/presence_harness.mjs", "opencode-presence.js")
}

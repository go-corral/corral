package opencode

import (
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/internal/agenttest"
)

// TestOpencodePresenceSourceWellFormed pins the load-bearing shape of the presence backstop.
func TestOpencodePresenceSourceWellFormed(t *testing.T) {
	src := string(presenceSource)
	assertPlainJS(t, "opencode-presence.js", src)
	agenttest.AssertContains(t, "embedded opencode presence backstop", src,
		"export default",
		`id: "corral-presence"`,
		`ctx.session.hook("prompt"`,
		"CORRAL_SANDBOX",
		"fileURLToPath",
		"corral run opencode",
		"delete this file",
		"NOT sandboxed",
		"parentID",
	)
	if strings.Contains(src, "CORRAL_BIN") {
		t.Error("embedded opencode presence backstop names CORRAL_BIN")
	}
}

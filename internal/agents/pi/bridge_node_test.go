package pi

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/internal/agenttest"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sidecar"
)

// runBridgeHarness runs testdata/bridge_harness.mjs against the bridge with the sidecar socket set.
func runBridgeHarness(t *testing.T, socket string, args ...string) []byte {
	t.Helper()
	return agenttest.RunNode(t, []string{sandbox.SidecarSocketEnvVar + "=" + socket},
		append([]string{"testdata/bridge_harness.mjs", "pi-bridge.ts"}, args...)...)
}

// TestPiBridgeNodeHarness exercises the embedded pi bridge against a real sidecar server: the
// tool name/key mapping, the sidecar's answers, and pi's asymmetric fail-closed rules (tool_call
// throws to block; tool_result/user_bash return a withhold/deny, never throw). The pi->bridge
// direction against a real pi binary needs a configured model and is verified by hand.
func TestPiBridgeNodeHarness(t *testing.T) {
	runBridgeHarness(t, agenttest.ServeScripted(t), "events")
}

// harnessToolCall runs one tool_call through the bridge and returns the harness's report.
func harnessToolCall(t *testing.T, socket, toolName string, input map[string]any) (result map[string]any, threw string) {
	t.Helper()
	arg, err := json.Marshal(map[string]any{"toolName": toolName, "input": input})
	if err != nil {
		t.Fatal(err)
	}
	out := runBridgeHarness(t, socket, "tool_call", string(arg))
	var rep struct {
		Result map[string]any `json:"result"`
		Threw  string         `json:"threw"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("harness output %q: %v", out, err)
	}
	return rep.Result, rep.Threw
}

// TestPiBridgeFilesystemParity checks the bridge's filesystem answers against the hook's.
func TestPiBridgeFilesystemParity(t *testing.T) {
	agenttest.FilesystemParity(t, func(socket string) {
		if result, threw := harnessToolCall(t, socket, "read", map[string]any{"path": "/x"}); threw != "" || result != nil {
			t.Fatalf("tool call: threw %q, result %v", threw, result)
		}
	})
}

// TestPiBridgeParityProtectedSymlink writes through a symlink that a process in the sandbox
// created to a protected file. The policy resolves the link through the bridge.
func TestPiBridgeParityProtectedSymlink(t *testing.T) {
	socket, link, other := agenttest.ProtectedSymlink(t)
	result, threw := harnessToolCall(t, socket, "write", map[string]any{"path": link, "content": "x"})
	reason, _ := result["reason"].(string)
	if threw != "" || result["block"] != true || !strings.Contains(reason, "[hook:blocked-path]") {
		t.Fatalf("write through %s: want a blocked-path block, got threw %q, result %v", link, threw, result)
	}
	result, threw = harnessToolCall(t, socket, "write", map[string]any{"path": other, "content": "x"})
	if threw != "" || result != nil {
		t.Fatalf("write to an unprotected path: want allow, got threw %q, result %v", threw, result)
	}
}

// TestPiBridgeOversizedEvent sends a tool_call over the event cap. The bridge sends
// MaxEventBytes+1 bytes, so the policy sees the overflow.
func TestPiBridgeOversizedEvent(t *testing.T) {
	socket := agenttest.Serve(t, func(_ sidecar.Request, payload []byte, _ policy.FS) sidecar.Response {
		if len(payload) != policy.MaxEventBytes+1 {
			return sidecar.Response{Error: fmt.Sprintf("got %d payload bytes, want %d", len(payload), policy.MaxEventBytes+1)}
		}
		return sidecar.Response{}
	})
	runBridgeHarness(t, socket, "oversize")
}

// TestPiPresenceNodeHarness exercises the presence backstop's JS: silent inside corral
// (CORRAL_SANDBOX set), warns once with the removal hint outside corral.
func TestPiPresenceNodeHarness(t *testing.T) {
	agenttest.RunNode(t, nil, "testdata/presence_harness.mjs", "pi-presence.ts")
}

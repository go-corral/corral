package opencode

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/internal/agenttest"
	"github.com/go-corral/corral/internal/sandbox"
)

// runPolicyHarness runs testdata/policy_harness.mjs against the plugin with the sidecar socket set.
func runPolicyHarness(t *testing.T, socket string, args ...string) []byte {
	t.Helper()
	return agenttest.RunNode(t, []string{sandbox.SidecarSocketEnvVar + "=" + socket},
		append([]string{"testdata/policy_harness.mjs", "opencode-policy.js"}, args...)...)
}

// TestOpencodePolicyNodeHarness exercises the embedded opencode policy plugin against a real
// sidecar server: the tool mapping, the path normalization, the patch parsing, and the
// fail-closed rules of each hook.
func TestOpencodePolicyNodeHarness(t *testing.T) {
	runPolicyHarness(t, agenttest.ServeScripted(t), "events")
}

// harnessToolCall runs one execute.before through the plugin and returns the thrown message,
// or "" when the call is allowed.
func harnessToolCall(t *testing.T, socket, tool string, input map[string]any) string {
	t.Helper()
	arg, err := json.Marshal(map[string]any{"tool": tool, "input": input})
	if err != nil {
		t.Fatal(err)
	}
	out := runPolicyHarness(t, socket, "tool", string(arg))
	var rep struct {
		Threw *string `json:"threw"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("harness output %q: %v", out, err)
	}
	if rep.Threw == nil {
		return ""
	}
	return *rep.Threw
}

// TestOpencodePolicyNodeFilesystemParity checks the plugin's filesystem answers against the hook's.
func TestOpencodePolicyNodeFilesystemParity(t *testing.T) {
	agenttest.FilesystemParity(t, func(socket string) {
		if threw := harnessToolCall(t, socket, "read", map[string]any{"path": "/x"}); threw != "" {
			t.Fatalf("tool call: threw %q", threw)
		}
	})
}

// TestOpencodePolicyNodeParityProtectedSymlink writes through a symlink that a process in the
// sandbox created to a protected file. The policy resolves the link through the plugin.
func TestOpencodePolicyNodeParityProtectedSymlink(t *testing.T) {
	socket, link, other := agenttest.ProtectedSymlink(t)
	if threw := harnessToolCall(t, socket, "write", map[string]any{"path": link, "content": "x"}); !strings.HasPrefix(threw, "blocked by corral policy [hook:blocked-path]") {
		t.Fatalf("write through %s: want a blocked-path deny, got threw %q", link, threw)
	}
	if threw := harnessToolCall(t, socket, "write", map[string]any{"path": other, "content": "x"}); threw != "" {
		t.Fatalf("write to an unprotected path: want allow, got threw %q", threw)
	}
}

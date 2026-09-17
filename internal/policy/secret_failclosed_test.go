package policy

import (
	"encoding/json"
	"testing"
)

// TestSecretScanRuleUnparseableInputFailsClosed reaches the read and write scanner branches
// directly because a full engine rejects the input before this rule.
func TestSecretScanRuleUnparseableInputFailsClosed(t *testing.T) {
	r := &SecretScanRule{}
	cases := []struct{ name, tool, input string }{
		{"write-string", "Write", `"not-an-object"`},
		{"edit-array", "Edit", `[1,2]`},
		{"multiedit-number", "MultiEdit", `42`},
		{"read-number", "Read", `42`},
		{"read-array", "Read", `[1,2]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &HookEvent{ToolName: tc.tool, ToolInput: json.RawMessage(tc.input)}
			if _, _, err := r.Evaluate(ev); err == nil {
				t.Fatalf("%s with unparseable tool_input must error (fail closed)", tc.tool)
			}
		})
	}
}

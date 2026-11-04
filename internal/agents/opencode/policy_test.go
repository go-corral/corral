package opencode

import (
	"regexp"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/internal/agenttest"
	"github.com/go-corral/corral/internal/sandbox"
)

var (
	importLine = regexp.MustCompile(`(?m)^[ \t]*import\b.*$`)
	nodeImport = regexp.MustCompile(`^import (\* as \w+|\{[\w, ]+\}|\w+) from "node:[\w/]+";$`)
	typeSyntax = regexp.MustCompile(`(?m)^[ \t]*(export\s+)?(interface|type)\s+\w+|:\s*(string|number|boolean|any|unknown|void|never)\b|\bas\s+(string|number|boolean|any|unknown|const)\b|\brequire\s*\(|\bimport\s*\(`)
)

// assertPlainJS checks that src loads as plain JavaScript with Node built-ins only: every import
// is a one-line import of a node: module, and src has no type syntax, require, or dynamic import.
func assertPlainJS(t *testing.T, name, src string) {
	t.Helper()
	if len(src) == 0 {
		t.Fatalf("%s is empty — the //go:embed did not take", name)
	}
	for _, line := range importLine.FindAllString(src, -1) {
		if !nodeImport.MatchString(strings.TrimSpace(line)) {
			t.Errorf("%s: import is not a one-line node: import: %q", name, line)
		}
	}
	for _, m := range typeSyntax.FindAllString(src, -1) {
		t.Errorf("%s: type syntax, require, or dynamic import: %q", name, m)
	}
}

// TestOpencodePolicySourceWellFormed pins the embedded plugin's load-bearing shape so a careless
// edit cannot silently drop a hook or the sidecar wiring.
func TestOpencodePolicySourceWellFormed(t *testing.T) {
	src := string(policySource)
	assertPlainJS(t, "opencode-policy.js", src)
	agenttest.AssertContains(t, "embedded opencode policy plugin", src,
		`export default { id: "corral-policy", setup };`,
		`ctx.tool.hook("execute.before"`,
		`ctx.tool.hook("execute.after"`,
		`ctx.session.hook("prompt"`,
		`ctx.session.hook("context"`,
		`"pre-tool-use", "exit2"`,
		`"post-tool-use"`,
		`"user-prompt-submit"`,
		`"session-start"`,
		sandbox.SidecarSocketEnvVar,
	)
	if strings.Contains(src, "CORRAL_BIN") {
		t.Error("embedded opencode policy plugin names CORRAL_BIN")
	}
}

func TestOpencodePolicyFailureTexts(t *testing.T) {
	agenttest.AssertFailureTexts(t, "embedded opencode policy plugin", string(policySource))
}

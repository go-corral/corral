package claudecfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The PreToolUse matcher must cover MCP tools, and corral must register a
// PostToolUse hook (matched on Bash, Grep, and MCP tools) for the response ingress scan. The
// golden files encode the full rendered settings; these assert the load-bearing specifics so a
// regression is legible even before eyeballing a golden diff.

func TestDefaultMatcherCoversMCPTools(t *testing.T) {
	// The PreToolUse matcher must cover MCP tools. "*" is Claude Code's match-all value,
	// which covers every tool (MCP included); otherwise the matcher must explicitly carry
	// the mcp__.* arm.
	if DefaultMatcher != "*" && !strings.Contains(DefaultMatcher, "mcp__.*") {
		t.Errorf("DefaultMatcher must cover MCP tool names (\"*\" or mcp__.*): %q", DefaultMatcher)
	}
	if PostToolUseMatcher != "Bash|Grep|mcp__.*" {
		t.Errorf("PostToolUseMatcher must cover Bash, Grep, and MCP tools: %q", PostToolUseMatcher)
	}
}

func TestSyncRegistersPostToolUseForMCP(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/opt/corral"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	groups, ok := top.Hooks["PostToolUse"]
	if !ok {
		t.Fatal("corral must register a PostToolUse hook (#19)")
	}
	var found bool
	for _, g := range groups {
		for _, h := range g.Hooks {
			if _, sub, ok := parseGuardedCommand(h.Command); ok && sub == "hook post-tool-use" {
				found = true
				if g.Matcher != "Bash|Grep|mcp__.*" {
					t.Errorf("PostToolUse matcher must be Bash|Grep|mcp__.*  (Bash, Grep, and MCP), got %q", g.Matcher)
				}
			}
		}
	}
	if !found {
		t.Error("PostToolUse must invoke `corral hook post-tool-use`")
	}
}

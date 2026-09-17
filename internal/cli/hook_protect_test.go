package cli

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"

	"github.com/go-corral/corral/internal/config"
)

// TestAgentProtectedPaths covers the cli-level wrapper around the agent seam: it
// resolves the active agent, then canonicalizes and de-duplicates the raw paths the agent
// derives from its live config under configDir. The agent-specific parsing itself is tested with
// each implementation (e.g. internal/agents/claude); here we pin the canonicalize+dedup step and
// the agent resolution (including the defensive fallback for an unknown agent).
func TestAgentProtectedPaths(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The same hook script in two lexical forms (one with a "..") plus a unique one, split across
	// two merged settings files: canonicalization collapses the "..", so the dedup step must
	// return the script once.
	write("settings.json", `{"hooks":{"PreToolUse":[{"hooks":[
		{"type":"command","command":"/opt/guard/x/../a.sh"}
	]}]}}`)
	write("settings.local.json", `{"hooks":{"SessionStart":[{"hooks":[
		{"type":"command","command":"/opt/guard/a.sh"},
		{"type":"command","command":"/opt/guard/b.sh"}
	]}]}}`)

	claudeWant := []string{"/opt/guard/a.sh", "/opt/guard/b.sh"}
	cases := []struct {
		name  string
		agent string
		want  []string
	}{
		{"claude derives, canonicalizes, dedups", "claude", claudeWant},
		{"unknown agent falls back to default (claude)", "bogus", claudeWant},
		{"pi contributes none", "pi", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := agentProtectedPaths(&config.Config{Agent: tc.agent}, dir)
			sort.Strings(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("agentProtectedPaths = %v, want %v", got, tc.want)
			}
		})
	}
}

package claude

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/spec"
)

func TestClaudeIdentity(t *testing.T) {
	a := New()
	if a.Name() != "claude" {
		t.Errorf("claude agent Name() = %q, want %q", a.Name(), "claude")
	}
	if !slices.Equal(a.Binaries(), []string{"claude"}) {
		t.Errorf("Binaries() = %v, want [claude] (first entry is also the exec fallback)", a.Binaries())
	}
}

// TestClaudeConfigDir pins ConfigDir's resolution: the CLAUDE_CONFIG_DIR override (trimmed) if
// set, otherwise <home>/.claude. A whitespace-only override falls back to the default.
func TestClaudeConfigDir(t *testing.T) {
	const home = "/home/u"
	a := New()
	tests := []struct {
		name string
		host map[string]string
		want string
	}{
		{"unset", nil, filepath.Join(home, ".claude")},
		{"empty", map[string]string{"CLAUDE_CONFIG_DIR": ""}, filepath.Join(home, ".claude")},
		{"whitespace", map[string]string{"CLAUDE_CONFIG_DIR": "   "}, filepath.Join(home, ".claude")},
		{"override", map[string]string{"CLAUDE_CONFIG_DIR": "/custom/claude"}, "/custom/claude"},
		{"override trimmed", map[string]string{"CLAUDE_CONFIG_DIR": "  /custom/claude  "}, "/custom/claude"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.ConfigDir(home, tt.host); got != tt.want {
				t.Errorf("ConfigDir(%q, %v) = %q, want %q", home, tt.host, got, tt.want)
			}
		})
	}
}

// TestClaudeLaunchConnectorsEnv pins the connectors kill switch: off (the default) sets
// ENABLE_CLAUDEAI_MCP_SERVERS=false; on omits it so connectors load per Claude's own rules.
func TestClaudeLaunchConnectorsEnv(t *testing.T) {
	if off := (Config{}).SandboxEnv(); off["ENABLE_CLAUDEAI_MCP_SERVERS"] != "false" {
		t.Errorf("connectors off: SandboxEnv[ENABLE_CLAUDEAI_MCP_SERVERS] = %q, want \"false\"", off["ENABLE_CLAUDEAI_MCP_SERVERS"])
	}
	if on := (Config{ClaudeaiConnectors: true}).SandboxEnv(); on["ENABLE_CLAUDEAI_MCP_SERVERS"] != "" {
		t.Errorf("connectors on: SandboxEnv must omit ENABLE_CLAUDEAI_MCP_SERVERS; got %v", on)
	}
}

// TestClaudeTempEnvAliases pins the agent-supplied temp-dir override a temp-isolating backend
// repoints: claude declares CLAUDE_CODE_TMPDIR.
func TestClaudeTempEnvAliases(t *testing.T) {
	a := New()
	if got := a.Launch().TempEnvAliases; !slices.Equal(got, []string{"CLAUDE_CODE_TMPDIR"}) {
		t.Errorf("claude TempEnvAliases = %v, want [CLAUDE_CODE_TMPDIR]", got)
	}
}

// TestClaudeReservedEnv pins claude's reserved-env contribution: config reserves the connectors
// kill switch and every phone-home / attribution var from env.set, so a config typo cannot
// silently flip connectors on or undo the privacy hardening out of band.
func TestClaudeReservedEnv(t *testing.T) {
	a := New()
	for _, name := range []string{
		"ENABLE_CLAUDEAI_MCP_SERVERS",
		"DISABLE_TELEMETRY",
		"DISABLE_ERROR_REPORTING",
		"CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY",
		"CLAUDE_CODE_ATTRIBUTION_HEADER",
		"CLAUDE_CODE_DISABLE_AGENT_VIEW",
	} {
		if !slices.Contains(a.ReservedEnv(), name) {
			t.Errorf("claude.ReservedEnv() = %v, want it to reserve %q", a.ReservedEnv(), name)
		}
	}
}

// TestClaudePrivacyEnv pins the phone-home / attribution kill switches: each capability, when
// denied (the hardened default, the zero value), sets Claude Code's own env var; when allowed it
// is omitted. AttributionHeader is inverted — enabled (Claude's default) omits the var; disabled
// sets =0.
func TestClaudePrivacyEnv(t *testing.T) {
	// Fully hardened (zero value): every kill switch is set to its disable value.
	hardened := (Config{}).SandboxEnv()
	for k, want := range map[string]string{
		"DISABLE_TELEMETRY":                   "1",
		"DISABLE_ERROR_REPORTING":             "1",
		"CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY": "1",
		"CLAUDE_CODE_ATTRIBUTION_HEADER":      "0",
		"CLAUDE_CODE_DISABLE_AGENT_VIEW":      "1",
	} {
		if hardened[k] != want {
			t.Errorf("hardened SandboxEnv[%s] = %q, want %q", k, hardened[k], want)
		}
	}

	// Fully opted back on: no phone-home / attribution var is contributed at all.
	on := Config{
		ClaudeaiConnectors: true,
		Telemetry:          true,
		ErrorReporting:     true,
		FeedbackSurvey:     true,
		AttributionHeader:  true,
		AgentView:          true,
	}.SandboxEnv()
	if on != nil {
		t.Errorf("all capabilities enabled: SandboxEnv must be nil (contribute nothing), got %v", on)
	}

	// The attribution var is omitted when enabled, present (=0) only when disabled.
	if v := (Config{AttributionHeader: true}).SandboxEnv()["CLAUDE_CODE_ATTRIBUTION_HEADER"]; v != "" {
		t.Errorf("attribution enabled: CLAUDE_CODE_ATTRIBUTION_HEADER must be omitted, got %q", v)
	}
}

// TestClaudeConfigPaths pins claude's out-of-config-dir filesystem grants: ~/.claude.json (all
// archs, single node, optional) and ~/.local/share/claude (the native-installer binary tree, all
// archs, read-only, optional), plus the macOS-only atomic-write regex sibling and node cache.
// This is what keeps the embedded baseline agent-neutral — the regression guard for the
// cross-agent leak where `corral run pi` bound ~/.claude.json.
func TestClaudeConfigPaths(t *testing.T) {
	paths := New().ConfigPaths()

	var bare, binDir *spec.ConfigPath
	macOnly := 0
	for i := range paths {
		p := &paths[i]
		switch {
		case p.Path == "$HOME/.claude.json":
			bare = p
		case p.Path == "$HOME/.local/share/claude":
			binDir = p
		case slices.Equal(p.Archs, []string{"macos"}):
			macOnly++
		}
	}
	if bare == nil {
		t.Fatalf("claude ConfigPaths missing $HOME/.claude.json: %+v", paths)
	}
	if len(bare.Archs) != 0 {
		t.Errorf("$HOME/.claude.json must be all-archs (so it applies on Linux too), got archs=%v", bare.Archs)
	}
	if !bare.Writeable || !bare.Optional {
		t.Errorf("$HOME/.claude.json must be writeable+optional, got %+v", *bare)
	}
	if bare.Recursive == nil || *bare.Recursive {
		t.Errorf("$HOME/.claude.json must be a single node (recursive=false), got recursive=%v", bare.Recursive)
	}
	// The native-installer binary tree: the launcher at ~/.local/bin/claude symlinks into here,
	// so the sandboxed exec fails without this bind. All-archs (same ~/.local layout on Linux and
	// macOS), read-only (exec, don't overwrite the running binary), optional (npm installs skip it).
	if binDir == nil {
		t.Fatalf("claude ConfigPaths missing $HOME/.local/share/claude (native-installer binary): %+v", paths)
	}
	if len(binDir.Archs) != 0 {
		t.Errorf("$HOME/.local/share/claude must be all-archs (so it applies on Linux too), got archs=%v", binDir.Archs)
	}
	if binDir.Writeable {
		t.Errorf("$HOME/.local/share/claude must be read-only (agent may exec but not overwrite its binary), got writeable")
	}
	if !binDir.Optional {
		t.Errorf("$HOME/.local/share/claude must be optional (npm-global installs lack it), got %+v", *binDir)
	}
	if macOnly != 2 {
		t.Errorf("claude must contribute 2 macOS-only ConfigPaths (regex sibling + node cache), got %d: %+v", macOnly, paths)
	}
}

// TestClaudeFootprint pins claude's static enforcement footprint the hook self-protects: the
// ".claude" marker, the three merged settings kill-switch files (built from settingsFiles), and the
// hooks/ subtree. The reason strings are load-bearing — they must stay byte-identical to what
// corral gated before this became agent data.
func TestClaudeFootprint(t *testing.T) {
	fp := New().Footprint()
	if fp.Dir != ".claude" || fp.DirReason != "Claude Code's config directory" {
		t.Errorf("Footprint dir = %q/%q, want .claude / Claude Code's config directory", fp.Dir, fp.DirReason)
	}
	wantFiles := map[string]string{
		"settings.json":         "Claude Code's settings.json",
		"settings.local.json":   "Claude Code's settings.local.json",
		"managed-settings.json": "Claude Code's managed-settings.json",
	}
	for name, reason := range wantFiles {
		if fp.ProtectedFiles[name] != reason {
			t.Errorf("ProtectedFiles[%q] = %q, want %q", name, fp.ProtectedFiles[name], reason)
		}
	}
	if len(fp.ProtectedFiles) != len(wantFiles) {
		t.Errorf("ProtectedFiles = %v, want exactly the merged settings kill-switch set", fp.ProtectedFiles)
	}
	if got := fp.ProtectedDirs["hooks"]; got != "Claude Code's hooks directory" {
		t.Errorf("ProtectedDirs[hooks] = %q, want Claude Code's hooks directory", got)
	}
	if len(fp.ProtectedDirs) != 1 {
		t.Errorf("ProtectedDirs = %v, want only hooks/", fp.ProtectedDirs)
	}
}

// containsLine reports whether any line contains sub. Shared by this package's report assertions.
func containsLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

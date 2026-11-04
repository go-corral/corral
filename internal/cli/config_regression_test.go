package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
)

// config.Net == NetNone sets params.Net = NetNone.
func TestSpecParamsNetNone(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Net: config.NetNone,
	}
	host := map[string]string{}

	params := specParams(cfg, home, proj, host, "")

	// The sandbox package's NetNone must be set (it's an enum, not a string method)
	if params.Net != sandbox.NetNone {
		t.Errorf("specParams with Net=NetNone: got %v, want NetNone", params.Net)
	}
}

// config.Net != NetNone (or the zero value) sets params.Net = NetOpen.
func TestSpecParamsNetOpen(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Net: config.NetOpen, // or default (zero value)
	}
	host := map[string]string{}

	params := specParams(cfg, home, proj, host, "")

	// Default should be NetOpen
	if params.Net != sandbox.NetOpen {
		t.Errorf("specParams with Net=NetOpen (or default): got %v, want NetOpen", params.Net)
	}
}

// An enabled home provider sets SandboxHome to the private home.
func TestSpecParamsHomeProviderEnabled(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Providers.Home.Enabled = true
	// Path is empty, so it will use the default: the keyed home for the default agent's config dir.
	host := map[string]string{}
	privateHome, ok := homeDir(cfg, home, host)
	if !ok {
		t.Fatal("homeDir: provider unexpectedly disabled")
	}

	params := specParams(cfg, home, proj, host, "")

	// SandboxHome must be set to the private home
	if params.SandboxHome == "" {
		t.Errorf("specParams with home provider enabled: SandboxHome is empty, want private home")
	}
	if params.SandboxHome != privateHome {
		t.Errorf("specParams with home provider enabled: got %q, want %q", params.SandboxHome, privateHome)
	}
}

// A disabled home provider leaves SandboxHome empty.
func TestSpecParamsHomeProviderDisabled(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Providers.Home.Enabled = false

	host := map[string]string{}

	params := specParams(cfg, home, proj, host, "")

	// SandboxHome should be empty when home provider is disabled
	if params.SandboxHome != "" {
		t.Errorf("specParams with home provider disabled: SandboxHome = %q, want empty", params.SandboxHome)
	}
}

// agentView only toggles CLAUDE_CODE_DISABLE_AGENT_VIEW; every other sandbox param stays equal.
func TestSpecParamsAgentViewOnlyChangesEnv(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	build := func(agent string, agentView bool) sandbox.DefaultParams {
		cfg := &config.Config{Agent: agent}
		cfg.Agents.Claude.AgentView = agentView
		return specParams(cfg, home, proj, map[string]string{}, "")
	}

	off, on := build("claude", false), build("claude", true)
	if off.AgentEnv["CLAUDE_CODE_DISABLE_AGENT_VIEW"] != "1" {
		t.Errorf("agentView false: AgentEnv = %v, want CLAUDE_CODE_DISABLE_AGENT_VIEW=1", off.AgentEnv)
	}
	if _, ok := on.AgentEnv["CLAUDE_CODE_DISABLE_AGENT_VIEW"]; ok {
		t.Errorf("agentView true: AgentEnv = %v, want no CLAUDE_CODE_DISABLE_AGENT_VIEW", on.AgentEnv)
	}
	delete(off.AgentEnv, "CLAUDE_CODE_DISABLE_AGENT_VIEW")
	if !reflect.DeepEqual(off, on) {
		t.Errorf("agentView must change only CLAUDE_CODE_DISABLE_AGENT_VIEW:\noff: %+v\non:  %+v", off, on)
	}

	for _, agentView := range []bool{false, true} {
		for _, agent := range []string{"pi", "opencode"} {
			if _, ok := build(agent, agentView).AgentEnv["CLAUDE_CODE_DISABLE_AGENT_VIEW"]; ok {
				t.Errorf("%s with agentView %v: AgentEnv must not contain CLAUDE_CODE_DISABLE_AGENT_VIEW", agent, agentView)
			}
		}
	}
}

// opencode adds its data and installer grants; no other agent gets them, and no rule names
// opencode's state or cache directories.
func TestSpecRulesOpencodeGrants(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	rules := func(agent string) map[string]sandbox.Rule {
		cfg := &config.Config{Agent: agent}
		spec := sandbox.DefaultSpec(specParams(cfg, home, proj, map[string]string{}, ""))
		m := map[string]sandbox.Rule{}
		for _, r := range sandbox.RulesFor(spec) {
			m[r.Path] = r
		}
		return m
	}

	oc := rules("opencode")
	if r, ok := oc["$HOME/.local/share/opencode"]; !ok || !r.Writeable || !r.Optional {
		t.Errorf("opencode data rule = %+v (present %v), want read-write optional", r, ok)
	}
	if r, ok := oc["$HOME/.opencode/bin"]; !ok || r.Writeable || !r.Optional {
		t.Errorf("opencode installer rule = %+v (present %v), want read-only optional", r, ok)
	}
	for path := range oc {
		if strings.Contains(path, ".local/state/opencode") || strings.Contains(path, ".cache/opencode") {
			t.Errorf("opencode must not grant %q", path)
		}
	}
	for _, agent := range []string{"claude", "pi"} {
		for path := range rules(agent) {
			if strings.Contains(path, "opencode") {
				t.Errorf("%s must not carry the opencode rule %q", agent, path)
			}
		}
	}
}

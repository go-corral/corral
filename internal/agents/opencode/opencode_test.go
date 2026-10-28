package opencode

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestLaunchArgsPinsStandalone(t *testing.T) {
	for _, tc := range []struct {
		in, want []string
	}{
		{nil, []string{"--standalone"}},
		{[]string{"./src"}, []string{"./src", "--standalone"}},
		{[]string{"run", "fix the tests"}, []string{"run", "fix the tests", "--standalone"}},
		{[]string{"run", "--standalone", "hi"}, []string{"run", "--standalone", "hi"}},
		{[]string{"run", "--", "--literal"}, []string{"run", "--standalone", "--", "--literal"}},
		{[]string{"mcp", "list"}, []string{"mcp", "list"}},
		{[]string{"acp", "--print-logs"}, []string{"acp", "--print-logs"}},
	} {
		got, err := launchArgs(tc.in)
		if err != nil {
			t.Errorf("launchArgs(%q): %v", tc.in, err)
			continue
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("launchArgs(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestLaunchArgsRejects(t *testing.T) {
	for _, in := range [][]string{
		{"--server", "http://127.0.0.1:49374"},
		{"run", "--server=http://127.0.0.1:49374", "hi"},
		{"--auto"},
		{"run", "--auto", "hi"},
		{"--yolo"},
		{"run", "--dangerously-skip-permissions", "hi"},
	} {
		if got, err := launchArgs(in); err == nil {
			t.Errorf("launchArgs(%q) = %q, want an error", in, got)
		}
	}
}

func TestActivationEnvLoadsPluginDirWithAskFallback(t *testing.T) {
	t.Setenv(configContentEnv, "")
	env := activationEnv("/home/u/.cache/corral/opencode-policy/index.js")
	var cfg struct {
		Plugins     []string            `json:"plugins"`
		Permissions []map[string]string `json:"permissions"`
	}
	if err := json.Unmarshal([]byte(env[configContentEnv]), &cfg); err != nil {
		t.Fatalf("%s is not JSON: %v", configContentEnv, err)
	}
	if !slices.Equal(cfg.Plugins, []string{"/home/u/.cache/corral/opencode-policy"}) {
		t.Errorf("plugins = %q, want the extension directory", cfg.Plugins)
	}
	if len(cfg.Permissions) != 1 || cfg.Permissions[0]["effect"] != "ask" || cfg.Permissions[0]["action"] != "*" {
		t.Errorf("permissions = %v, want one catch-all ask rule", cfg.Permissions)
	}
}

func TestActivationEnvKeepsHostConfig(t *testing.T) {
	t.Setenv(configContentEnv, `{"default_agent":"copilot-build","plugins":["/copilot"],"permissions":[{"action":"websearch","resource":"*","effect":"deny"}]}`)
	env := activationEnv("/home/u/.cache/corral/opencode-policy/index.js")
	var cfg struct {
		DefaultAgent string              `json:"default_agent"`
		Plugins      []string            `json:"plugins"`
		Permissions  []map[string]string `json:"permissions"`
	}
	if err := json.Unmarshal([]byte(env[configContentEnv]), &cfg); err != nil {
		t.Fatalf("%s is not JSON: %v", configContentEnv, err)
	}
	if cfg.DefaultAgent != "copilot-build" {
		t.Errorf("default_agent = %q, want the host value", cfg.DefaultAgent)
	}
	if !slices.Equal(cfg.Plugins, []string{"/copilot", "/home/u/.cache/corral/opencode-policy"}) {
		t.Errorf("plugins = %q, want the host plugin, then the extension directory", cfg.Plugins)
	}
	if len(cfg.Permissions) != 2 || cfg.Permissions[0]["effect"] != "ask" || cfg.Permissions[1]["effect"] != "deny" {
		t.Errorf("permissions = %v, want the ask rule before the host rules", cfg.Permissions)
	}
}

func TestBridgeIsEmbedded(t *testing.T) {
	if !strings.Contains(string(bridgeSource), `ctx.tool.hook("execute.before"`) {
		t.Error("embedded bridge does not register execute.before")
	}
}

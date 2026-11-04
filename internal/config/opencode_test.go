package config

import (
	"slices"
	"strings"
	"testing"
)

func TestOpencodeAgentConfig(t *testing.T) {
	cfg, _, err := loadFrom(t, "", "agent: opencode\nagents:\n  opencode:\n    args: [--print-logs]\n", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveAgent() != "opencode" {
		t.Errorf("EffectiveAgent = %q, want opencode", cfg.EffectiveAgent())
	}
	if want := []string{"--print-logs"}; !slices.Equal(cfg.AgentArgs(), want) {
		t.Errorf("AgentArgs = %v, want %v", cfg.AgentArgs(), want)
	}
	if got := cfg.AgentEnv()["OPENCODE_DISABLE_AUTOUPDATE"]; got != "1" {
		t.Errorf("AgentEnv OPENCODE_DISABLE_AUTOUPDATE = %q, want 1", got)
	}
	if got := cfg.AgentConfigDir("/home/u", map[string]string{"OPENCODE_CONFIG_DIR": "/srv/oc"}); got != "/srv/oc" {
		t.Errorf("AgentConfigDir with host value = %q, want /srv/oc", got)
	}
	if got := cfg.AgentConfigDir("/home/u", nil); got != "/home/u/.config/opencode" {
		t.Errorf("AgentConfigDir default = %q, want /home/u/.config/opencode", got)
	}
	if !slices.Contains(cfg.Providers.Env.Passthrough, "OPENCODE_CONFIG_DIR") {
		t.Errorf("default passthrough = %v, want OPENCODE_CONFIG_DIR", cfg.Providers.Env.Passthrough)
	}
}

func TestOpencodeAgentsKeyStrict(t *testing.T) {
	if _, _, err := loadFrom(t, "", "agents:\n  opencode: {}\n", "", ""); err != nil {
		t.Fatalf("agents.opencode: {} must load: %v", err)
	}
	_, _, err := loadFrom(t, "", "agents:\n  opencode: {share: false}\n", "", "")
	if err == nil || !strings.Contains(err.Error(), "share") {
		t.Fatalf("agents.opencode.share must fail naming the key, got %v", err)
	}
}

func TestOpencodeEnvSetRejected(t *testing.T) {
	for _, name := range []string{"OPENCODE_CONFIG_CONTENT", "OPENCODE_CONFIG_DIR"} {
		_, _, err := loadFrom(t, "", "providers:\n  env:\n    set:\n      - {name: "+name+", value: x}", "", "")
		want := `providers.env.set: "` + name + `" is reserved by corral and cannot be set`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("env.set naming %s: got err %v, want it to contain %q", name, err, want)
		}
	}
}

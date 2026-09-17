package env

import (
	"strings"
	"testing"
)

// Validate owns the env passthrough/set rules; config supplies the reserved sets. These
// exercise the method directly (config's Load tests prove the wiring end-to-end).
func TestValidate(t *testing.T) {
	core := []string{"CORRAL_SANDBOX", "CORRAL_GLOBAL_CONFIG"}
	all := map[string]bool{"CORRAL_SANDBOX": true, "ENABLE_CLAUDEAI_MCP_SERVERS": true}

	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = expect success
	}{
		{"valid", Config{Passthrough: []string{"TERM", "MY_VAR2"}, Set: []Var{{Name: "FOO", Value: "bar"}}}, ""},
		{"bad passthrough name", Config{Passthrough: []string{"MY VAR"}}, "is not a valid environment variable name"},
		{"core-reserved passthrough", Config{Passthrough: []string{"CORRAL_SANDBOX"}}, "is reserved by corral and cannot be forwarded"},
		{"bad set name", Config{Set: []Var{{Name: "1ABC", Value: "x"}}}, "is not a valid environment variable name"},
		{"reserved set name", Config{Set: []Var{{Name: "ENABLE_CLAUDEAI_MCP_SERVERS", Value: "x"}}}, "is reserved by corral and cannot be set"},
		{"passthrough/set conflict", Config{Passthrough: []string{"MY_VAR"}, Set: []Var{{Name: "MY_VAR", Value: "x"}}}, "is in both passthrough and set"},
		{"duplicate set", Config{Set: []Var{{Name: "FOO", Value: "a"}, {Name: "FOO", Value: "b"}}}, "is set more than once"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate(core, all)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestIsEnvName(t *testing.T) {
	for _, name := range []string{"FOO", "FOO_BAR", "FOO_BAR_123", "FOO123", "_FOO", "_"} {
		if !isEnvName(name) {
			t.Errorf("isEnvName(%q) = false, want true (valid name)", name)
		}
	}
	for _, name := range []string{"", "1FOO", "FOO-BAR", "FOO BAR", "FOO.BAR", "FOO*", "FOO?"} {
		if isEnvName(name) {
			t.Errorf("isEnvName(%q) = true, want false (invalid name)", name)
		}
	}
}

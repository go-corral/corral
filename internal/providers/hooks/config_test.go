package hooks

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestHookIsEnabled(t *testing.T) {
	if !(Hook{}).IsEnabled() {
		t.Error("an absent enabled (nil) must default to enabled")
	}
	if !(Hook{Enabled: boolPtr(true)}).IsEnabled() {
		t.Error("enabled: true must be enabled")
	}
	if (Hook{Enabled: boolPtr(false)}).IsEnabled() {
		t.Error("enabled: false must be disabled (the tombstone)")
	}
}

func TestConfigEnabled(t *testing.T) {
	if (Config{}).Enabled() {
		t.Error("an empty config must be inert")
	}
	// Only a disabled entry → still inert.
	only := Config{PreStart: map[string]Hook{"10-a": {Exec: "x", Enabled: boolPtr(false)}}}
	if only.Enabled() {
		t.Error("a config with only disabled entries must be inert")
	}
	if !(Config{PreStart: map[string]Hook{"10-a": {Exec: "x"}}}).Enabled() {
		t.Error("an enabled preStart entry must enable the provider")
	}
	if !(Config{PostEnd: map[string]Hook{"report": {Exec: "x"}}}).Enabled() {
		t.Error("an enabled postEnd entry must enable the provider")
	}
}

func TestConfigValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = must pass
	}{
		{"empty ok", Config{}, ""},
		{"good run-parts keys", Config{PreStart: map[string]Hook{
			"10-update": {Exec: "./u.sh"}, "20-check": {Exec: "./c.sh", Optional: true},
		}, PostEnd: map[string]Hook{"session.report": {Exec: "./r.sh"}}}, ""},
		{"enabled empty script rejected", Config{PreStart: map[string]Hook{"10-a": {Exec: ""}}},
			"providers.hooks.preStart.10-a: exec must not be empty"},
		{"disabled empty script ok", Config{PreStart: map[string]Hook{"10-a": {Exec: "", Enabled: boolPtr(false)}}}, ""},
		{"postEnd empty script attributed to postEnd", Config{PostEnd: map[string]Hook{"report": {Exec: ""}}},
			"providers.hooks.postEnd.report: exec must not be empty"},
		{"space in key rejected", Config{PreStart: map[string]Hook{"bad key": {Exec: "x"}}},
			"providers.hooks.preStart"},
		{"leading dot key rejected", Config{PreStart: map[string]Hook{".hidden": {Exec: "x"}}},
			"invalid key"},
		// A disabled entry's key is still charset-checked (it could be re-enabled by a layer).
		{"disabled entry key still checked", Config{PostEnd: map[string]Hook{"has/slash": {Exec: "x", Enabled: boolPtr(false)}}},
			"providers.hooks.postEnd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestConfigGrants(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"one hook is singular", Config{PreStart: map[string]Hook{"10-a": {Exec: "x"}}},
			"runs 1 pre-start / 0 post-end host session hook"},
		{"several are plural", Config{
			PreStart: map[string]Hook{"10-a": {Exec: "x"}, "20-b": {Exec: "y"}},
			PostEnd:  map[string]Hook{"report": {Exec: "z"}},
		}, "runs 2 pre-start / 1 post-end host session hooks"},
		// Disabled entries are not counted.
		{"disabled not counted", Config{PreStart: map[string]Hook{
			"10-a": {Exec: "x"}, "20-b": {Exec: "y", Enabled: boolPtr(false)},
		}}, "runs 1 pre-start / 0 post-end host session hook"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.Grants(); got != tc.want {
				t.Errorf("Grants() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestConfigFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{
			"required pre-start",
			Config{PreStart: map[string]Hook{"required": {Exec: "x"}}},
			"required pre-start failures abort launch",
		},
		{
			"all hook kinds",
			Config{
				PreStart: map[string]Hook{
					"required": {Exec: "x"},
					"optional": {Exec: "y", Optional: true},
					"disabled": {Exec: "z", Enabled: boolPtr(false)},
				},
				PostEnd: map[string]Hook{"report": {Exec: "z"}},
			},
			"required pre-start failures abort launch; optional pre-start failures continue; post-end failures warn",
		},
		{
			"post-end only",
			Config{PostEnd: map[string]Hook{"report": {Exec: "z"}}},
			"post-end failures warn",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.FailurePolicy(); got != tc.want {
				t.Errorf("FailurePolicy() = %q, want %q", got, tc.want)
			}
		})
	}
}

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
)

// A profile's providers.block entry takes effect in the hook only through the session pin.
func TestHookAppliesSessionProfile(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, "strict-only.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgYAML := "profiles:\n  strict:\n    providers:\n      block:\n        files:\n          - " + secret + "\n"
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	for _, tc := range []struct {
		profiles string
		want     int
	}{
		{profiles: "strict", want: policy.ExitBlock},
		{profiles: "", want: policy.ExitAllow},
	} {
		t.Setenv(sandbox.ProfilesEnvVar, tc.profiles)
		var code int
		withStdin(t, preToolUseEvent(t, proj, secret), func() {
			code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
		})
		if code != tc.want {
			t.Errorf("%s=%q: got exit %d, want %d", sandbox.ProfilesEnvVar, tc.profiles, code, tc.want)
		}
	}
}

// A session profile the config no longer defines fails each hook event closed.
func TestHookMissingSessionProfile(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	t.Setenv(sandbox.ProfilesEnvVar, "gone")

	var code int
	stderr := captureStderr(t, func() {
		withStdin(t, preToolUseEvent(t, proj, filepath.Join(proj, "notes.txt")), func() {
			code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
		})
	})
	if code != policy.ExitBlock {
		t.Errorf("pre-tool-use: got exit %d, want %d", code, policy.ExitBlock)
	}
	if !strings.Contains(stderr, `"gone"`) {
		t.Errorf("pre-tool-use stderr must name the profile, got:\n%s", stderr)
	}

	ev := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"hello"}}`
	out := captureStdout(t, func() {
		withStdin(t, ev, func() { cmdHook([]string{"post-tool-use"}) })
	})
	if !strings.Contains(out, "tool response withheld") {
		t.Errorf("post-tool-use must write the withheld-marker payload, got:\n%s", out)
	}
}

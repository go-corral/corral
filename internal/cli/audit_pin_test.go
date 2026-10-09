package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
)

// isolateAuditPin points the bare-session hook at a temp home and clears the global-config
// pin, so each test sets only the pin it exercises.
func isolateAuditPin(t *testing.T) string {
	t.Helper()
	bareSession(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv(sandbox.GlobalConfigEnvVar, "")
	return home
}

// auditPinArg is how the dry-run env -i prefix sets CORRAL_AUDIT_PATH to path.
func auditPinArg(path string) string {
	return "'" + sandbox.AuditPathEnvVar + "=" + path + "'"
}

// The launcher pins the default audit log under XDG_STATE_HOME when it is absolute, else under
// ~/.local/state, keyed by the agent config dir the host environment resolves.
func TestRunDryRunPinsDefaultAuditPath(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	defaultState := filepath.Join(home, ".local", "state")
	defaultConfig := filepath.Join(home, ".claude")
	xdg := filepath.Join(home, "xdg-state")
	relocated := filepath.Join(home, "claude-config")

	for _, tc := range []struct {
		name, xdg, configDir, wantState, wantConfig string
	}{
		{"unset", "", "", defaultState, defaultConfig},
		{"absolute XDG_STATE_HOME", xdg, "", xdg, defaultConfig},
		{"relative XDG_STATE_HOME", "state", "", defaultState, defaultConfig},
		{"relocated CLAUDE_CONFIG_DIR", "", relocated, defaultState, relocated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", tc.xdg)
			t.Setenv("CLAUDE_CONFIG_DIR", tc.configDir)
			var code int
			out := captureStdout(t, func() {
				code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
			})
			if code != 0 {
				t.Fatalf("run --dry-run exit=%d", code)
			}
			if want := auditPinArg(defaultAuditPath(tc.wantState, tc.wantConfig)); !strings.Contains(out, want) {
				t.Errorf("dry-run argv must contain %q:\n%s", want, out)
			}
		})
	}
}

// A nested launch prints the path it pins in the banner, not the enclosing session's pin.
func TestRunBannerShowsOwnAuditPath(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	outer := filepath.Join(home, "outer", "corral-audit.jsonl")
	t.Setenv(sandbox.AuditPathEnvVar, outer)

	var code int
	var stderr string
	captureStdout(t, func() {
		stderr = captureStderr(t, func() {
			code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
		})
	})
	if code != 0 {
		t.Fatalf("run --dry-run exit=%d", code)
	}
	own := defaultAuditPath(filepath.Join(home, ".local", "state"), filepath.Join(home, ".claude"))
	if want := "audit events in " + abbrevHome(own, home); !strings.Contains(stderr, want) {
		t.Errorf("banner must contain %q:\n%s", want, stderr)
	}
	if strings.Contains(stderr, abbrevHome(outer, home)) {
		t.Errorf("banner must not show the enclosing session's pin %s:\n%s", outer, stderr)
	}
}

// A bare session and a launch with the same home, XDG_STATE_HOME, and agent config dir append
// to the same default audit log.
func TestBareSessionAndLaunchShareDefaultAuditPath(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	bareSession(t)
	t.Setenv("CLAUDE_CONFIG_DIR", filepath.Join(home, "claude-config"))

	in, err := localEngineInputs()
	if err != nil {
		t.Fatal(err)
	}
	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("run --dry-run exit=%d", code)
	}
	if want := auditPinArg(in.auditPath); !strings.Contains(out, want) {
		t.Errorf("the launch must pin the bare session's audit path %q:\n%s", in.auditPath, out)
	}
}

// The pin wins over policy.audit.path: a PreToolUse decision must append to the pinned
// file, and neither the configured path nor the default may receive a record.
func TestCmdHookAuditPinReceivesRecord(t *testing.T) {
	home := isolateAuditPin(t)

	// Hermetic cwd: the hook walks up from the process cwd for project config.
	proj := t.TempDir()
	cfgPath := filepath.Join(home, "cfg-audit", "corral-audit.jsonl")
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"),
		[]byte("policy:\n  audit:\n    path: "+cfgPath+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(proj)

	pinDir := filepath.Join(home, "pinned")
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(pinDir, "corral-audit.jsonl")
	t.Setenv(sandbox.AuditPathEnvVar, pinned)

	var code int
	withStdin(t, bashPreToolUse("ls -la"), func() {
		code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
	})
	if code != policy.ExitAllow {
		t.Fatalf("benign Bash must allow so a record exists, got %d", code)
	}

	data, err := os.ReadFile(pinned)
	if err != nil {
		t.Fatalf("audit record must land in the pinned file: %v", err)
	}
	for _, want := range []string{`"action":"allow"`, `"tool":"Bash"`} {
		if !strings.Contains(string(data), want) {
			t.Errorf("pinned audit record missing %s:\n%s", want, data)
		}
	}
	// Neither the configured path nor the default receives anything.
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Errorf("policy.audit.path must not receive a record while the pin is set, stat err: %v", err)
	}
	def := defaultAuditPath(filepath.Join(home, ".local", "state"), filepath.Join(home, ".claude"))
	if _, err := os.Stat(def); !os.IsNotExist(err) {
		t.Errorf("the default must not receive a record while the pin is set, stat err: %v", err)
	}
}

// The self-protect gate guards the pinned file and its rotation backups: rm and truncate
// against them deny with the audit-log reason, while a benign command still allows.
func TestCmdHookAuditPinSelfProtect(t *testing.T) {
	home := isolateAuditPin(t)
	t.Chdir(t.TempDir())

	dir := filepath.Join(home, "audit")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	pinned := filepath.Join(dir, "corral-audit.jsonl")
	backup := pinned + ".20260101T000000Z"
	for _, p := range []string{pinned, backup} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(sandbox.AuditPathEnvVar, pinned)

	for _, cmd := range []string{
		"rm -rf " + pinned,
		"rm -rf " + backup,
		"truncate -s 0 " + pinned,
	} {
		var code int
		stderr := captureStderr(t, func() {
			withStdin(t, bashPreToolUse(cmd), func() {
				code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
			})
		})
		if code != policy.ExitBlock {
			t.Errorf("%q must deny, got %d:\n%s", cmd, code, stderr)
		}
		if !strings.Contains(stderr, "audit log") {
			t.Errorf("%q must deny with the audit-log self-protect reason, got:\n%s", cmd, stderr)
		}
	}

	var code int
	withStdin(t, bashPreToolUse("ls -la"), func() {
		code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
	})
	if code != policy.ExitAllow {
		t.Errorf("a benign command must still allow, got %d", code)
	}
}

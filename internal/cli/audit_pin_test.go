package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
)

// isolateAuditPin points the hook at a temp home and clears the global-config pin, so
// each test sets only the pin it exercises.
func isolateAuditPin(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(sandbox.GlobalConfigEnvVar, "")
	return home
}

// The pin wins over policy.audit.path: a PreToolUse decision must append to the pinned
// file, and neither the configured path nor the config-dir default may receive a record.
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
	// Neither the configured path nor the config-dir default receives anything.
	if _, err := os.Stat(cfgPath); !os.IsNotExist(err) {
		t.Errorf("policy.audit.path must not receive a record while the pin is set, stat err: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".claude", "corral-audit.jsonl")); !os.IsNotExist(err) {
		t.Errorf("the config-dir default must not receive a record while the pin is set, stat err: %v", err)
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

package enforce

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
)

// buildAuditor must log allow and deny decisions, and each line must carry the
// structural tool parameters: an allowed Read names what it read, not just that it was allowed.
func TestBuildAuditorLogsAllowAndDenyWithInput(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")

	aud := buildAuditor(&config.Config{}, logPath)

	readEv := &policy.HookEvent{
		SessionID: "s1",
		ToolName:  "Read",
		Cwd:       "/work",
		ToolInput: json.RawMessage(`{"file_path":"/etc/hosts"}`),
	}
	aud(readEv, policy.Decision{Action: policy.Allow})

	bashEv := &policy.HookEvent{
		ToolName:  "Bash",
		ToolInput: json.RawMessage(`{"command":"rm -rf /tmp/x"}`),
	}
	aud(bashEv, policy.Decision{Action: policy.Deny, Rule: "bash-danger", Reason: "rm -rf"})

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 audit lines (allow + deny), got %d: %s", len(lines), data)
	}

	var allow struct {
		Action string          `json:"action"`
		Tool   string          `json:"tool"`
		Input  json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &allow); err != nil {
		t.Fatal(err)
	}
	if allow.Action != "allow" || allow.Tool != "Read" {
		t.Errorf("first line must be the allowed Read: %s", lines[0])
	}
	var ai map[string]any
	if err := json.Unmarshal(allow.Input, &ai); err != nil {
		t.Fatalf("allow line must carry structural input: %v (%s)", err, lines[0])
	}
	if ai["file_path"] != "/etc/hosts" {
		t.Errorf("allow line must record the read path, got %v", ai)
	}

	var deny struct {
		Action string          `json:"action"`
		Input  json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &deny); err != nil {
		t.Fatal(err)
	}
	if deny.Action != "deny" {
		t.Errorf("second line must be the deny: %s", lines[1])
	}
	if !strings.Contains(string(deny.Input), "rm -rf /tmp/x") {
		t.Errorf("deny line must record the command, got %s", deny.Input)
	}
}

// auditProtectedPaths must cover the resolved log path and every timestamped rotation
// backup present at init (gzip'd or not), so the agent can neither truncate the live log
// nor delete a backup. The lock file is not a backup and must not be conflated.
func TestAuditProtectedPathsIncludesBackups(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "corral-audit.jsonl")
	// Live log + two timestamped backups (one gzip'd) + the lock file.
	for _, name := range []string{
		"corral-audit.jsonl",
		"corral-audit.jsonl.20260101T000000Z",
		"corral-audit.jsonl.20260108T000000Z.gz",
		"corral-audit.jsonl.lock",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got := auditProtectedPaths(base, policy.OSFS{})

	// Expect: base + its directory + 2 backups = 4 protected paths; the .lock is excluded.
	if len(got) != 4 {
		t.Fatalf("want 4 protected audit paths (log + dir + 2 backups), got %d: %v", len(got), got)
	}
	canon, _ := policy.CanonicalizeRoot(base, "")
	if got[canon] != "corral's audit log" {
		t.Errorf("base audit log %q not protected: %v", canon, got)
	}
	dc, _ := policy.CanonicalizeRoot(dir, "")
	if got[dc] == "" {
		t.Errorf("audit-log directory %q not protected (rm -rf guard): %v", dir, got)
	}
	for _, b := range []string{"corral-audit.jsonl.20260101T000000Z", "corral-audit.jsonl.20260108T000000Z.gz"} {
		bc, _ := policy.CanonicalizeRoot(filepath.Join(dir, b), "")
		if got[bc] == "" {
			t.Errorf("rotation backup %q not protected: %v", b, got)
		}
	}
	lc, _ := policy.CanonicalizeRoot(base+".lock", "")
	if _, ok := got[lc]; ok {
		t.Errorf("the .lock file must not be treated as a backup: %v", got)
	}
}

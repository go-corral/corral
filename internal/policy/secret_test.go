package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func toolEvent(t *testing.T, tool string, input map[string]any) *HookEvent {
	t.Helper()
	ti, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return &HookEvent{ToolName: tool, ToolInput: ti}
}

func TestScanSecretsKnownFormats(t *testing.T) {
	cases := []struct{ name, content string }{
		{"pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEvDATA\n-----END RSA PRIVATE KEY-----"},
		{"aws", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"},
		{"jwt", "auth: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5Nq"},
		{"github", "token=ghp_" + strings.Repeat("a", 36)},
		{"google", "key=AIza" + strings.Repeat("b", 35)},
		{"stripe", "sk_live_" + strings.Repeat("c", 24)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, hit := scanSecrets([]byte(tc.content), 0); !hit {
				t.Errorf("expected to detect a secret (%s)", tc.name)
			}
		})
	}
}

func TestScanSecretsBenign(t *testing.T) {
	benign := []string{
		"package main\n\nfunc main() {}\n",
		"the quick brown fox jumps over the lazy dog",
		"commit 9f2a1c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90", // 40-hex git SHA
		"550e8400-e29b-41d4-a716-446655440000",            // UUID
		"https://api.example.com/v1/users?token=refresh",
	}
	for _, c := range benign {
		if _, hit := scanSecrets([]byte(c), 0); hit {
			t.Errorf("false positive on benign content: %q", c)
		}
	}
}

func TestScanSecretsEntropyOptIn(t *testing.T) {
	blob := "Xk9Q2mZ7pL4vR1tB8nW3cY6jH0aD5sF2gK8eU4oI1qT7" // high-entropy, not a known format
	if _, hit := scanSecrets([]byte(blob), 0); hit {
		t.Errorf("entropy disabled (threshold 0) must not flag %q", blob)
	}
	if _, hit := scanSecrets([]byte(blob), 4.0); !hit {
		t.Errorf("entropy enabled (threshold 4.0) should flag a high-entropy blob")
	}
}

func TestSecretScanRuleWriteDeniesAndDoesNotLeak(t *testing.T) {
	r := &SecretScanRule{}
	aws := "AKIAIOSFODNN7EXAMPLE"
	d, matched, err := r.Evaluate(toolEvent(t, "Write", map[string]any{
		"file_path": "/tmp/out.txt", "content": "credentials:\n  key = " + aws,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !matched || d.Action != Deny {
		t.Fatalf("writing an AWS key must be denied; got matched=%v action=%v", matched, d.Action)
	}
	if strings.Contains(d.Reason, aws) {
		t.Errorf("deny reason must NOT contain the secret value: %s", d.Reason)
	}
}

func TestSecretScanRuleWriteAllowsBenign(t *testing.T) {
	r := &SecretScanRule{}
	_, matched, err := r.Evaluate(toolEvent(t, "Edit", map[string]any{
		"file_path": "/tmp/x.go", "new_string": "func add(a, b int) int { return a + b }",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Errorf("a benign edit must be allowed")
	}
}

func TestSecretScanRuleReadDetectsRenamedSecret(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "report.txt") // innocuous name, secret content
	if err := os.WriteFile(p, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3Bl...\n-----END OPENSSH PRIVATE KEY-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &SecretScanRule{}
	d, matched, err := r.Evaluate(toolEvent(t, "Read", map[string]any{"file_path": p}))
	if err != nil {
		t.Fatal(err)
	}
	if !matched || d.Action != Deny {
		t.Fatalf("reading a renamed file containing a private key must be denied; got matched=%v", matched)
	}
}

func TestSecretScanRuleReadAllowsBenignAndMissing(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(p, []byte("just some project notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &SecretScanRule{}
	if _, matched, err := r.Evaluate(toolEvent(t, "Read", map[string]any{"file_path": p})); err != nil || matched {
		t.Errorf("benign read must allow (matched=%v err=%v)", matched, err)
	}
	// A missing file is an I/O error, not a policy failure → allow (the Read itself
	// will report the error to the agent).
	missing := filepath.Join(dir, "does-not-exist.txt")
	if _, matched, err := r.Evaluate(toolEvent(t, "Read", map[string]any{"file_path": missing})); err != nil || matched {
		t.Errorf("missing-file read must allow (matched=%v err=%v)", matched, err)
	}
}

func TestSecretScanRuleSkipRoots(t *testing.T) {
	dir := t.TempDir()
	canonDir, err := Canonicalize(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "creds.txt")
	if err := os.WriteFile(p, []byte("AKIAIOSFODNN7EXAMPLE"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := &SecretScanRule{SkipRoots: []string{canonDir}}
	if _, matched, err := r.Evaluate(toolEvent(t, "Read", map[string]any{"file_path": p})); err != nil || matched {
		t.Errorf("a file under a skip-root must not be scanned (matched=%v err=%v)", matched, err)
	}
}

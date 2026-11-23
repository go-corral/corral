package enforce

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sidecar"
)

// promptAWSKey is a format-valid AWS access key id (AKIA + 16 [0-9A-Z]) — a known-format
// secret the scanner always catches, without embedding a PEM block (which would make this
// file unreadable through corral's own Read gate).
const promptAWSKey = "AKIA" + "QQQQQQQQQQQQQQQQ"

// promptEvent builds a UserPromptSubmit hook event JSON with proper escaping.
func promptEvent(sessionID, prompt string) string {
	b, _ := json.Marshal(map[string]string{"session_id": sessionID, "prompt": prompt})
	return string(b)
}

func preToolUseEvent(t *testing.T, cwd, file string) string {
	t.Helper()
	return fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":"Read","cwd":%q,"tool_input":{"file_path":%q}}`, cwd, file)
}

// testEngineInputs blocks home/vault and logs to home/audit.
func testEngineInputs(t *testing.T) (in Inputs, vault string) {
	t.Helper()
	home := t.TempDir()
	vault = filepath.Join(home, "vault")
	cfg := &config.Config{}
	cfg.Providers.Block.Directories = []string{vault}
	return Inputs{
		Config:    cfg,
		Home:      home,
		Env:       map[string]string{"HOME": home},
		WorkDir:   home,
		AuditPath: filepath.Join(home, "audit", "corral-audit.jsonl"),
	}, vault
}

func TestHandler(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	in, vault := testEngineInputs(t)
	h, err := Handler(in)
	if err != nil {
		t.Fatal(err)
	}
	blocked := []byte(preToolUseEvent(t, in.Home, filepath.Join(vault, "creds")))

	resp := h(sidecar.Request{Type: "pre-tool-use", Decision: "json"}, blocked, policy.OSFS{})
	if resp.Code != policy.ExitAllow || !strings.Contains(resp.Stdout, `"permissionDecision":"deny"`) || resp.Stderr != "" || resp.Error != "" {
		t.Errorf("JSON deny: got %+v", resp)
	}

	resp = h(sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}, blocked, policy.OSFS{})
	if resp.Code != policy.ExitBlock || resp.Stdout != "" || !strings.Contains(resp.Stderr, "[hook:blocked-path]") || resp.Error != "" {
		t.Errorf("exit2 deny: got %+v", resp)
	}

	post := `{"hook_event_name":"PostToolUse","tool_name":"mcp__db__get","tool_response":"the value is ` + promptAWSKey + `"}`
	resp = h(sidecar.Request{Type: "post-tool-use"}, []byte(post), policy.OSFS{})
	if resp.Code != policy.ExitAllow || !strings.Contains(resp.Stdout, `"updatedToolOutput"`) || strings.Contains(resp.Stdout, promptAWSKey) || resp.Error != "" {
		t.Errorf("secret response: got %+v", resp)
	}

	resp = h(sidecar.Request{Type: "user-prompt-submit"}, []byte(promptEvent("s1", "key "+promptAWSKey)), policy.OSFS{})
	if resp.Code != policy.ExitAllow || !strings.Contains(resp.Stdout, `"block"`) || strings.Contains(resp.Stdout, promptAWSKey) || resp.Error != "" {
		t.Errorf("secret prompt: got %+v", resp)
	}

	if resp = h(sidecar.Request{Type: "notification"}, nil, policy.OSFS{}); resp.Error == "" {
		t.Errorf("unknown request type: got %+v, want an error", resp)
	}

	data, err := os.ReadFile(in.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{`"rule":"blocked-path"`, `"rule":"response-secret"`, `"rule":"prompt-secret-scan"`} {
		if !strings.Contains(string(data), rule) {
			t.Errorf("audit log missing %s:\n%s", rule, data)
		}
	}
}

// lexicalFS sees the paths under dir without resolving symlinks, as bwrap does for a bind
// whose host parent is a symlink. Other paths resolve on the host.
type lexicalFS struct{ dir string }

func (f lexicalFS) EvalSymlinks(p string) (string, error) {
	if p == f.dir || strings.HasPrefix(p, f.dir+string(filepath.Separator)) {
		return filepath.Clean(p), nil
	}
	return policy.OSFS{}.EvalSymlinks(p)
}

func (f lexicalFS) ReadRegular(p string, limit int64) ([]byte, bool, error) {
	return policy.OSFS{}.ReadRegular(p, limit)
}

// A blocked directory and an AI ignore root behind a host symlink stay protected when the
// sandbox sees the paths without the symlink.
func TestHandlerResolvesRootsInTheEventFS(t *testing.T) {
	in, _ := testEngineInputs(t)
	link := filepath.Join(in.Home, "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	vault := filepath.Join(link, "vault")
	in.Config.Providers.Block.Directories = []string{vault}
	in.WorkDir = filepath.Join(link, "proj")
	if err := os.Mkdir(in.WorkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.WorkDir, ".aiignore"), []byte("notes.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	h, err := Handler(in)
	if err != nil {
		t.Fatal(err)
	}
	for file, rule := range map[string]string{
		filepath.Join(vault, "creds"):          "[hook:blocked-path]",
		filepath.Join(in.WorkDir, "notes.txt"): "[hook:ai-ignore]",
	} {
		event := []byte(preToolUseEvent(t, in.Home, file))
		resp := h(sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}, event, lexicalFS{dir: link})
		if resp.Code != policy.ExitBlock || !strings.Contains(resp.Stderr, rule) {
			t.Errorf("%s: got %+v, want a %s deny", file, resp, rule)
		}
	}
}

// The sidecar serves connections concurrently, so the handler is called concurrently.
func TestHandlerConcurrent(t *testing.T) {
	in, vault := testEngineInputs(t)
	h, err := Handler(in)
	if err != nil {
		t.Fatal(err)
	}
	blocked := []byte(preToolUseEvent(t, in.Home, filepath.Join(vault, "creds")))

	const n = 8
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if resp := h(sidecar.Request{Type: "pre-tool-use", Decision: "exit2"}, blocked, policy.OSFS{}); resp.Code != policy.ExitBlock {
				t.Errorf("concurrent deny: got %+v", resp)
			}
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(in.AuditPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(data), "\n"); got != n {
		t.Errorf("want %d audit records, got %d:\n%s", n, got, data)
	}
}

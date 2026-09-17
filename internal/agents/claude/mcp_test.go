package claude

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Per-transport classification: plaintext http/ws to a non-loopback host warns; stdio,
// https/wss, and any loopback host are exempt (the "http is fine for localhost" steer).
func TestInsecureMCPTransport(t *testing.T) {
	cases := []struct {
		name string
		url  string
		warn bool
	}{
		{"stdio (no url)", "", false},
		{"https remote", "https://api.example.com/mcp", false},
		{"wss remote", "wss://api.example.com/mcp", false},
		{"http remote", "http://api.example.com/mcp", true},
		{"http remote with port", "http://api.example.com:8080/mcp", true},
		{"ws remote", "ws://api.example.com/socket", true},
		{"http localhost", "http://localhost:3000/mcp", false},
		{"http 127.0.0.1", "http://127.0.0.1:3000", false},
		{"http 127.0.0.5 (loopback /8)", "http://127.0.0.5:3000", false},
		{"http ipv6 loopback", "http://[::1]:3000", false},
		{"ws localhost", "ws://localhost:3000", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := insecureMCPTransport("srv", mcpServerEntry{URL: tc.url})
			if got != tc.warn {
				t.Errorf("insecureMCPTransport(url=%q) warn=%v, want %v", tc.url, got, tc.warn)
			}
		})
	}
}

func TestMCPTransportWarningsReadsBothScopes(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()

	// Project-scope .mcp.json: one remote http server (warns) + one stdio (exempt).
	mustWriteMCP(t, filepath.Join(project, ".mcp.json"), `{"mcpServers":{
		"docs":{"type":"http","url":"http://docs.example.com/mcp"},
		"fs":{"command":"mcp-fs","args":["--root","."]}
	}}`)
	// User-scope ~/.claude.json: a remote http server (warns) + a localhost one (exempt).
	mustWriteMCP(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{
		"remote":{"url":"http://api.example.com"},
		"local":{"url":"http://localhost:9000"}
	}}`)

	w := mcpTransportWarnings(home, project)
	joined := strings.Join(w, "\n")
	if len(w) != 2 {
		t.Fatalf("want 2 warnings (docs, remote), got %d:\n%s", len(w), joined)
	}
	for _, want := range []string{`"docs"`, `"remote"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing warning for %s:\n%s", want, joined)
		}
	}
	for _, exempt := range []string{`"fs"`, `"local"`} {
		if strings.Contains(joined, exempt) {
			t.Errorf("server %s should be exempt but warned:\n%s", exempt, joined)
		}
	}
}

// An empty workDir (outside a launch — doctor/sync) skips the project-scope .mcp.json entirely:
// only the user-scope ~/.claude.json is read, and no relative ".mcp.json" is pulled from the cwd.
func TestMCPTransportWarningsSkipsProjectWhenWorkDirEmpty(t *testing.T) {
	home := t.TempDir()

	// A project .mcp.json in the process cwd must not be read when workDir is empty (t.Chdir
	// restores the cwd afterward).
	t.Chdir(home)
	mustWriteMCP(t, filepath.Join(home, ".mcp.json"), `{"mcpServers":{
		"cwd":{"url":"http://cwd.example.com/mcp"}
	}}`)
	mustWriteMCP(t, filepath.Join(home, ".claude.json"), `{"mcpServers":{
		"remote":{"url":"http://api.example.com"}
	}}`)

	w := mcpTransportWarnings(home, "")
	joined := strings.Join(w, "\n")
	if len(w) != 1 || !strings.Contains(joined, `"remote"`) {
		t.Fatalf("empty workDir must read only ~/.claude.json (want 1 warning for remote), got %d:\n%s", len(w), joined)
	}
	if strings.Contains(joined, `"cwd"`) {
		t.Errorf("empty workDir must not read a relative .mcp.json from the cwd:\n%s", joined)
	}
}

// Missing or malformed registry files contribute nothing (lenient, never an error).
func TestMCPTransportWarningsLenient(t *testing.T) {
	home := t.TempDir()
	project := t.TempDir()
	if w := mcpTransportWarnings(home, project); len(w) != 0 {
		t.Errorf("missing files must yield no warnings, got %v", w)
	}
	mustWriteMCP(t, filepath.Join(project, ".mcp.json"), `{not valid json`)
	if w := mcpTransportWarnings(home, project); len(w) != 0 {
		t.Errorf("malformed .mcp.json must yield no warnings, got %v", w)
	}
}

func mustWriteMCP(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

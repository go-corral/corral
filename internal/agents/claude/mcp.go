package claude

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type mcpServerEntry struct {
	URL string `json:"url"`
}

// mcpTransportWarnings reads MCP server registrations and warns on plaintext transport
// (http:// or ws://) to a non-loopback host. HTTPS/WSS, stdio, and loopback are exempt.
// workDir is empty outside a launch (doctor/sync): the project-scope file is skipped then.
func mcpTransportWarnings(home, workDir string) []string {
	var files []string
	if workDir != "" {
		files = append(files, filepath.Join(workDir, ".mcp.json"))
	}
	files = append(files, filepath.Join(home, ".claude.json"))

	servers := map[string]mcpServerEntry{}
	for _, f := range files {
		for name, e := range readMCPServers(f) {
			servers[name] = e
		}
	}
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	var w []string
	for _, name := range names {
		if msg, ok := insecureMCPTransport(name, servers[name]); ok {
			w = append(w, msg)
		}
	}
	return w
}

func readMCPServers(path string) map[string]mcpServerEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var top struct {
		MCPServers map[string]mcpServerEntry `json:"mcpServers"`
	}
	if json.Unmarshal(data, &top) != nil {
		return nil
	}
	return top.MCPServers
}

func insecureMCPTransport(name string, e mcpServerEntry) (string, bool) {
	if e.URL == "" {
		return "", false
	}
	u, err := url.Parse(e.URL)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "ws" {
		return "", false
	}
	if isLoopbackHost(u.Hostname()) {
		return "", false
	}
	proto := "HTTP"
	if scheme == "ws" {
		proto = "WebSocket"
	}
	return fmt.Sprintf("MCP server %q uses plaintext %s across a network boundary (%s) — HTTPS/WSS is required for a remote server (stdio or loopback http is fine for local dev)", name, proto, u.Host), true
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

package cli

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type opencodeResult struct {
	code        int
	out, stderr string
	home        string
}

// opencodeDryRun runs `corral run opencode --dry-run` with the given project config, host
// environment (set after the isolation helper cleared the reserved names), and arguments.
func opencodeDryRun(t *testing.T, project string, hostEnv map[string]string, args ...string) opencodeResult {
	t.Helper()
	home, proj := fakeRunProject(t, project)
	for k, v := range hostEnv {
		t.Setenv(k, v)
	}
	r := opencodeResult{home: home}
	argv := append([]string{"opencode", "--dry-run", "--home", home, "--project", proj}, args...)
	r.stderr = captureStderr(t, func() {
		r.out = captureStdout(t, func() { r.code = cmdRun(argv, "dev") })
	})
	return r
}

// agentArgs returns the words after the last opencode binary word of the printed command line.
func (r opencodeResult) agentArgs(t *testing.T) []string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(r.out), "\n")
	words := strings.Fields(lines[len(lines)-1])
	for i := len(words) - 1; i >= 0; i-- {
		if filepath.Base(words[i]) == "opencode" {
			return words[i+1:]
		}
	}
	t.Fatalf("no opencode command on the last line:\n%s", r.out)
	return nil
}

func (r opencodeResult) plugins(t *testing.T) []string {
	t.Helper()
	var doc struct {
		Plugins []string `json:"plugins"`
	}
	if err := json.Unmarshal([]byte(envVal(r.out, "OPENCODE_CONFIG_CONTENT")), &doc); err != nil {
		t.Fatalf("OPENCODE_CONFIG_CONTENT is not JSON: %v\n%s", err, r.out)
	}
	return doc.Plugins
}

func TestRunOpencodeDryRunActivatesPlugin(t *testing.T) {
	r := opencodeDryRun(t, "", map[string]string{
		"XDG_CONFIG_HOME":         "/srv/xdg",
		"OPENCODE_CONFIG_CONTENT": `{"model":"a/b","plugins":["/p"]}`,
	})
	if r.code != 0 {
		t.Fatalf("exit=%d\n%s", r.code, r.stderr)
	}
	dir := filepath.Join(r.home, ".cache", "corral", "opencode-policy")
	if got := r.plugins(t); !slices.Equal(got, []string{"/p", dir}) {
		t.Errorf("plugins = %v, want [/p %s]", got, dir)
	}
	if got := envVal(r.out, "OPENCODE_DISABLE_AUTOUPDATE"); got != "1" {
		t.Errorf("OPENCODE_DISABLE_AUTOUPDATE = %q, want 1", got)
	}
	if got := r.agentArgs(t); !slices.Equal(got, []string{"--standalone"}) {
		t.Errorf("agent arguments = %v, want [--standalone]", got)
	}
	if strings.Contains(r.out, "XDG_CONFIG_HOME") || strings.Contains(r.out, "OPENCODE_CONFIG_DIR") {
		t.Errorf("a host XDG_CONFIG_HOME must not reach the sandbox, and no OPENCODE_CONFIG_DIR is set:\n%s", r.out)
	}
	if strings.Contains(r.out, "CLAUDE_CODE_DISABLE_AGENT_VIEW") {
		t.Errorf("opencode must not get the Claude Code agent view variable:\n%s", r.out)
	}
}

func TestRunOpencodeDryRunConfigDir(t *testing.T) {
	cfgDir := filepath.Join(t.TempDir(), "oc")
	r := opencodeDryRun(t, "", map[string]string{"OPENCODE_CONFIG_DIR": cfgDir})
	if r.code != 0 {
		t.Fatalf("exit=%d\n%s", r.code, r.stderr)
	}
	if got := envVal(r.out, "OPENCODE_CONFIG_DIR"); got != cfgDir {
		t.Errorf("OPENCODE_CONFIG_DIR = %q, want %q", got, cfgDir)
	}
	if !strings.Contains(r.out, "--bind "+cfgDir+" "+cfgDir) {
		t.Errorf("config dir must be mounted read-write:\n%s", r.out)
	}
}

func TestRunOpencodeDryRunArgs(t *testing.T) {
	r := opencodeDryRun(t, "agents: {opencode: {args: [--print-logs]}}", nil, "--", "run", "hello")
	if r.code != 0 {
		t.Fatalf("exit=%d\n%s", r.code, r.stderr)
	}
	if got, want := r.agentArgs(t), []string{"--print-logs", "run", "hello", "--standalone"}; !slices.Equal(got, want) {
		t.Errorf("agent arguments = %v, want %v", got, want)
	}
}

package enforce

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
)

// TestCanonicalHookPaths covers the enforce-level half of the agent seam: it
// resolves the active agent, then canonicalizes and de-duplicates the raw paths the agent
// derives from its live config under configDir. The agent-specific parsing itself is tested with
// each implementation (e.g. internal/agents/claude); here we pin the canonicalize+dedup step and
// the agent resolution (including the defensive fallback for an unknown agent).
func TestCanonicalHookPaths(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The same hook script in two lexical forms (one with a "..") plus a unique one, split across
	// two merged settings files: canonicalization collapses the "..", so the dedup step must
	// return the script once.
	write("settings.json", `{"hooks":{"PreToolUse":[{"hooks":[
		{"type":"command","command":"/opt/guard/x/../a.sh"}
	]}]}}`)
	write("settings.local.json", `{"hooks":{"SessionStart":[{"hooks":[
		{"type":"command","command":"/opt/guard/a.sh"},
		{"type":"command","command":"/opt/guard/b.sh"}
	]}]}}`)

	claudeWant := []string{"/opt/guard/a.sh", "/opt/guard/b.sh"}
	cases := []struct {
		name  string
		agent string
		want  []string
	}{
		{"claude derives, canonicalizes, dedups", "claude", claudeWant},
		{"unknown agent falls back to default (claude)", "bogus", claudeWant},
		{"pi contributes none", "pi", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalHookPaths(agents.LookupOrDefault(tc.agent).ProtectedPaths(dir), policy.OSFS{})
			sort.Strings(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("canonicalHookPaths = %v, want %v", got, tc.want)
			}
		})
	}
}

// The always-blocked paths and config block.directories/block.files each deny under their own
// rule name. A config entry equal to an always-blocked directory reports always-blocked. newEngine builds from its inputs alone: the process HOME and cwd point elsewhere.
func TestNewEngineAlwaysBlockedUnion(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())

	home := t.TempDir()
	projDir := filepath.Join(home, "proj")
	customBlocked := filepath.Join(home, "custom-blocked")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".aws"), projDir, customBlocked} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	cfg := &config.Config{}
	cfg.Providers.Block.Directories = []string{customBlocked, filepath.Join(home, ".aws")}

	in := Inputs{
		Config:    cfg,
		Home:      home,
		Env:       map[string]string{"HOME": home},
		WorkDir:   projDir,
		AuditPath: filepath.Join(home, ".claude", "corral-audit.jsonl"),
	}
	eng, err := newEngine(in, readPolicyFiles(in), policy.OSFS{})
	if err != nil {
		t.Fatalf("newEngine must succeed with a valid config and home; got %v", err)
	}

	for _, tc := range []struct {
		file string
		rule string
	}{
		{filepath.Join(home, ".ssh", "id_rsa"), "always-blocked"},
		{filepath.Join(customBlocked, "file.txt"), "blocked-path"},
		{filepath.Join(home, ".aws", "credentials"), "always-blocked"},
	} {
		event, _ := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse",
			"tool_name":       "Read",
			"tool_input":      map[string]any{"file_path": tc.file},
			"cwd":             home,
		})
		var stderr strings.Builder
		if code := policy.RunHook(eng, strings.NewReader(string(event)), &stderr); code != policy.ExitBlock {
			t.Errorf("%s must be blocked, got code %d (want %d)", tc.file, code, policy.ExitBlock)
		}
		if want := "[hook:" + tc.rule + "]"; !strings.Contains(stderr.String(), want) {
			t.Errorf("%s: deny must carry %s, got %q", tc.file, want, stderr.String())
		}
	}
}

// Every rule of the engine has a fix.
func TestEveryRuleHasAFix(t *testing.T) {
	home := t.TempDir()
	in := Inputs{
		Config:    &config.Config{},
		Home:      home,
		Env:       map[string]string{"HOME": home},
		WorkDir:   home,
		AuditPath: filepath.Join(home, "corral-audit.jsonl"),
	}
	eng, err := newEngine(in, readPolicyFiles(in), policy.OSFS{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range eng.RuleNames() {
		if _, ok := policy.Fixes[name]; !ok {
			t.Errorf("rule %q has no entry in policy.Fixes", name)
		}
	}
}

type footprintAgent struct {
	agents.Agent
	fp agents.Footprint
}

func (a footprintAgent) Footprint() agents.Footprint { return a.fp }

func TestAgentFootprintCopiesEveryField(t *testing.T) {
	in := agents.Footprint{
		Dir:            ".config/x",
		DirReason:      "r",
		ProjectDir:     ".x",
		ProtectedFiles: map[string]string{"a": "ra"},
		ProtectedDirs:  map[string]string{"d": "rd"},
		ProtectedNames: []string{"n"},
	}
	got := agentFootprint(footprintAgent{fp: in})
	want := policy.AgentFootprint{
		Dir:            in.Dir,
		DirReason:      in.DirReason,
		ProjectDir:     in.ProjectDir,
		ProtectedFiles: in.ProtectedFiles,
		ProtectedDirs:  in.ProtectedDirs,
		ProtectedNames: in.ProtectedNames,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("agentFootprint = %+v, want %+v", got, want)
	}
}

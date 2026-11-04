package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/policy"
)

func writeToolEvent(tool, field, file string) string {
	return fmt.Sprintf(`{"hook_event_name":"PreToolUse","tool_name":%q,"cwd":"/","tool_input":{"file_path":%q,%q:"x"}}`, tool, file, field)
}

// Deny decisions for opencode's control files and project config, in an opencode session and in
// a Claude Code session.
func TestHookOpencodeFootprint(t *testing.T) {
	type call struct {
		name  string
		event func(home, work string) string
		deny  bool
	}
	cfg := func(home string, parts ...string) string {
		return filepath.Join(append([]string{home, ".config", "opencode"}, parts...)...)
	}
	for _, agent := range []struct {
		name  string
		calls []call
	}{
		{"opencode", []call{
			{"write plugin", func(h, w string) string { return writeToolEvent("Write", "content", cfg(h, "plugins", "x.js")) }, true},
			{"edit service.json", func(h, w string) string { return writeToolEvent("Edit", "new_string", cfg(h, "service.json")) }, true},
			{"rm -rf plugins", func(h, w string) string { return bashPreToolUse("rm -rf " + cfg(h, "plugins")) }, true},
			{"read opencode.json", func(h, w string) string { return preToolUseEvent(t, w, cfg(h, "opencode.json")) }, false},
			{"write AGENTS.md", func(h, w string) string { return writeToolEvent("Write", "content", cfg(h, "AGENTS.md")) }, false},
		}},
		{"claude", []call{
			{"write other home's opencode.json", func(h, w string) string {
				return writeToolEvent("Write", "content", "/home/other/.config/opencode/opencode.json")
			}, true},
			{"write project plugin", func(h, w string) string {
				return writeToolEvent("Write", "content", filepath.Join(w, ".opencode", "plugins", "x.js"))
			}, true},
			{"write project opencode.json", func(h, w string) string {
				return writeToolEvent("Write", "content", filepath.Join(w, "opencode.json"))
			}, true},
		}},
	} {
		t.Run(agent.name, func(t *testing.T) {
			home := t.TempDir()
			work := filepath.Join(home, "proj")
			if err := os.MkdirAll(work, 0o755); err != nil {
				t.Fatal(err)
			}
			writeCorralYML(t, work, "agent: "+agent.name+"\n")
			isolateConfigEnv(t, home, work)
			bareSession(t)
			for _, c := range agent.calls {
				t.Run(c.name, func(t *testing.T) {
					var code int
					withStdin(t, c.event(home, work), func() {
						code = cmdHook([]string{"pre-tool-use", "--decision", "exit2"})
					})
					want := policy.ExitAllow
					if c.deny {
						want = policy.ExitBlock
					}
					if code != want {
						t.Errorf("exit = %d, want %d", code, want)
					}
				})
			}
		})
	}
}

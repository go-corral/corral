package policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sshRule builds a BlockedPathRule rooted at <home>/.ssh, canonicalized.
func sshRule(t *testing.T, home string) *BlockedPathRule {
	t.Helper()
	root, err := Canonicalize(filepath.Join(home, ".ssh"), "")
	if err != nil {
		t.Fatal(err)
	}
	return &BlockedPathRule{RuleName: "block-ssh", Roots: []string{root}}
}

func readEvent(t *testing.T, tool string, input map[string]any, cwd string) *HookEvent {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return &HookEvent{
		HookEventName: "PreToolUse",
		ToolName:      tool,
		ToolInput:     raw,
		Cwd:           cwd,
	}
}

func setupHomeWithSSH(t *testing.T) (home, ssh string) {
	t.Helper()
	home, err := Canonicalize(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	ssh = filepath.Join(home, ".ssh")
	if err := os.Mkdir(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ssh, "id_rsa"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home, ssh
}

func TestBlockedPathRule(t *testing.T) {
	home, ssh := setupHomeWithSSH(t)
	rule := sshRule(t, home)

	t.Run("read secret denied", func(t *testing.T) {
		ev := readEvent(t, "Read", map[string]any{"file_path": filepath.Join(ssh, "id_rsa")}, home)
		d, matched, err := rule.Evaluate(ev)
		if err != nil || !matched || d.Action != Deny {
			t.Fatalf("expected deny; got matched=%v action=%v err=%v", matched, d.Action, err)
		}
	})

	t.Run("read elsewhere allowed", func(t *testing.T) {
		ev := readEvent(t, "Read", map[string]any{"file_path": filepath.Join(home, "notes.txt")}, home)
		_, matched, err := rule.Evaluate(ev)
		if err != nil || matched {
			t.Fatalf("expected no match; got matched=%v err=%v", matched, err)
		}
	})

	t.Run("sibling prefix not denied", func(t *testing.T) {
		// ~/.sshx must not be caught by the ~/.ssh root.
		ev := readEvent(t, "Read", map[string]any{"file_path": filepath.Join(home, ".sshx")}, home)
		_, matched, err := rule.Evaluate(ev)
		if err != nil || matched {
			t.Fatalf("sibling prefix wrongly matched: matched=%v err=%v", matched, err)
		}
	})

	t.Run("write new file under secret denied", func(t *testing.T) {
		ev := readEvent(t, "Write", map[string]any{
			"file_path": filepath.Join(ssh, "authorized_keys"),
			"content":   "attacker-key",
		}, home)
		_, matched, err := rule.Evaluate(ev)
		if err != nil || !matched {
			t.Fatalf("write to new secret file not blocked: matched=%v err=%v", matched, err)
		}
	})

	t.Run("symlink bypass denied", func(t *testing.T) {
		link := filepath.Join(home, "innocent")
		if err := os.Symlink(filepath.Join(ssh, "id_rsa"), link); err != nil {
			t.Fatal(err)
		}
		ev := readEvent(t, "Read", map[string]any{"file_path": link}, home)
		_, matched, err := rule.Evaluate(ev)
		if err != nil || !matched {
			t.Fatalf("symlink bypass not blocked: matched=%v err=%v", matched, err)
		}
	})

	t.Run("relative path resolved via cwd denied", func(t *testing.T) {
		ev := readEvent(t, "Read", map[string]any{"file_path": ".ssh/id_rsa"}, home)
		_, matched, err := rule.Evaluate(ev)
		if err != nil || !matched {
			t.Fatalf("relative secret path not blocked: matched=%v err=%v", matched, err)
		}
	})

	t.Run("grep search path under secret denied", func(t *testing.T) {
		ev := readEvent(t, "Grep", map[string]any{"pattern": "PRIVATE", "path": ssh}, home)
		_, matched, err := rule.Evaluate(ev)
		if err != nil || !matched {
			t.Fatalf("grep into secret dir not blocked: matched=%v err=%v", matched, err)
		}
	})

	t.Run("unparseable tool_input fails closed", func(t *testing.T) {
		ev := &HookEvent{ToolName: "Read", ToolInput: json.RawMessage(`"not-an-object"`), Cwd: home}
		_, _, err := rule.Evaluate(ev)
		if err == nil {
			t.Fatal("expected error (fail closed) on unparseable tool_input")
		}
	})
}

func TestEngineDenyShortCircuits(t *testing.T) {
	home, ssh := setupHomeWithSSH(t)
	eng := NewEngine(sshRule(t, home))
	ev := readEvent(t, "Read", map[string]any{"file_path": filepath.Join(ssh, "id_rsa")}, home)
	d, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != Deny || d.Rule != "block-ssh" {
		t.Errorf("got action=%v rule=%q", d.Action, d.Rule)
	}
}

func TestEngineAllowsWhenNoMatch(t *testing.T) {
	home, _ := setupHomeWithSSH(t)
	eng := NewEngine(sshRule(t, home))
	ev := readEvent(t, "Read", map[string]any{"file_path": filepath.Join(home, "ok.txt")}, home)
	d, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != Allow {
		t.Errorf("expected allow, got %v", d.Action)
	}
}

func TestEngineNoToolInputAllows(t *testing.T) {
	home, _ := setupHomeWithSSH(t)
	eng := NewEngine(sshRule(t, home))
	ev := &HookEvent{HookEventName: "UserPromptSubmit", Prompt: "hello", Cwd: home}
	d, err := eng.Evaluate(ev)
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != Allow {
		t.Errorf("expected allow for non-tool event, got %v", d.Action)
	}
}

func TestFilePathsExtraction(t *testing.T) {
	ev := readEvent(t, "Read", map[string]any{"file_path": "/a/b"}, "/")
	paths, err := ev.FilePaths()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/a/b" {
		t.Errorf("got %v", paths)
	}
}

func TestMultiEditPathExtraction(t *testing.T) {
	// MultiEdit tool calls have an edits array where each element has file_path
	ev := readEvent(t, "MultiEdit", map[string]any{
		"edits": []any{
			map[string]any{"file_path": "/path/one", "old_string": "a", "new_string": "b"},
			map[string]any{"file_path": "/path/two", "old_string": "c", "new_string": "d"},
		},
	}, "/")
	paths, err := ev.FilePaths()
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[0] != "/path/one" || paths[1] != "/path/two" {
		t.Errorf("got %v", paths)
	}
}

func TestMultiEditBlockedPathRule(t *testing.T) {
	home, ssh := setupHomeWithSSH(t)
	rule := sshRule(t, home)

	t.Run("multiedit with blocked path denied", func(t *testing.T) {
		ev := readEvent(t, "MultiEdit", map[string]any{
			"edits": []any{
				map[string]any{
					"file_path":  filepath.Join(ssh, "id_rsa"),
					"old_string": "secret",
					"new_string": "pwned",
				},
			},
		}, home)
		d, matched, err := rule.Evaluate(ev)
		if err != nil || !matched || d.Action != Deny {
			t.Fatalf("expected deny; got matched=%v action=%v err=%v", matched, d.Action, err)
		}
	})

	t.Run("multiedit with mixed paths blocks if any blocked", func(t *testing.T) {
		ev := readEvent(t, "MultiEdit", map[string]any{
			"edits": []any{
				map[string]any{
					"file_path":  filepath.Join(home, "ok.txt"),
					"old_string": "a",
					"new_string": "b",
				},
				map[string]any{
					"file_path":  filepath.Join(ssh, "id_rsa"),
					"old_string": "secret",
					"new_string": "pwned",
				},
			},
		}, home)
		d, matched, err := rule.Evaluate(ev)
		if err != nil || !matched || d.Action != Deny {
			t.Fatalf("expected deny; got matched=%v action=%v err=%v", matched, d.Action, err)
		}
	})
}

func TestBashCommandExtraction(t *testing.T) {
	ev := readEvent(t, "Bash", map[string]any{"command": "ls -la"}, "/")
	cmd, ok, err := ev.BashCommand()
	if err != nil || !ok || cmd != "ls -la" {
		t.Errorf("got cmd=%q ok=%v err=%v", cmd, ok, err)
	}
	if !strings.Contains(cmd, "ls") {
		t.Error("command not extracted")
	}
}

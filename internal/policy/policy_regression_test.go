package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Unknown actions render as deny so the audit log cannot label a blocked verdict as allowed.
func TestActionString(t *testing.T) {
	tests := []struct {
		action   Action
		expected string
	}{
		{Allow, "allow"},
		{Deny, "deny"},
		{Action(999), "deny"}, // unrecognized action -> fail-closed label
	}
	for _, tt := range tests {
		got := tt.action.String()
		if got != tt.expected {
			t.Errorf("Action(%d).String() = %q, want %q", tt.action, got, tt.expected)
		}
	}
}

func TestLogicalSysPathFor(t *testing.T) {
	tests := []struct {
		name     string
		goos     string
		input    string
		expected string
	}{
		{"darwin-etc", "darwin", "/private/etc", "/etc"},
		{"darwin-etc-file", "darwin", "/private/etc/shadow", "/etc/shadow"},
		{"darwin-var", "darwin", "/private/var", "/var"},
		{"darwin-var-dir", "darwin", "/private/var/log/system.log", "/var/log/system.log"},
		{"darwin-tmp", "darwin", "/private/tmp", "/tmp"},
		{"darwin-tmp-file", "darwin", "/private/tmp/script.sh", "/tmp/script.sh"},

		{"darwin-etcd-no-match", "darwin", "/private/etcd/data", "/private/etcd/data"},
		{"darwin-etc-prefix", "darwin", "/private/etc_backup", "/private/etc_backup"},

		{"darwin-home", "darwin", "/Users/user/.ssh", "/Users/user/.ssh"},
		{"darwin-other", "darwin", "/opt/bin", "/opt/bin"},

		{"linux-etc", "linux", "/etc/shadow", "/etc/shadow"},
		{"linux-var", "linux", "/var/log/syslog", "/var/log/syslog"},
		{"linux-home", "linux", "/home/user/.ssh", "/home/user/.ssh"},
		{"linux-private", "linux", "/private/something", "/private/something"},

		{"other-freebsd", "freebsd", "/private/etc", "/private/etc"},
		{"other-windows", "windows", "C:\\Private\\file", "C:\\Private\\file"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := logicalSysPathFor(tt.input, tt.goos)
			if got != tt.expected {
				t.Errorf("logicalSysPathFor(%q, %q) = %q, want %q",
					tt.input, tt.goos, got, tt.expected)
			}
		})
	}
}

func TestWriteSessionStartContext(t *testing.T) {
	t.Run("non-empty context", func(t *testing.T) {
		var out bytes.Buffer
		code := WriteSessionStartContext(&out, "test-context")
		if code != ExitAllow {
			t.Errorf("code = %d, want %d", code, ExitAllow)
		}
		if out.Len() == 0 {
			t.Fatal("expected JSON output")
		}

		var parsed struct {
			HookSpecificOutput struct {
				HookEventName     string `json:"hookEventName"`
				AdditionalContext string `json:"additionalContext"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if parsed.HookSpecificOutput.HookEventName != "SessionStart" {
			t.Errorf("hookEventName = %q, want SessionStart",
				parsed.HookSpecificOutput.HookEventName)
		}
		if parsed.HookSpecificOutput.AdditionalContext != "test-context" {
			t.Errorf("additionalContext = %q, want test-context",
				parsed.HookSpecificOutput.AdditionalContext)
		}
	})

	t.Run("empty context writes nothing", func(t *testing.T) {
		var out bytes.Buffer
		code := WriteSessionStartContext(&out, "")
		if code != ExitAllow {
			t.Errorf("code = %d, want %d", code, ExitAllow)
		}
		if out.Len() != 0 {
			t.Errorf("empty context should write nothing, got %d bytes", out.Len())
		}
	})
}

func TestWriteUserPromptBlock(t *testing.T) {
	t.Run("normal block", func(t *testing.T) {
		var out bytes.Buffer
		code := WriteUserPromptBlock(&out, "test reason")
		if code != ExitAllow {
			t.Errorf("code = %d, want %d", code, ExitAllow)
		}
		if out.Len() == 0 {
			t.Fatal("expected JSON output")
		}

		var parsed struct {
			Decision string `json:"decision"`
			Reason   string `json:"reason"`
		}
		if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
		if parsed.Decision != "block" {
			t.Errorf("decision = %q, want block", parsed.Decision)
		}
		if parsed.Reason != "test reason" {
			t.Errorf("reason = %q, want test reason", parsed.Reason)
		}
	})

	t.Run("empty reason still produces valid output", func(t *testing.T) {
		var out bytes.Buffer
		code := WriteUserPromptBlock(&out, "")
		if code != ExitAllow {
			t.Errorf("code = %d, want %d", code, ExitAllow)
		}

		var parsed struct {
			Decision string `json:"decision"`
		}
		if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
			t.Fatalf("output is not valid JSON: %v", err)
		}
	})
}

func TestIsWriteRedir(t *testing.T) {
	r := &BashRule{}

	tests := []struct {
		name     string
		cmd      string
		wantDeny bool
	}{
		{"write-out-env", "echo secret > .env", true},
		{"write-append-env", "echo secret >> .env", true},
		{"write-all-ssh", "echo secret &> ~/.ssh/id_rsa", true},
		{"write-all-append-aws", "echo secret &>> ~/.aws/credentials", true},

		{"read-stdin-normal", "cat < /etc/hosts", false}, // < is read
		{"read-dup-normal", "exec 3< file", false},       // <, DupIn
		{"read-close", "exec 3<-", false},                // close read

		{"write-out-normal", "echo hello > file", false},
		{"write-append-normal", "echo hello >> file", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := bashEvent(t, tt.cmd)
			d, matched, err := r.Evaluate(ev)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantDeny {
				if !matched || d.Action != Deny {
					t.Errorf("cmd %q: expected deny, got matched=%v action=%v",
						tt.cmd, matched, d.Action)
				}
			} else {
				if matched && d.Action == Deny {
					t.Errorf("cmd %q: expected allow, got deny", tt.cmd)
				}
			}
		})
	}
}

func TestSplitSymbolic(t *testing.T) {
	tests := []struct {
		clause      string
		expectWho   string
		expectPerms string
		expectOk    bool
		description string
	}{
		{"u+rwx", "u", "rwx", true, "user grant"},
		{"g+w", "g", "w", true, "group grant"},
		{"o+x", "o", "x", true, "other grant"},
		{"a+r", "a", "r", true, "all grant"},

		{"u=rx", "u", "rx", true, "user set"},
		{"o=", "o", "", true, "other set empty"},
		{"a=rwx", "a", "rwx", true, "all set"},

		{"u-w", "", "", false, "user remove"},
		{"o-x", "", "", false, "other remove"},
		{"a-rwx", "", "", false, "all remove"},

		{"xyz", "", "", false, "no operator"},
		{"", "", "", false, "empty clause"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			who, perms, ok := splitSymbolic(tt.clause)
			if who != tt.expectWho || perms != tt.expectPerms || ok != tt.expectOk {
				t.Errorf("splitSymbolic(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tt.clause, who, perms, ok,
					tt.expectWho, tt.expectPerms, tt.expectOk)
			}
		})
	}
}

func TestClassifySensitiveCaseInsensitive(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantMatch bool
	}{
		{".env", "/path/.env", true},
		{".ENV", "/path/.ENV", true},
		{".EnV", "/path/.EnV", true},
		{".eNv", "/path/.eNv", true},

		{".envrc", "/path/.envrc", true},
		{".ENVRC", "/path/.ENVRC", true},
		{".EnVrC", "/path/.EnVrC", true},

		{".ssh-exact", "/home/user/.ssh/id_rsa", true},
		{".SSH-upper", "/home/user/.SSH/id_rsa", true},
		{".Ssh-mixed", "/home/user/.Ssh/id_rsa", true},

		{".gnupg-exact", "/home/user/.gnupg/pubring.gpg", true},
		{".GNUPG-upper", "/home/user/.GNUPG/pubring.gpg", true},
		{".GnuPG-mixed", "/home/user/.GnuPG/pubring.gpg", true},

		{".aws-exact", "/home/user/.aws/credentials", true},
		{".AWS-upper", "/home/user/.AWS/credentials", true},
		{".Aws-mixed", "/home/user/.Aws/credentials", true},

		{"secret.json", "/app/secret.json", true},
		{"SECRET.JSON", "/app/SECRET.JSON", true},
		{"SeCrEt.JsOn", "/app/SeCrEt.JsOn", true},

		{"credentials.yaml", "/app/credentials.yaml", true},
		{"CREDENTIALS.YAML", "/app/CREDENTIALS.YAML", true},
		{"Credentials.YaMl", "/app/Credentials.YaMl", true},

		{"readme", "/path/README.md", false},
		{"source", "/path/source.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, matched := classifySensitive(tt.path)
			if matched != tt.wantMatch {
				t.Errorf("classifySensitive(%q) matched=%v, want %v",
					tt.path, matched, tt.wantMatch)
			}
		})
	}
}

func TestResolveExistingPrefixNoAncestor(t *testing.T) {
	impossiblePath := "/nonexistent/very/deep/path/to/nonexistent/file"
	canon, err := resolveExistingPrefix(impossiblePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if canon == "" {
		t.Errorf("resolveExistingPrefix should return a canonical path, got empty string")
	}
	if !strings.HasPrefix(canon, "/") {
		t.Errorf("canonical path should be absolute, got %q", canon)
	}
}

func TestGrantsWorldWrite(t *testing.T) {
	tests := []struct {
		mode      string
		wantGrant bool
	}{
		{"777", true},
		{"0777", true},
		{"7", true},   // 1-digit: world rwx
		{"07", true},  // 2-digit: other rwx
		{"007", true}, // 3-digit: other rwx
		{"666", true}, // 110 110 110 (user, group, other all rw-)
		{"0666", true},
		{"66", true},   // world rw-
		{"6", true},    // world rw-
		{"755", false}, // user rwx, group rx, other rx (no write)
		{"0755", false},
		{"644", false}, // user rw-, group r-, other r-
		{"0644", false},
		{"700", false}, // user rwx, others none
		{"755", false},

		{"u+rwx,o+w", true}, // explicit other write
		{"a+rwx", true},     // all includes other
		{"o+w", true},       // explicit other write
		{"u+w", false},      // user write, not other
		{"o+x", false},      // other exec, not write
		{"o-w", false},      // removing (never grants)
	}

	for _, tt := range tests {
		got := grantsWorldWrite(tt.mode)
		if got != tt.wantGrant {
			t.Errorf("grantsWorldWrite(%q) = %v, want %v", tt.mode, got, tt.wantGrant)
		}
	}
}

func TestWriteContentsAllKeys(t *testing.T) {
	tests := []struct {
		name             string
		toolInput        map[string]any
		expectedContents []string
	}{
		{
			"content field",
			map[string]any{"content": "secret-data"},
			[]string{"secret-data"},
		},
		{
			"file_contents field",
			map[string]any{"file_contents": "secret-data"},
			[]string{"secret-data"},
		},
		{
			"new_string field",
			map[string]any{"new_string": "secret-data"},
			[]string{"secret-data"},
		},
		{
			"new_source field",
			map[string]any{"new_source": "secret-code"},
			[]string{"secret-code"},
		},
		{
			"source field",
			map[string]any{"source": "secret-source"},
			[]string{"secret-source"},
		},
		{
			"multiedit edits array",
			map[string]any{
				"edits": []any{
					map[string]any{"new_string": "edit1-secret"},
					map[string]any{"new_string": "edit2-secret"},
				},
			},
			[]string{"edit1-secret", "edit2-secret"},
		},
		{
			"mixed fields and multiedit",
			map[string]any{
				"content": "top-level",
				"edits": []any{
					map[string]any{"new_string": "edit-secret"},
				},
			},
			[]string{"top-level", "edit-secret"},
		},
		{
			"empty content fields are skipped",
			map[string]any{
				"content":       "",
				"file_contents": "data",
			},
			[]string{"data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(tt.toolInput)
			ev := &HookEvent{ToolName: "Write", ToolInput: data}
			contents, err := ev.WriteContents()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(contents) != len(tt.expectedContents) {
				t.Errorf("WriteContents returned %d items, want %d; got: %v, want: %v",
					len(contents), len(tt.expectedContents), contents, tt.expectedContents)
			}
			for i, expected := range tt.expectedContents {
				if i >= len(contents) {
					t.Errorf("missing content at index %d: expected %q", i, expected)
					continue
				}
				if contents[i] != expected {
					t.Errorf("contents[%d] = %q, want %q", i, contents[i], expected)
				}
			}
		})
	}
}

func TestEngineRuleErrorPropagation(t *testing.T) {
	errRule := &testErrorRule{ruleName: "test-error-rule"}
	eng := NewEngine(errRule)

	ev := &HookEvent{
		HookEventName: "PreToolUse",
		ToolName:      "Read",
		ToolInput:     json.RawMessage(`{"file_path":"/tmp/file"}`),
		Cwd:           "/",
	}

	_, err := eng.Evaluate(ev)
	if err == nil {
		t.Fatal("expected error from engine, got nil")
	}
	if !strings.Contains(err.Error(), "test-error-rule") {
		t.Errorf("error should mention rule name, got: %v", err)
	}
	if !strings.Contains(err.Error(), "intentional") {
		t.Errorf("error should contain original message, got: %v", err)
	}
}

func TestBashRuleNonBashTool(t *testing.T) {
	r := &BashRule{}

	t.Run("non-bash tool", func(t *testing.T) {
		ev := readEvent(t, "Read", map[string]any{"file_path": "/etc/passwd"}, "/")
		d, matched, err := r.Evaluate(ev)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if matched || d.Action != Allow {
			t.Errorf("non-bash tool should not match; got matched=%v action=%v", matched, d.Action)
		}
	})

	t.Run("bash tool with empty command", func(t *testing.T) {
		ev := bashEvent(t, "")
		d, matched, err := r.Evaluate(ev)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if matched || d.Action != Allow {
			t.Errorf("empty command should not match; got matched=%v action=%v", matched, d.Action)
		}
	})

	t.Run("bash tool with actual command", func(t *testing.T) {
		ev := bashEvent(t, "ls")
		d, matched, err := r.Evaluate(ev)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if matched && d.Action == Deny {
			t.Errorf("benign ls should not be denied")
		}
	})
}

// A failed deny write must fall back to exit 2 rather than silently allow.
func TestPresentDenyWriteFailureFallback(t *testing.T) {
	failOut := failWriter{}
	var errBuf bytes.Buffer

	dec := Decision{
		Action: Deny,
		Rule:   "test-rule",
		Reason: "test reason",
	}

	code := presentDeny(dec, failOut, &errBuf, PresentJSON)

	if code != ExitBlock {
		t.Errorf("stdout write failure should fall back to exit %d (fail-closed), got %d",
			ExitBlock, code)
	}
	if !strings.Contains(errBuf.String(), "test-rule") {
		t.Errorf("fallback block must name the rule on stderr, got: %s", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "test reason") {
		t.Errorf("fallback block must include reason, got: %s", errBuf.String())
	}
}

func TestBlockedPathRuleNameDefault(t *testing.T) {
	t.Run("empty RuleName returns default", func(t *testing.T) {
		rule := &BlockedPathRule{RuleName: "", Roots: []string{"/x"}}
		if got := rule.Name(); got != "blocked-path" {
			t.Errorf("Name() = %q, want 'blocked-path'", got)
		}
	})

	t.Run("non-empty RuleName returns RuleName", func(t *testing.T) {
		rule := &BlockedPathRule{RuleName: "custom-block", Roots: []string{"/x"}}
		if got := rule.Name(); got != "custom-block" {
			t.Errorf("Name() = %q, want 'custom-block'", got)
		}
	})
}

func TestPathPatternRuleUnparseableInput(t *testing.T) {
	rule := &PathPatternRule{}
	ev := &HookEvent{
		HookEventName: "PreToolUse",
		ToolName:      "Glob",
		ToolInput:     json.RawMessage(`"not-an-object"`),
		Cwd:           "/",
	}
	_, _, err := rule.Evaluate(ev)
	if err == nil {
		t.Errorf("unparseable glob input should error, got nil")
	}
}

func TestBashRuleParseErrorDenied(t *testing.T) {
	r := &BashRule{}
	ev := bashEvent(t, `echo "unterminated`)
	d, matched, err := r.Evaluate(ev)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !matched || d.Action != Deny {
		t.Errorf("unparseable command should deny; got matched=%v action=%v", matched, d.Action)
	}
	if !strings.Contains(d.Reason, "could not parse") {
		t.Errorf("deny reason should mention parse error, got: %s", d.Reason)
	}
}

type testErrorRule struct {
	ruleName string
}

func (r *testErrorRule) Name() string {
	return r.ruleName
}

func (r *testErrorRule) Evaluate(*HookEvent) (Decision, bool, error) {
	return Decision{}, false, errors.New("intentional test error")
}

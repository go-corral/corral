package claudecfg

import (
	"sort"
	"testing"
)

// TestHookCommandPaths covers the derivation of non-corral hook script paths from
// settings.json: the happy path across multiple events, the filtering of
// corral's own entries, and the leniency rules (non-command types, non-absolute and
// interpreter-wrapped commands, de-duplication).
func TestHookCommandPaths(t *testing.T) {
	const settings = `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [
        {"type": "command", "command": "/opt/guard/pre.sh --strict"},
        {"type": "command", "command": "/opt/corral/bin/corral hook pre-tool-use"}
      ]}
    ],
    "SessionStart": [
      {"hooks": [
        {"type": "command", "command": "/opt/guard/session.sh"},
        {"type": "command", "command": "/opt/guard/pre.sh --strict"},
        {"type": "command", "command": "relative/script.sh"},
        {"type": "command", "command": "bash /opt/wrapped/x.sh"},
        {"type": "prompt", "prompt": "ignore me"}
      ]}
    ]
  }
}`
	got := HookCommandPaths([]byte(settings))
	sort.Strings(got)
	want := []string{"/opt/guard/pre.sh", "/opt/guard/session.sh"}
	if !equalStrings(got, want) {
		t.Errorf("HookCommandPaths = %v, want %v\n"+
			"(corral's own entry filtered; relative + interpreter-wrapped + non-command dropped; pre.sh de-duped)", got, want)
	}
}

// TestHookCommandPathsFallbacks asserts every malformed/empty input yields no paths and
// never panics — the enforcer falls back to its static .claude/hooks assumption.
func TestHookCommandPathsFallbacks(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"whitespace":       "   \n",
		"not an object":    "[1,2,3]",
		"invalid json":     "{not json",
		"no hooks key":     `{"permissions": {"deny": []}}`,
		"hooks null":       `{"hooks": null}`,
		"hooks not object": `{"hooks": [1,2,3]}`,
		"event not array":  `{"hooks": {"PreToolUse": {"oops": true}}}`,
		"empty hooks":      `{"hooks": {}}`,
		"only corral":      `{"hooks": {"PreToolUse": [{"hooks": [{"type":"command","command":"/x/corral hook pre-tool-use"}]}]}}`,
		"non-command only": `{"hooks": {"SessionStart": [{"hooks": [{"type":"prompt","prompt":"hi"}]}]}}`,
		"relative only":    `{"hooks": {"PreToolUse": [{"hooks": [{"type":"command","command":"./local.sh"}]}]}}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if got := HookCommandPaths([]byte(in)); len(got) != 0 {
				t.Errorf("HookCommandPaths(%q) = %v, want empty (fallback)", in, got)
			}
		})
	}
}

// TestFirstAbsToken pins the leading-token extraction, including the quoted-path form.
func TestFirstAbsToken(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/opt/x.sh", "/opt/x.sh"},
		{"/opt/x.sh --flag arg", "/opt/x.sh"},
		{`"/opt/with space.sh" --flag`, "/opt/with space.sh"},
		{`'/opt/single.sh'`, "/opt/single.sh"},
		{"  /opt/lead.sh  ", "/opt/lead.sh"},
		{"relative.sh", ""},
		{"./rel.sh", ""},
		{"bash /opt/x.sh", ""}, // interpreter-wrapped: leading token is not absolute
		{"", ""},
		{"   ", ""},
		{`"/opt/unterminated.sh`, "/opt/unterminated.sh"},
	}
	for _, c := range cases {
		if got := firstAbsToken(c.in); got != c.want {
			t.Errorf("firstAbsToken(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

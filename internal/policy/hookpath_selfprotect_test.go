package policy

import "testing"

// TestSelfConfigMatchDerivedHookPath asserts a hook script at a non-default location,
// supplied via selfProtect.hookPaths, is self-protected — and that an unrelated file and
// a near-miss path are not.
func TestSelfConfigMatchDerivedHookPath(t *testing.T) {
	sp := selfProtect{
		configDir: "/home/u/.claude",
		hookPaths: []string{"/opt/guard/pre.sh", "/srv/hooks/session.sh"},
	}
	for _, p := range []string{"/opt/guard/pre.sh", "/srv/hooks/session.sh"} {
		if _, ok := selfConfigMatch(p, sp); !ok {
			t.Errorf("derived hook script %q must be self-protected", p)
		}
	}
	for _, p := range []string{"/opt/guard/pre.sh.bak", "/opt/guard/other.sh", "/opt/guard"} {
		if reason, ok := selfConfigMatch(p, sp); ok {
			t.Errorf("%q must NOT match (got %q) — only the exact registered script is protected", p, reason)
		}
	}
	// With no derived paths, the static config-dir rules still stand (fallback).
	if _, ok := selfConfigMatch("/opt/guard/pre.sh", selfProtect{configDir: "/home/u/.claude"}); ok {
		t.Error("a custom hook path must NOT match when none were derived (static fallback only)")
	}
}

// TestPathPatternRuleProtectsDerivedHookPath asserts the Edit/Write gate blocks editing a
// derived hook script, the front-line self-protection vector.
func TestPathPatternRuleProtectsDerivedHookPath(t *testing.T) {
	r := &PathPatternRule{AgentConfigDir: "/home/u/.claude", HookPaths: []string{"/opt/guard/pre.sh"}}
	d, matched := evalOrSkip(t, r, toolEvent(t, "Write", map[string]any{"file_path": "/opt/guard/pre.sh"}))
	if !matched || d.Action != Deny {
		t.Errorf("Write of a derived hook script must be denied; matched=%v action=%v", matched, d.Action)
	}
	// A sibling, non-registered file under the same dir stays writable.
	if _, matched := evalOrSkip(t, r, toolEvent(t, "Write", map[string]any{"file_path": "/opt/guard/notes.md"})); matched {
		t.Error("a non-registered sibling must remain writable")
	}
}

// TestBashRuleProtectsDerivedHookPath asserts the Bash gate blocks rm of a derived hook
// script (the delete vector parallel to the Edit/Write one).
func TestBashRuleProtectsDerivedHookPath(t *testing.T) {
	r := &BashRule{ConfigDir: "/home/u/.claude", HookPaths: []string{"/opt/guard/pre.sh"}}
	d, matched, err := r.Evaluate(bashEvent(t, "rm -rf /opt/guard/pre.sh"))
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !matched || d.Action != Deny {
		t.Errorf("rm of a derived hook script must be denied; matched=%v action=%v", matched, d.Action)
	}
}

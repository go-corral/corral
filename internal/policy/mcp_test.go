package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// These tests cover the MCP-tool branches: lenient (non-fail-closed)
// path extraction, the dual-name response accessor, the egress argument secret scan, and
// the BashRule skip that prevents a non-object MCP tool_input from false-blocking.
//
// Secret-shaped fixtures are built by concatenation at runtime so no literal credential
// pattern appears in this source file — otherwise corral's own secret-scan hook would
// block writing the test.

func mcpEvent(tool, input string) *HookEvent {
	return &HookEvent{ToolName: tool, ToolInput: json.RawMessage(input)}
}

// awsShaped returns a string shaped like an AWS access key id (AKIA + 16 upper alnum),
// assembled at runtime so the contiguous pattern is absent from the file on disk.
func awsShaped() string { return "AKIA" + strings.Repeat("Q", 16) }

// For built-in tools a non-object tool_input fails closed (TestFilePathsUnparseableFailsClosed);
// for MCP tools there is no schema, so it must be a no-op, never an error.
func TestMCPFilePathsNonObjectIsNotFailClosed(t *testing.T) {
	for _, in := range []string{`"a string"`, `123`, `[1,2]`, `true`, `null`} {
		ev := mcpEvent("mcp__server__tool", in)
		paths, err := ev.FilePaths()
		if err != nil {
			t.Errorf("MCP FilePaths over %s must not error, got %v", in, err)
		}
		if len(paths) != 0 {
			t.Errorf("MCP FilePaths over %s must extract nothing, got %v", in, paths)
		}
	}
}

func TestMCPFilePathsExtractsWhitelistedKeys(t *testing.T) {
	cases := []struct {
		name, input string
		want        []string
	}{
		{"top-level path", `{"path":"/etc/passwd"}`, []string{"/etc/passwd"}},
		{"nested under params", `{"params":{"file":"/a/b"}}`, []string{"/a/b"}},
		{"file uri reduced", `{"uri":"file:///etc/shadow"}`, []string{"/etc/shadow"}},
		{"string array", `{"target":["/x","/y"]}`, []string{"/x", "/y"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := mcpEvent("mcp__fs__read", tc.input).FilePaths()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !sameStringSet(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMCPFilePathsSkipsURLsAndNonPathKeys(t *testing.T) {
	for _, in := range []string{
		`{"path":"https://example.com/x"}`, // an http(s) URL is not a local path
		`{"url":"/etc/passwd"}`,            // "url" is not a whitelisted path key
		`{"query":"/etc/shadow"}`,          // free-text field, not a path key
	} {
		got, err := mcpEvent("mcp__web__fetch", in).FilePaths()
		if err != nil {
			t.Fatalf("unexpected error on %s: %v", in, err)
		}
		if len(got) != 0 {
			t.Errorf("%s should extract no path, got %v", in, got)
		}
	}
}

func TestResponseBytesPrefersNonNull(t *testing.T) {
	cases := []struct {
		name string
		ev   *HookEvent
		want string
	}{
		{"tool_output present", &HookEvent{ToolOutput: json.RawMessage(`{"x":1}`)}, `{"x":1}`},
		{"tool_response fallback", &HookEvent{ToolResponse: json.RawMessage(`"r"`)}, `"r"`},
		{"tool_output null falls back", &HookEvent{ToolOutput: json.RawMessage(`null`), ToolResponse: json.RawMessage(`"r"`)}, `"r"`},
		{"neither set", &HookEvent{}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(tc.ev.ResponseBytes()); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSecretScanRuleMCPArgsDeniesSecretAndDoesNotLeak(t *testing.T) {
	key := awsShaped()
	r := &SecretScanRule{}
	// The secret sits in a free-text "query" field — the raw-byte scan still catches it.
	input := `{"query":"my key is ` + key + ` thanks"}`
	d, matched, err := r.Evaluate(mcpEvent("mcp__chat__send", input))
	if err != nil {
		t.Fatal(err)
	}
	if !matched || d.Action != Deny {
		t.Fatalf("a secret in MCP args must be denied; got matched=%v action=%v", matched, d.Action)
	}
	if strings.Contains(d.Reason, key) {
		t.Errorf("deny reason must not contain the secret value: %s", d.Reason)
	}
}

func TestSecretScanRuleMCPArgsAllowsBenign(t *testing.T) {
	r := &SecretScanRule{}
	_, matched, err := r.Evaluate(mcpEvent("mcp__context7__query_docs",
		`{"query":"how do I rotate AWS keys safely?"}`))
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Errorf("a benign MCP query must be allowed")
	}
}

func TestSecretScanRuleMCPArgsScansNonObject(t *testing.T) {
	r := &SecretScanRule{}
	// A bare string tool_input (non-object) must still be scanned, not skipped.
	d, matched, err := r.Evaluate(mcpEvent("mcp__chat__send", `"`+awsShaped()+`"`))
	if err != nil {
		t.Fatal(err)
	}
	if !matched || d.Action != Deny {
		t.Errorf("non-object MCP args must still be scanned; got matched=%v", matched)
	}
}

// A non-object tool_input would make BashCommand error and fail closed for a built-in;
// for an MCP tool BashRule must skip entirely (no shell-command contract), or it would
// false-block every MCP call with non-object arguments once the matcher is widened.
func TestBashRuleSkipsMCP(t *testing.T) {
	r := &BashRule{}
	_, matched, err := r.Evaluate(mcpEvent("mcp__server__tool", `["not","an","object"]`))
	if err != nil {
		t.Errorf("BashRule must not error on an MCP event, got %v", err)
	}
	if matched {
		t.Errorf("BashRule must not match an MCP event")
	}
}

// --- registration-surface protection ---

// The agent must not hand-edit the MCP registry files; selfConfigMatch is the shared
// classifier the Write/Edit guards and the Bash gate both consult, so recognizing these
// basenames there blocks every hand-edit path at once. `claude mcp add` (the CLI flow) is
// not a file edit and is intentionally unaffected.
func TestSelfConfigMatchMCPRegistry(t *testing.T) {
	// The project MCP registry is protected from hand-edits.
	if _, ok := selfConfigMatch("/work/proj/.mcp.json", selfProtect{}); !ok {
		t.Error(".mcp.json must be recognized as a protected MCP registry file")
	}
	// The user-scope ~/.claude.json is intentionally not, because it doubles as Claude
	// Code session state that must stay writable, so blanket-blocking it would break
	// legitimate writes.
	for _, p := range []string{"/home/u/.claude.json", "/home/u/.claude/.claude.json"} {
		if _, ok := selfConfigMatch(p, selfProtect{}); ok {
			t.Errorf("%s must remain writable (session state), not flagged", p)
		}
	}
	// A normal project file must not be flagged.
	if _, ok := selfConfigMatch("/work/proj/main.go", selfProtect{}); ok {
		t.Error("a normal file must not be flagged as a protected registry")
	}
}

// --- tier-2 audit-only path classification ---

// An MCP path argument whose name looks sensitive must be audited (matched + Allow with a
// rule), never denied — MCP path-args often name remote/other-repo files, and a configured
// server is a trusted grant. Tier-1 (paths into a blocked root) is a different rule.
func TestPathPatternRuleMCPSensitivePathAuditsNotBlocks(t *testing.T) {
	r := &PathPatternRule{}
	for _, p := range []string{"/work/proj/secrets.json", "/work/proj/config/.env", "/remote/repo/id_rsa.pem"} {
		d, matched, err := r.Evaluate(mcpEvent("mcp__fs__read", `{"path":"`+p+`"}`))
		if err != nil {
			t.Fatalf("%s: unexpected error %v", p, err)
		}
		if !matched {
			t.Errorf("%s: a sensitive-named MCP path must be matched (audited)", p)
			continue
		}
		if d.Action != Allow {
			t.Errorf("%s: tier-2 must AUDIT (allow), not deny; got %v", p, d.Action)
		}
		if d.Rule != "mcp-sensitive-path" {
			t.Errorf("%s: rule=%q, want mcp-sensitive-path", p, d.Rule)
		}
	}
	// A benign MCP path is not classified.
	if _, matched, err := r.Evaluate(mcpEvent("mcp__fs__read", `{"path":"/work/proj/main.go"}`)); err != nil || matched {
		t.Errorf("benign MCP path must not match: matched=%v err=%v", matched, err)
	}
	// A non-path argument key is not classified (no spurious path extraction).
	if _, matched, _ := r.Evaluate(mcpEvent("mcp__chat__send", `{"query":"how do .env files work?"}`)); matched {
		t.Error("a non-path-key argument must not be classified as a path")
	}
}

// fakeRule is a minimal Rule stub for exercising the engine's allow-note seam.
type fakeRule struct {
	name    string
	dec     Decision
	matched bool
}

func (f fakeRule) Name() string                                { return f.name }
func (f fakeRule) Evaluate(*HookEvent) (Decision, bool, error) { return f.dec, f.matched, nil }

// The engine carries a matched Allow as an audit-only note onto the final verdict, but a
// later Deny still wins; a no-match run is a plain (unannotated) Allow.
func TestEngineAllowNoteSurfacesAndDenyWins(t *testing.T) {
	note := fakeRule{name: "note", dec: Decision{Action: Allow, Rule: "mcp-sensitive-path", Reason: "looks sensitive"}, matched: true}
	deny := fakeRule{name: "deny", dec: Decision{Action: Deny, Rule: "blocked-path", Reason: "nope"}, matched: true}
	miss := fakeRule{name: "miss"}

	if d, err := NewEngine(note, miss).Evaluate(&HookEvent{}); err != nil || d.Action != Allow || d.Rule != "mcp-sensitive-path" {
		t.Errorf("allow-note must surface on the verdict: action=%v rule=%q err=%v", d.Action, d.Rule, err)
	}
	if d, err := NewEngine(note, deny).Evaluate(&HookEvent{}); err != nil || d.Action != Deny || d.Rule != "blocked-path" {
		t.Errorf("a later deny must win over an earlier note: action=%v rule=%q err=%v", d.Action, d.Rule, err)
	}
	if d, err := NewEngine(miss).Evaluate(&HookEvent{}); err != nil || d.Action != Allow || d.Rule != "" {
		t.Errorf("no match must be a plain allow: action=%v rule=%q err=%v", d.Action, d.Rule, err)
	}
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, s := range a {
		m[s]++
	}
	for _, s := range b {
		m[s]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

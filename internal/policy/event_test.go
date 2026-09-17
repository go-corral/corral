package policy

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Structurally invalid built-in tool input must propagate an error and fail closed.

func TestParseEventEmptyFailsClosed(t *testing.T) {
	if _, err := ParseEvent(nil); err == nil {
		t.Error("nil hook event must error (fail closed)")
	}
	if _, err := ParseEvent([]byte("")); err == nil {
		t.Error("empty hook event must error (fail closed)")
	}
}

func TestParseEventInvalidJSONFailsClosed(t *testing.T) {
	for _, in := range []string{"{not json", "}{", "[1,2", `{"tool_name":}`} {
		if _, err := ParseEvent([]byte(in)); err == nil {
			t.Errorf("ParseEvent(%q) must error (fail closed)", in)
		}
	}
}

// Unknown fields are tolerated on purpose: the protocol gains fields over time and
// rejecting benign additions would fail closed too aggressively.
func TestParseEventToleratesUnknownFields(t *testing.T) {
	ev, err := ParseEvent([]byte(`{"tool_name":"Read","brand_new_field":123,"cwd":"/x"}`))
	if err != nil {
		t.Fatalf("unknown fields must be tolerated, got %v", err)
	}
	if ev.ToolName != "Read" || ev.Cwd != "/x" {
		t.Errorf("known fields not parsed: tool_name=%q cwd=%q", ev.ToolName, ev.Cwd)
	}
}

func TestFilePathsUnparseableFailsClosed(t *testing.T) {
	for _, in := range []string{`"string"`, `123`, `[1,2]`, `true`} {
		ev := &HookEvent{ToolInput: json.RawMessage(in)}
		if _, err := ev.FilePaths(); err == nil {
			t.Errorf("FilePaths over tool_input %s must error (fail closed)", in)
		}
	}
}

func TestFilePathsEmptyInputNoError(t *testing.T) {
	paths, err := (&HookEvent{}).FilePaths() // no tool_input at all
	if err != nil || paths != nil {
		t.Errorf("absent tool_input must be a no-op: paths=%v err=%v", paths, err)
	}
}

// A path key whose value is not a plain string must never be silently skipped: if it were,
// the path would never reach a path-based rule and an always-blocked target would be
// allowed. A list of strings must be extracted (so the rules judge the real path); any
// other shape must error, which the engine turns into a fail-closed block.
func TestFilePathsNonStringPathKey(t *testing.T) {
	t.Run("list of strings is extracted", func(t *testing.T) {
		ev := &HookEvent{ToolInput: json.RawMessage(`{"file_path":["/home/u/.ssh/id_rsa","/tmp/x"]}`)}
		paths, err := ev.FilePaths()
		if err != nil {
			t.Fatalf("a list of path strings must extract, not error: %v", err)
		}
		if len(paths) != 2 || paths[0] != "/home/u/.ssh/id_rsa" || paths[1] != "/tmp/x" {
			t.Errorf("both list entries must be checked; got %v", paths)
		}
	})

	// Anything else is a shape no built-in tool produces — fail closed rather than drop it.
	for _, in := range []string{
		`{"file_path":123}`,
		`{"file_path":true}`,
		`{"file_path":{"v":"/home/u/.ssh/id_rsa"}}`,
		`{"file_path":["/tmp/x",123]}`,
		`{"path":123}`,
		`{"notebook_path":{}}`,
	} {
		ev := &HookEvent{ToolInput: json.RawMessage(in)}
		if _, err := ev.FilePaths(); err == nil {
			t.Errorf("FilePaths over %s must error (fail closed), so the path is never silently dropped", in)
		}
	}
}

// The write-side counterpart. Here an odd shape must not fail closed — a Jupyter cell
// "source" is idiomatically a list of line strings, and blocking that would break a
// legitimate notebook write — but the content still has to reach the scanner. List-wrapped
// content must not be skipped past the secret scan.
func TestWriteContentsNonStringContent(t *testing.T) {
	cases := []struct {
		name, input, want string
	}{
		{"list-wrapped content", `{"content":["secret-marker-1"]}`, "secret-marker-1"},
		{"jupyter source lines", `{"source":["line one\n","secret-marker-2"]}`, "secret-marker-2"},
		{"nested object content", `{"content":{"nested":"secret-marker-3"}}`, "secret-marker-3"},
		{"edits new_string list", `{"edits":[{"new_string":["secret-marker-4"]}]}`, "secret-marker-4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := &HookEvent{ToolInput: json.RawMessage(tc.input)}
			contents, err := ev.WriteContents()
			if err != nil {
				t.Fatalf("write content extraction must not fail closed on an odd shape: %v", err)
			}
			if !strings.Contains(strings.Join(contents, "\n"), tc.want) {
				t.Errorf("content %q must reach the scanner; got %v", tc.want, contents)
			}
		})
	}
}

func TestWriteContentsUnparseableFailsClosed(t *testing.T) {
	for _, in := range []string{`"string"`, `123`, `[1,2]`} {
		ev := &HookEvent{ToolInput: json.RawMessage(in)}
		if _, err := ev.WriteContents(); err == nil {
			t.Errorf("WriteContents over tool_input %s must error (fail closed)", in)
		}
	}
}

func TestBashCommandUnparseableFailsClosed(t *testing.T) {
	for _, in := range []string{`"string"`, `123`, `[1,2]`} {
		ev := &HookEvent{ToolInput: json.RawMessage(in)}
		if _, _, err := ev.BashCommand(); err == nil {
			t.Errorf("BashCommand over tool_input %s must error (fail closed)", in)
		}
	}
}

func TestBashCommandEmptyNoMatch(t *testing.T) {
	ev := &HookEvent{ToolInput: json.RawMessage(`{"command":""}`)}
	cmd, ok, err := ev.BashCommand()
	if err != nil || ok || cmd != "" {
		t.Errorf("empty command is not a match: cmd=%q ok=%v err=%v", cmd, ok, err)
	}
}

// sanitized decodes SanitizedInput into a generic map for assertions. ToolName is empty, so
// the call is treated as a built-in tool (the richer identifier allowlist applies).
func sanitized(t *testing.T, toolInput string) map[string]any {
	t.Helper()
	return sanitizedTool(t, "", toolInput)
}

// sanitizedTool is sanitized for a specific tool name (e.g. "mcp__server__tool" to exercise
// the MCP gate).
func sanitizedTool(t *testing.T, toolName, toolInput string) map[string]any {
	t.Helper()
	raw := (&HookEvent{ToolName: toolName, ToolInput: json.RawMessage(toolInput)}).SanitizedInput()
	if raw == nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("SanitizedInput produced invalid JSON %q: %v", raw, err)
	}
	return m
}

// SanitizedInput keeps structural args (paths, command, patterns) but reduces content
// bodies to a byte count — the "structural only" audit policy. The cardinal property
// asserted throughout: a content body (file contents, edit text) never appears verbatim.
func TestSanitizedInputStructuralOnly(t *testing.T) {
	t.Run("read keeps file_path", func(t *testing.T) {
		m := sanitized(t, `{"file_path":"/etc/hosts","limit":50}`)
		if m["file_path"] != "/etc/hosts" {
			t.Errorf("file_path not kept: %v", m)
		}
		if m["limit"].(float64) != 50 {
			t.Errorf("structural number not kept: %v", m)
		}
	})

	t.Run("write content becomes a byte count, never the body", func(t *testing.T) {
		// Build an AWS-key-shaped value from fragments so the literal never appears in
		// this source file (corral's own secret scanner would otherwise block writing it).
		secret := "AKIA" + "IOSFODNN7" + "EXAMPLE" + "-super-secret-value"
		in := `{"file_path":"/app/.env","content":"` + secret + `"}`
		m := sanitized(t, in)
		if m["file_path"] != "/app/.env" {
			t.Errorf("file_path not kept: %v", m)
		}
		if _, ok := m["content"]; ok {
			t.Errorf("content body must NOT be logged: %v", m)
		}
		if m["content_bytes"].(float64) != float64(len(secret)) {
			t.Errorf("content_bytes wrong: %v", m)
		}
		got, _ := json.Marshal(m)
		if strings.Contains(string(got), "AKIA") {
			t.Errorf("secret leaked into sanitized input: %s", got)
		}
	})

	t.Run("edit old/new strings become byte counts", func(t *testing.T) {
		m := sanitized(t, `{"file_path":"/a.go","old_string":"foo","new_string":"barbar"}`)
		if _, ok := m["old_string"]; ok {
			t.Errorf("old_string body must not be logged: %v", m)
		}
		if _, ok := m["new_string"]; ok {
			t.Errorf("new_string body must not be logged: %v", m)
		}
		if m["old_string_bytes"].(float64) != 3 || m["new_string_bytes"].(float64) != 6 {
			t.Errorf("edit byte counts wrong: %v", m)
		}
	})

	t.Run("bash command kept verbatim (it is the action)", func(t *testing.T) {
		m := sanitized(t, `{"command":"rm -rf /tmp/x && echo done","description":"clean"}`)
		if m["command"] != "rm -rf /tmp/x && echo done" {
			t.Errorf("command must be kept verbatim: %v", m)
		}
	})

	t.Run("pathologically long command is byte-counted", func(t *testing.T) {
		long := `{"command":"` + strings.Repeat("x", auditMaxCommandLen+1) + `"}`
		m := sanitized(t, long)
		s, _ := m["command"].(string)
		if !strings.HasPrefix(s, "<") || !strings.HasSuffix(s, "bytes>") {
			t.Errorf("over-long command must be byte-counted, got %q", s)
		}
	})

	t.Run("structural key kept, free-text/unknown key byte-counted (even when short)", func(t *testing.T) {
		// "path" is structural → kept verbatim; "note" is not → byte-counted regardless of length.
		m := sanitized(t, `{"path":"/etc/hosts","note":"short free text"}`)
		if m["path"] != "/etc/hosts" {
			t.Errorf("structural key must be kept: %v", m)
		}
		if _, ok := m["note"]; ok {
			t.Errorf("free-text/unknown key must NOT be kept verbatim: %v", m)
		}
		if m["note_bytes"].(float64) != float64(len("short free text")) {
			t.Errorf("unknown key must be byte-counted: %v", m)
		}
	})

	t.Run("LEAK REGRESSION: a secret under a non-structural free-text key is never copied verbatim", func(t *testing.T) {
		// Reproduces the audit-leak finding: an MCP free-text arg (e.g. Slack "message") holding
		// a credential. The scanner would deny such a call, and the audit line is written on the
		// deny path too — so the value must be byte-counted, never echoed.
		secret := "ghp_" + strings.Repeat("A", 36) // GitHub-PAT-shaped, well under the 512B clamp
		for _, key := range []string{"message", "value", "body", "text", "data", "token"} {
			m := sanitized(t, `{"`+key+`":"`+secret+`"}`)
			if _, ok := m[key]; ok {
				t.Errorf("free-text key %q must not be kept verbatim: %v", key, m)
			}
			if m[key+"_bytes"].(float64) != float64(len(secret)) {
				t.Errorf("free-text key %q must be byte-counted: %v", key, m)
			}
			if blob, _ := json.Marshal(m); strings.Contains(string(blob), "ghp_") {
				t.Errorf("secret leaked verbatim for key %q: %s", key, blob)
			}
		}
	})

	t.Run("multiedit edits array byte-counts each edit's strings", func(t *testing.T) {
		m := sanitized(t, `{"file_path":"/a","edits":[{"file_path":"/a","old_string":"x","new_string":"yy"}]}`)
		edits, ok := m["edits"].([]any)
		if !ok || len(edits) != 1 {
			t.Fatalf("edits not preserved as array: %v", m)
		}
		e0 := edits[0].(map[string]any)
		if _, ok := e0["new_string"]; ok {
			t.Errorf("edit new_string body must not be logged: %v", e0)
		}
		if e0["new_string_bytes"].(float64) != 2 || e0["file_path"] != "/a" {
			t.Errorf("edit summary wrong: %v", e0)
		}
	})

	t.Run("mcp nested object is sanitized too", func(t *testing.T) {
		long := strings.Repeat("q", auditMaxScalarLen+1)
		m := sanitized(t, `{"params":{"path":"/x","content":"`+long+`"}}`)
		params, ok := m["params"].(map[string]any)
		if !ok {
			t.Fatalf("nested object not preserved: %v", m)
		}
		if params["path"] != "/x" {
			t.Errorf("nested structural path not kept: %v", params)
		}
		if _, ok := params["content"]; ok {
			t.Errorf("nested content body must not be logged: %v", params)
		}
		if params["content_bytes"].(float64) != float64(len(long)) {
			t.Errorf("nested content_bytes wrong: %v", params)
		}
	})
}

// Built-in tools record their "what happened" identifier verbatim (the prior gap: WebSearch
// logged that it ran but not the query). Content/instruction fields stay byte-counted.
func TestSanitizedInputBuiltinIdentifiers(t *testing.T) {
	t.Run("WebSearch query is kept", func(t *testing.T) {
		m := sanitizedTool(t, "WebSearch", `{"query":"golang flock semantics","allowed_domains":["go.dev"]}`)
		if m["query"] != "golang flock semantics" {
			t.Errorf("WebSearch query must be recorded: %v", m)
		}
		if d, _ := m["allowed_domains"].([]any); len(d) != 1 || d[0] != "go.dev" {
			t.Errorf("allowed_domains must be recorded: %v", m)
		}
	})
	t.Run("WebFetch url kept, prompt byte-counted", func(t *testing.T) {
		m := sanitizedTool(t, "WebFetch", `{"url":"https://example.com/x","prompt":"summarize the page contents please"}`)
		if m["url"] != "https://example.com/x" {
			t.Errorf("WebFetch url must be recorded: %v", m)
		}
		if _, ok := m["prompt"]; ok {
			t.Errorf("WebFetch prompt (free-text instruction) must stay byte-counted: %v", m)
		}
		if m["prompt_bytes"].(float64) == 0 {
			t.Errorf("prompt must be byte-counted: %v", m)
		}
	})
	t.Run("Task identifiers kept, prompt byte-counted", func(t *testing.T) {
		m := sanitizedTool(t, "Task", `{"description":"fix the bug","subagent_type":"Explore","prompt":"long free text instruction"}`)
		if m["description"] != "fix the bug" || m["subagent_type"] != "Explore" {
			t.Errorf("Task description/subagent_type must be recorded: %v", m)
		}
		if _, ok := m["prompt"]; ok {
			t.Errorf("Task prompt must stay byte-counted: %v", m)
		}
	})
}

// The built-in identifier allowlist is not applied to MCP tools: query and URL remain
// byte-counted. This test covers the conservative path set; command is handled separately.
func TestSanitizedInputMCPGate(t *testing.T) {
	m := sanitizedTool(t, "mcp__search__run", `{"query":"secret-ish terms","url":"https://x/y?token=abc","path":"/repo/x"}`)
	if _, ok := m["query"]; ok {
		t.Errorf("MCP query must NOT be kept verbatim (only built-in tools): %v", m)
	}
	if _, ok := m["url"]; ok {
		t.Errorf("MCP url must NOT be kept verbatim: %v", m)
	}
	if m["query_bytes"] == nil || m["url_bytes"] == nil {
		t.Errorf("MCP query/url must be byte-counted: %v", m)
	}
	if m["path"] != "/repo/x" {
		t.Errorf("the base path set still applies to MCP: %v", m)
	}
}

func TestSanitizedInputEdgeCases(t *testing.T) {
	if got := (&HookEvent{}).SanitizedInput(); got != nil {
		t.Errorf("absent tool_input must be nil, got %s", got)
	}
	if got := (&HookEvent{ToolInput: json.RawMessage(`null`)}).SanitizedInput(); got != nil {
		t.Errorf("JSON null tool_input must be nil, got %s", got)
	}
	// Un-decodable input degrades to a size-only marker, never dropped silently.
	bad := (&HookEvent{ToolInput: json.RawMessage(`{not json`)}).SanitizedInput()
	var m map[string]any
	if err := json.Unmarshal(bad, &m); err != nil {
		t.Fatalf("marker must be valid JSON: %v", err)
	}
	if _, ok := m["_unparsed_bytes"]; !ok {
		t.Errorf("un-decodable input must yield an _unparsed_bytes marker, got %v", m)
	}
}

// The bound-the-blob branches are the load-bearing "never copy a content body" guards; a
// regression here (e.g. returning the partial summary instead of a marker) would silently
// re-introduce a leak, so assert each branch directly.
func TestSanitizedInputBounds(t *testing.T) {
	t.Run("oversized summary collapses to _oversized_bytes (no field bodies)", func(t *testing.T) {
		// An array of many long paths under the structural key "path" is kept verbatim and
		// pushes the serialized summary past auditMaxInputBytes.
		elem := `"` + strings.Repeat("a", 500) + `"`
		elems := make([]string, 40)
		for i := range elems {
			elems[i] = elem
		}
		in := `{"path":[` + strings.Join(elems, ",") + `]}`
		m := sanitized(t, in)
		if _, ok := m["_oversized_bytes"]; !ok {
			t.Fatalf("oversized summary must collapse to _oversized_bytes, got keys %v", keysOf(m))
		}
		if _, ok := m["path"]; ok {
			t.Errorf("oversized fallback must not include any field body: %v", keysOf(m))
		}
	})

	t.Run("too many keys yields _truncated_keys", func(t *testing.T) {
		parts := make([]string, 70)
		for i := range parts {
			parts[i] = fmt.Sprintf(`"k%02d":%d`, i, i)
		}
		m := sanitized(t, "{"+strings.Join(parts, ",")+"}")
		tk, ok := m["_truncated_keys"]
		if !ok {
			t.Fatalf("over-auditMaxKeys object must carry _truncated_keys, got %v", keysOf(m))
		}
		if tk.(float64) != float64(70-auditMaxKeys) {
			t.Errorf("_truncated_keys = %v, want %d", tk, 70-auditMaxKeys)
		}
	})

	t.Run("excessive nesting collapses to the depth marker", func(t *testing.T) {
		deep := "0"              // valid JSON leaf
		for i := 0; i < 8; i++ { // 8 > auditMaxDepth
			deep = `{"a":` + deep + `}`
		}
		raw := (&HookEvent{ToolInput: json.RawMessage(deep)}).SanitizedInput()
		// json.Marshal HTML-escapes the marker's angle brackets (<…>); the ellipsis
		// rune survives and is unambiguous.
		if !strings.Contains(string(raw), "…") {
			t.Errorf("nesting beyond auditMaxDepth must produce the depth marker, got %s", raw)
		}
	})
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

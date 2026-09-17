package policy

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// HookEvent is the JSON payload Claude Code writes to a hook's stdin.
type HookEvent struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	HookEventName  string          `json:"hook_event_name"`
	PermissionMode string          `json:"permission_mode"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	ToolResponse   json.RawMessage `json:"tool_response"`
	ToolOutput     json.RawMessage `json:"tool_output"`
	Prompt         string          `json:"prompt"`
}

// ParseEvent decodes a hook event. Unknown fields are tolerated: the protocol gains fields over
// time and rejecting benign additions would fail closed too aggressively.
func ParseEvent(data []byte) (*HookEvent, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty hook event")
	}
	var ev HookEvent
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("decode hook event: %w", err)
	}
	return &ev, nil
}

func (e *HookEvent) isMCP() bool {
	return strings.HasPrefix(e.ToolName, "mcp__")
}

// ResponseBytes returns the raw bytes of the tool result for PostToolUse response scanning.
// Claude Code has labeled this field both "tool_response" and "tool_output" across versions;
// accepting whichever is present prevents a silent no-op on a field rename (a latent fail-open).
func (e *HookEvent) ResponseBytes() []byte {
	if v := nonNullRaw(e.ToolOutput); v != nil {
		return v
	}
	return nonNullRaw(e.ToolResponse)
}

func nonNullRaw(r json.RawMessage) []byte {
	if t := strings.TrimSpace(string(r)); t == "" || t == "null" {
		return nil
	}
	return r
}

var pathInputKeys = []string{"file_path", "notebook_path", "path"}

// stringsUnder returns the non-empty strings a tool_input value carries: a bare string or a list
// of strings. ok is false for anything else. A plain `v.(string)` assertion here would be a policy
// bypass: a non-string value falls through, so `{"file_path":["~/.ssh/id_rsa"]}` yields no paths.
func stringsUnder(v any) ([]string, bool) {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil, true
		}
		return []string{t}, true
	case []any:
		var out []string
		for _, e := range t {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			if s != "" {
				out = append(out, s)
			}
		}
		return out, true
	default:
		return nil, false
	}
}

// FilePaths returns the filesystem paths referenced by this event's tool_input. It is defensive:
// tool_input is treated as arbitrary JSON and only recognized path-bearing keys with string values
// are returned.
func (e *HookEvent) FilePaths() ([]string, error) {
	if e.isMCP() {
		return e.mcpFilePaths()
	}
	if len(e.ToolInput) == 0 {
		return nil, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(e.ToolInput, &obj); err != nil {
		return nil, fmt.Errorf("decode tool_input: %w", err)
	}
	var out []string
	for _, k := range pathInputKeys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		paths, ok := stringsUnder(v)
		if !ok {
			// A path key holding neither a string nor a list of strings is a shape no built-in tool
			// produces. Skipping it silently would drop the path from every path-based rule.
			return nil, fmt.Errorf("tool_input key %q has unsupported type %T", k, v)
		}
		out = append(out, paths...)
	}

	if edits, ok := obj["edits"].([]any); ok {
		for _, edit := range edits {
			if editObj, ok := edit.(map[string]any); ok {
				if f, ok := editObj["file_path"].(string); ok && f != "" {
					out = append(out, f)
				}
			}
		}
	}

	return out, nil
}

const mcpMaxKeys = 100

// mcpPathKeys are tool_input keys whose string value, for an MCP tool, names a filesystem path.
// Intentionally broad: over-inclusion is harmless (a non-path string won't match a blocked root)
// while a missed key skips a real one.
var mcpPathKeys = map[string]bool{
	"file_path": true, "filepath": true, "notebook_path": true, "path": true,
	"file": true, "filename": true, "target": true, "source": true,
	"destination": true, "dir": true, "directory": true, "uri": true,
}

// mcpFilePaths extracts candidate filesystem paths from an MCP tool's tool_input. A non-object or
// unrecognized tool_input is not an error: MCP tools have no fixed schema, so an unrecognized shape
// must not fail closed. It scans whitelisted keys at the top level and one level of nesting, bounded
// to mcpMaxKeys values, skipping non-file URL schemes and reducing file:// to its path.
func (e *HookEvent) mcpFilePaths() ([]string, error) {
	if len(e.ToolInput) == 0 {
		return nil, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(e.ToolInput, &obj); err != nil {
		return nil, nil
	}
	var out []string
	visited := 0
	collect := func(key string, v any) {
		if !mcpPathKeys[key] {
			return
		}
		switch val := v.(type) {
		case string:
			if p, ok := mcpPathCandidate(val); ok {
				out = append(out, p)
			}
		case []any:
			for _, item := range val {
				if s, ok := item.(string); ok {
					if p, ok := mcpPathCandidate(s); ok {
						out = append(out, p)
					}
				}
			}
		}
	}
	for k, v := range obj {
		if visited >= mcpMaxKeys {
			break
		}
		visited++
		collect(k, v)
		if nested, ok := v.(map[string]any); ok {
			for nk, nv := range nested {
				if visited >= mcpMaxKeys {
					break
				}
				visited++
				collect(nk, nv)
			}
		}
	}
	return out, nil
}

func mcpPathCandidate(s string) (string, bool) {
	if s == "" {
		return "", false
	}
	const fileScheme = "file://"
	if strings.HasPrefix(s, fileScheme) {
		return strings.TrimPrefix(s, fileScheme), true
	}
	if strings.Contains(s, "://") {
		return "", false
	}
	return s, true
}

// writeContentKeys are tool_input keys whose string value is content being persisted to a file.
// A superset is scanned because exact names vary by Claude version; over-scanning a non-secret
// field is harmless, missing the real content key is not.
var writeContentKeys = []string{"content", "file_contents", "new_string", "new_source", "source"}

// WriteContents returns the content a write-style tool would persist, so it can be scanned before
// landing on disk: top-level Write/Edit/NotebookEdit fields plus every MultiEdit edits[].new_string.
func (e *HookEvent) WriteContents() ([]string, error) {
	if len(e.ToolInput) == 0 {
		return nil, nil
	}
	var obj map[string]any
	if err := json.Unmarshal(e.ToolInput, &obj); err != nil {
		return nil, fmt.Errorf("decode tool_input: %w", err)
	}
	var out []string
	for _, k := range writeContentKeys {
		v, ok := obj[k]
		if !ok {
			continue
		}
		// This side never fails closed on an odd shape: a list of strings is the idiomatic Jupyter
		// cell "source" form, and erroring would block a legitimate notebook write.
		if contents, ok := stringsUnder(v); ok {
			out = append(out, contents...)
			continue
		}
		if raw, err := json.Marshal(v); err == nil {
			out = append(out, string(raw))
		}
	}
	if edits, ok := obj["edits"].([]any); ok {
		for _, ed := range edits {
			if m, ok := ed.(map[string]any); ok {
				if contents, ok := stringsUnder(m["new_string"]); ok {
					out = append(out, contents...)
				}
			}
		}
	}
	return out, nil
}

// BashCommand returns the command string for a Bash tool call, if present.
func (e *HookEvent) BashCommand() (string, bool, error) {
	if len(e.ToolInput) == 0 {
		return "", false, nil
	}
	var obj struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(e.ToolInput, &obj); err != nil {
		return "", false, fmt.Errorf("decode tool_input: %w", err)
	}
	if obj.Command == "" {
		return "", false, nil
	}
	return obj.Command, true, nil
}

// SanitizedInput audit bounds. The walk is bounded so a pathological tool_input cannot turn the
// millisecond hook into a deep tree walk.
const (
	auditMaxDepth      = 6
	auditMaxKeys       = 64
	auditMaxElems      = 64
	auditMaxScalarLen  = 512
	auditMaxCommandLen = 8192
	auditMaxInputBytes = 16384
)

var auditStructuralKeys = map[string]bool{
	"file_path": true, "notebook_path": true, "path": true, "filepath": true,
	"file": true, "filename": true, "target": true, "destination": true,
	"dir": true, "directory": true, "pattern": true, "glob": true,
}

// auditBuiltinKeys are identifier keys kept verbatim only for built-in (non-MCP) tools. MCP
// free-text args stay byte-counted except "command", which is retained for every tool.
var auditBuiltinKeys = map[string]bool{
	"query": true, "url": true, "uri": true,
	"description": true, "subagent_type": true, "model": true,
	"cell_type": true, "cell_id": true, "edit_mode": true, "mode": true,
	"output_mode": true, "bash_id": true, "shell_id": true, "filter": true,
	"allowed_domains": true, "blocked_domains": true,
}

func structuralKey(k string, builtin bool) bool {
	return auditStructuralKeys[k] || (builtin && auditBuiltinKeys[k])
}

// SanitizedInput returns a compact, structural JSON summary of this event's tool_input for the
// audit log, or nil when there is nothing to record. Structural keys and any command key are kept
// verbatim; every other value is reduced to a byte count. It is best-effort and isolated from the
// verdict: it never returns an error and is bounded against a pathological input.
func (e *HookEvent) SanitizedInput() json.RawMessage {
	if len(e.ToolInput) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(e.ToolInput, &v); err != nil {
		return auditSizeMarker("_unparsed_bytes", len(e.ToolInput))
	}
	if v == nil {
		return nil
	}
	b, err := json.Marshal(sanitizeAuditValue(v, 0, false, !e.isMCP()))
	if err != nil || len(b) > auditMaxInputBytes {
		return auditSizeMarker("_oversized_bytes", len(e.ToolInput))
	}
	return b
}

func auditSizeMarker(key string, n int) json.RawMessage {
	b, err := json.Marshal(map[string]int{key: n})
	if err != nil {
		return nil
	}
	return b
}

// sanitizeAuditValue recursively reduces a decoded JSON value to its structural audit summary,
// bounded by auditMaxDepth. keepStrings governs string values reached without key context (array
// elements): true only when the enclosing key was structural. Nested objects always re-decide
// per-key, so a content blob nested under a structural key is still byte-counted.
func sanitizeAuditValue(v any, depth int, keepStrings, builtin bool) any {
	if depth > auditMaxDepth {
		return "<…>"
	}
	switch t := v.(type) {
	case map[string]any:
		return sanitizeAuditMap(t, depth, builtin)
	case []any:
		return sanitizeAuditSlice(t, depth, keepStrings, builtin)
	case string:
		if keepStrings {
			return clampAuditScalar(t)
		}
		return fmt.Sprintf("<%d bytes>", len(t))
	default:
		return t
	}
}

func sanitizeAuditMap(m map[string]any, depth int, builtin bool) map[string]any {
	keys := slices.Sorted(maps.Keys(m))
	out := make(map[string]any, len(keys))
	for i, k := range keys {
		if i >= auditMaxKeys {
			out["_truncated_keys"] = len(keys) - auditMaxKeys
			break
		}
		val := m[k]
		if s, ok := val.(string); ok {
			switch {
			case k == "command":
				out[k] = clampAuditCommand(s)
			case structuralKey(k, builtin):
				out[k] = clampAuditScalar(s)
			default:
				out[k+"_bytes"] = len(s)
			}
			continue
		}
		out[k] = sanitizeAuditValue(val, depth+1, structuralKey(k, builtin), builtin)
	}
	return out
}

func sanitizeAuditSlice(s []any, depth int, keepStrings, builtin bool) []any {
	n := len(s)
	if n > auditMaxElems {
		n = auditMaxElems
	}
	out := make([]any, 0, n+1)
	for i := 0; i < n; i++ {
		out = append(out, sanitizeAuditValue(s[i], depth+1, keepStrings, builtin))
	}
	if len(s) > auditMaxElems {
		out = append(out, fmt.Sprintf("<%d more>", len(s)-auditMaxElems))
	}
	return out
}

func clampAuditScalar(s string) any {
	if len(s) <= auditMaxScalarLen {
		return s
	}
	return fmt.Sprintf("<%d bytes>", len(s))
}

func clampAuditCommand(s string) any {
	if len(s) <= auditMaxCommandLen {
		return s
	}
	return fmt.Sprintf("<%d bytes>", len(s))
}

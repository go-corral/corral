// Package claudecfg manages corral's hook registrations in Claude Code's settings.json.
// Any hook or setting corral does not own is preserved verbatim as raw JSON, so re-running
// `corral sync` is idempotent and de-registering never removes more than corral itself added.
package claudecfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-corral/corral/internal/sandbox"
)

const (
	DefaultMatcher                 = "*"
	PostToolUseMatcher             = "Bash|Grep|mcp__.*"
	DefaultTimeoutSecs             = 10
	hookSubcommand                 = "hook pre-tool-use"
	hookSubcommandPostToolUse      = "hook post-tool-use"
	hookSubcommandSessionStart     = "hook session-start"
	hookSubcommandUserPromptSubmit = "hook user-prompt-submit"
	corralBinaryName               = "corral"
)

var corralHookSubcommands = []string{hookSubcommand, hookSubcommandPostToolUse, hookSubcommandSessionStart, hookSubcommandUserPromptSubmit}

func Subcommands() []string {
	out := make([]string, len(corralHookSubcommands))
	for i, s := range corralHookSubcommands {
		out[i] = strings.TrimPrefix(s, "hook ")
	}
	return out
}

// The guarded command shape written for every event:
//
//	if [ -x "<bin>" ]; then exec "<bin>" hook <sub>;
//	elif [ -n "$CORRAL_SANDBOX" ]; then echo "<msg>" >&2; exit 2; fi
//
// The [ -x ] guard makes a missing binary a silent exit 0 outside the sandbox; the elif on
// CORRAL_SANDBOX makes it exit 2 inside (blocking). The binary path is embedded twice and
// must be identical. validateBinaryPath rejects shell-active characters. `exec` must never
// become `cmd && ...` or gain a `|| true` suffix: either would swallow the fail-closed exit 2
// and turn the guard into a no-op.
const guardedMessage = "corral: policy hook binary missing inside the sandbox - refusing (reinstall corral, then run 'corral sync')"

var guardedCommandRE = regexp.MustCompile(
	`^if \[ -x "([^"]+)" \]; then exec "([^"]+)" (hook [a-z-]+); elif \[ -n "\$` +
		regexp.QuoteMeta(sandbox.SandboxEnvVar) + `" \]; then echo "[^"]*" >&2; exit 2; fi$`)

type SyncOptions struct {
	SettingsPath string
	BinaryPath   string
	Matcher      string
	TimeoutSecs  int
	DryRun       bool
	// Remove strips corral's own hook entries instead of registering them. Entries are
	// identified by shape (isCorralEntry), so removal works no matter which corral wrote them.
	Remove bool
}

type hookEntry struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type matcherGroup struct {
	Matcher string            `json:"matcher,omitempty"`
	If      json.RawMessage   `json:"if,omitempty"`
	Hooks   []json.RawMessage `json:"hooks"`
}

// Sync merges corral's hook registrations into opt.SettingsPath, or strips them out with
// opt.Remove. Returns the rendered content and whether it differs from disk; when changed and
// not DryRun, it writes the file. Idempotent in both directions.
func Sync(opt SyncOptions) (rendered []byte, changed bool, err error) {
	if opt.SettingsPath == "" {
		return nil, false, errors.New("claudecfg: SettingsPath is required")
	}
	if !opt.Remove {
		if opt.BinaryPath == "" {
			return nil, false, errors.New("claudecfg: BinaryPath is required")
		}
		if err := validateBinaryPath(opt.BinaryPath); err != nil {
			return nil, false, err
		}
	}
	matcher := opt.Matcher
	if matcher == "" {
		matcher = DefaultMatcher
	}
	timeout := opt.TimeoutSecs
	if timeout == 0 {
		timeout = DefaultTimeoutSecs
	}

	existing, err := os.ReadFile(opt.SettingsPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("read settings: %w", err)
	}

	if opt.Remove {
		return removeSync(opt, existing)
	}

	rendered, _, err = render(existing, renderAdd, opt.BinaryPath, matcher, timeout)
	if err != nil {
		return nil, false, err
	}

	changed = !bytes.Equal(existing, rendered)
	if changed && !opt.DryRun {
		if err := writeSettings(opt.SettingsPath, rendered); err != nil {
			return nil, false, err
		}
	}
	return rendered, changed, nil
}

// removeSync strips corral's own hook entries. `changed` means an entry was removed, not byte
// inequality — a strip also canonicalizes.
func removeSync(opt SyncOptions, existing []byte) (rendered []byte, changed bool, err error) {
	if len(bytes.TrimSpace(existing)) == 0 {
		return existing, false, nil
	}
	rendered, stripped, err := render(existing, renderStrip, "", "", 0)
	if err != nil {
		return nil, false, err
	}
	if !stripped {
		return rendered, false, nil
	}
	if !opt.DryRun {
		if err := writeSettings(opt.SettingsPath, rendered); err != nil {
			return nil, false, err
		}
	}
	return rendered, true, nil
}

func writeSettings(path string, rendered []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create settings dir: %w", err)
	}
	if err := atomicWrite(path, rendered, 0o644); err != nil {
		return fmt.Errorf("write settings: %w", err)
	}
	return nil
}

// atomicWrite writes data to path atomically: temp file in the same directory, fsync, then
// rename over the target. A symlinked settings.json is followed, not replaced. Existing file
// permissions are preserved; perm applies only on creation.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".corral-settings-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func guardedCommand(binaryPath, sub string) string {
	return `if [ -x "` + binaryPath + `" ]; then exec "` + binaryPath + `" ` + sub +
		`; elif [ -n "$` + sandbox.SandboxEnvVar + `" ]; then echo "` + guardedMessage + `" >&2; exit 2; fi`
}

// parseGuardedCommand reports whether cmd is a guarded corral command, returning the binary
// and subcommand. Both binary occurrences must match, the subcommand must be one corral
// dispatches, and the binary's base name must be exactly "corral".
func parseGuardedCommand(cmd string) (binary, sub string, ok bool) {
	m := guardedCommandRE.FindStringSubmatch(strings.TrimSpace(cmd))
	if m == nil {
		return "", "", false
	}
	first, second, candidate := m[1], m[2], m[3]
	if first != second || filepath.Base(first) != corralBinaryName {
		return "", "", false
	}
	for _, known := range corralHookSubcommands {
		if candidate == known {
			return first, candidate, true
		}
	}
	return "", "", false
}

// validateBinaryPath refuses a binary path unsafe to embed in the hook command. The command
// runs through `sh -c`, so `"`, `$`, backtick, `\`, and control characters are shell-active
// inside the double quotes. A relative path is refused too: the hook runs from an arbitrary cwd.
func validateBinaryPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("claudecfg: binary path %q must be absolute", path)
	}
	for _, r := range path {
		switch {
		case r == '"' || r == '$' || r == '`' || r == '\\':
			return fmt.Errorf("claudecfg: binary path %q contains %q, which is shell-active in the persisted hook command — install corral at a plain path and re-run sync", path, r)
		case r < 0x20 || r == 0x7f:
			return fmt.Errorf("claudecfg: binary path %q contains a control character — install corral at a plain path and re-run sync", path)
		}
	}
	return nil
}

func upsertCorralHook(hooks map[string]json.RawMessage, event, matcher, command string, timeout int) error {
	var groups []matcherGroup
	if raw, ok := hooks[event]; ok && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return fmt.Errorf("settings.json hooks.%s is not an array: %w", event, err)
		}
	}
	kept := groups[:0:0]
	for _, g := range groups {
		var keepHooks []json.RawMessage
		for _, h := range g.Hooks {
			if isCorralEntry(h) {
				continue
			}
			keepHooks = append(keepHooks, h)
		}
		if len(keepHooks) == 0 {
			continue
		}
		g.Hooks = keepHooks
		kept = append(kept, g)
	}
	entry, err := marshalNoEscape(hookEntry{Type: "command", Command: command, Timeout: timeout})
	if err != nil {
		return err
	}
	kept = append(kept, matcherGroup{Matcher: matcher, Hooks: []json.RawMessage{entry}})
	groupsRaw, err := marshalNoEscape(kept)
	if err != nil {
		return err
	}
	hooks[event] = groupsRaw
	return nil
}

// stripCorralHooks deletes corral's own hook entries from the hooks map in place and reports
// whether it deleted any. A group array that fails to parse is an error.
func stripCorralHooks(hooks map[string]json.RawMessage) (bool, error) {
	stripped := false
	for _, event := range corralHookEventOrder {
		raw, ok := hooks[event]
		if !ok || len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var groups []matcherGroup
		if err := json.Unmarshal(raw, &groups); err != nil {
			return stripped, fmt.Errorf("settings.json hooks.%s is not an array: %w", event, err)
		}
		kept := groups[:0:0]
		removedHere := false
		for _, g := range groups {
			keepHooks := g.Hooks[:0:0]
			for _, h := range g.Hooks {
				if isCorralEntry(h) {
					removedHere = true
					continue
				}
				keepHooks = append(keepHooks, h)
			}
			if len(keepHooks) == 0 && len(g.Hooks) > 0 {
				continue
			}
			g.Hooks = keepHooks
			kept = append(kept, g)
		}
		if !removedHere {
			continue
		}
		stripped = true
		if len(kept) == 0 {
			delete(hooks, event)
			continue
		}
		groupsRaw, err := marshalNoEscape(kept)
		if err != nil {
			return stripped, err
		}
		hooks[event] = groupsRaw
	}
	return stripped, nil
}

type renderMode int

const (
	renderKeep  renderMode = iota // canonicalizing round-trip (CanonicalBaseline)
	renderAdd                     // upsert corral's hooks
	renderStrip                   // delete corral's hooks
)

// CanonicalBaseline renders existing settings.json through the same serializer a real sync
// uses, but without adding corral's hooks, so a diff cancels pure reformatting.
func CanonicalBaseline(existing []byte) ([]byte, error) {
	out, _, err := render(existing, renderKeep, "", "", 0)
	return out, err
}

// render parses existing settings, applies mode to corral's hooks, then re-nests and
// serializes deterministically. stripped reports whether renderStrip actually removed something.
func render(existing []byte, mode renderMode, binaryPath, matcher string, timeout int) (out []byte, stripped bool, err error) {
	top := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(existing)) > 0 {
		if err := json.Unmarshal(existing, &top); err != nil {
			return nil, false, fmt.Errorf("settings.json is not a JSON object: %w", err)
		}
	}
	if top == nil {
		top = map[string]json.RawMessage{}
	}

	hadHooks := false
	hooks := map[string]json.RawMessage{}
	if raw, ok := top["hooks"]; ok && len(bytes.TrimSpace(raw)) > 0 {
		hadHooks = true
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return nil, false, fmt.Errorf("settings.json \"hooks\" is not an object: %w", err)
		}
	}
	if hooks == nil {
		hooks = map[string]json.RawMessage{}
	}

	switch mode {
	case renderAdd:
		if err := upsertCorralHook(hooks, "PreToolUse", matcher, guardedCommand(binaryPath, hookSubcommand), timeout); err != nil {
			return nil, false, err
		}
		if err := upsertCorralHook(hooks, "PostToolUse", PostToolUseMatcher, guardedCommand(binaryPath, hookSubcommandPostToolUse), timeout); err != nil {
			return nil, false, err
		}
		// SessionStart/UserPromptSubmit: matcher omitted (match-all, not regex).
		if err := upsertCorralHook(hooks, "SessionStart", "", guardedCommand(binaryPath, hookSubcommandSessionStart), timeout); err != nil {
			return nil, false, err
		}
		if err := upsertCorralHook(hooks, "UserPromptSubmit", "", guardedCommand(binaryPath, hookSubcommandUserPromptSubmit), timeout); err != nil {
			return nil, false, err
		}
	case renderStrip:
		if stripped, err = stripCorralHooks(hooks); err != nil {
			return nil, false, err
		}
	}

	switch {
	case stripped && len(hooks) == 0:
		delete(top, "hooks")
	case hadHooks || len(hooks) > 0:
		hooksRaw, merr := marshalNoEscape(hooks)
		if merr != nil {
			return nil, false, merr
		}
		top["hooks"] = hooksRaw
	}

	out, err = marshalSettings(top)
	if err != nil {
		return nil, false, err
	}
	return out, stripped, nil
}

// marshalNoEscape is json.Marshal with HTML escaping off, for every nesting level. Go's
// default encoder rewrites `<`, `>`, `&` as \u00xx escapes, which would turn the guarded
// command's `>&2` into noise in the settings and the goldens that pin them.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func marshalSettings(top map[string]json.RawMessage) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(top); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var corralHookEventOrder = []string{"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit"}

type HookReport struct {
	Missing []string
	Stale   []string
	Current []string
}

func (r HookReport) Registered() bool { return len(r.Missing) == 0 && len(r.Stale) == 0 }

// HookRegistration reports how settings registers corral's hooks for binaryPath. An empty
// binaryPath skips the identity comparison. Lenient: anything unparseable reads as Missing.
func HookRegistration(settings []byte, binaryPath string) HookReport {
	var r HookReport
	for _, event := range corralHookEventOrder {
		state := ""
		for _, cmd := range corralCommands(settings, event) {
			if bin, _, ok := parseGuardedCommand(cmd); ok && (binaryPath == "" || bin == binaryPath) {
				state = "current"
				break
			}
			state = "stale"
		}
		switch state {
		case "current":
			r.Current = append(r.Current, event)
		case "stale":
			r.Stale = append(r.Stale, event)
		default:
			r.Missing = append(r.Missing, event)
		}
	}
	return r
}

func corralCommands(settings []byte, event string) []string {
	hooks, err := summaryParse(settings)
	if err != nil {
		return nil
	}
	raw, ok := hooks[event]
	if !ok || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var groups []matcherGroup
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil
	}
	var out []string
	for _, g := range groups {
		for _, h := range g.Hooks {
			if !isCorralEntry(h) {
				continue
			}
			if cmd, ok := commandEntry(h); ok {
				out = append(out, cmd)
			}
		}
	}
	return out
}

type HookChange struct {
	Event   string
	Update  bool
	Removed bool
}

type SyncSummary struct {
	Hooks []HookChange
}

func (s SyncSummary) Empty() bool { return len(s.Hooks) == 0 }

// String renders the one-line headline, e.g. "registered hooks: PreToolUse; updated hooks:
// SessionStart", or "" when empty.
func (s SyncSummary) String() string {
	var added, updated, removed []string
	for _, h := range s.Hooks {
		switch {
		case h.Removed:
			removed = append(removed, h.Event)
		case h.Update:
			updated = append(updated, h.Event)
		default:
			added = append(added, h.Event)
		}
	}
	var parts []string
	if len(added) > 0 {
		parts = append(parts, "registered hooks: "+strings.Join(added, ", "))
	}
	if len(updated) > 0 {
		parts = append(parts, "updated hooks: "+strings.Join(updated, ", "))
	}
	if len(removed) > 0 {
		parts = append(parts, "removed hooks: "+strings.Join(removed, ", "))
	}
	return strings.Join(parts, "; ")
}

// SummarizeSync compares a canonical baseline against a synced output, reporting which hook
// events corral registered, updated, or removed.
func SummarizeSync(baseline, rendered []byte) (SyncSummary, error) {
	var s SyncSummary
	beforeHooks, err := summaryParse(baseline)
	if err != nil {
		return s, err
	}
	afterHooks, err := summaryParse(rendered)
	if err != nil {
		return s, err
	}
	for _, ev := range corralHookEventOrder {
		b := extractCorralHook(beforeHooks, ev)
		a := extractCorralHook(afterHooks, ev)
		switch {
		case !a.found && !b.found:
		case !a.found:
			s.Hooks = append(s.Hooks, HookChange{Event: ev, Removed: true})
		case !b.found:
			s.Hooks = append(s.Hooks, HookChange{Event: ev})
		case a != b:
			s.Hooks = append(s.Hooks, HookChange{Event: ev, Update: true})
		}
	}
	return s, nil
}

func summaryParse(data []byte) (map[string]json.RawMessage, error) {
	top := map[string]json.RawMessage{}
	if len(bytes.TrimSpace(data)) > 0 {
		if err := json.Unmarshal(data, &top); err != nil {
			return nil, fmt.Errorf("settings.json is not a JSON object: %w", err)
		}
	}
	hooks := map[string]json.RawMessage{}
	if raw, ok := top["hooks"]; ok && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return nil, fmt.Errorf("settings.json \"hooks\" is not an object: %w", err)
		}
	}
	return hooks, nil
}

// corralHookState is the identifying content of corral's hook for one event. Comparable with
// == so the summary can tell a newly registered hook from an updated one.
type corralHookState struct {
	found   bool
	matcher string
	command string
	timeout int
}

func extractCorralHook(hooks map[string]json.RawMessage, event string) corralHookState {
	raw, ok := hooks[event]
	if !ok || len(bytes.TrimSpace(raw)) == 0 {
		return corralHookState{}
	}
	var groups []matcherGroup
	if err := json.Unmarshal(raw, &groups); err != nil {
		return corralHookState{}
	}
	for _, g := range groups {
		for _, h := range g.Hooks {
			if !isCorralEntry(h) {
				continue
			}
			var e hookEntry
			if err := json.Unmarshal(h, &e); err != nil {
				continue
			}
			return corralHookState{found: true, matcher: g.Matcher, command: e.Command, timeout: e.Timeout}
		}
	}
	return corralHookState{}
}

func isCorralEntry(raw json.RawMessage) bool {
	cmd, ok := commandEntry(raw)
	if !ok {
		return false
	}
	if _, _, guarded := parseGuardedCommand(cmd); guarded {
		return true
	}
	_, _, bare := parseBareCorralCommand(cmd)
	return bare
}

func commandEntry(raw json.RawMessage) (string, bool) {
	var e struct {
		Type    string `json:"type"`
		Command string `json:"command"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return "", false
	}
	if e.Type != "command" {
		return "", false
	}
	return strings.TrimSpace(e.Command), true
}

// parseBareCorralCommand reports whether cmd is the bare "<binary> hook <subcommand>" form.
// It must end with one of corralHookSubcommands with no trailing flags, and everything before
// must be a single token whose base name is exactly "corral".
func parseBareCorralCommand(cmd string) (binary, sub string, ok bool) {
	s := strings.TrimSpace(cmd)
	for _, candidate := range corralHookSubcommands {
		suffix := " " + candidate
		if !strings.HasSuffix(s, suffix) {
			continue
		}
		bin := strings.TrimSpace(strings.TrimSuffix(s, suffix))
		if bin == "" || strings.ContainsAny(bin, " \t") {
			continue
		}
		if filepath.Base(bin) == corralBinaryName {
			return bin, candidate, true
		}
	}
	return "", "", false
}

// HookCommandPaths extracts the absolute script paths of every non-corral command hook in
// settings.json. Never errors: anything unparseable yields no paths. Results are de-duplicated.
func HookCommandPaths(settings []byte) []string {
	if len(bytes.TrimSpace(settings)) == 0 {
		return nil
	}
	top := map[string]json.RawMessage{}
	if err := json.Unmarshal(settings, &top); err != nil {
		return nil
	}
	raw, ok := top["hooks"]
	if !ok || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	hooks := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &hooks); err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, eventRaw := range hooks {
		var groups []matcherGroup
		if err := json.Unmarshal(eventRaw, &groups); err != nil {
			continue
		}
		for _, g := range groups {
			for _, h := range g.Hooks {
				if isCorralEntry(h) {
					continue
				}
				var e hookEntry
				if err := json.Unmarshal(h, &e); err != nil || e.Type != "command" {
					continue
				}
				p := firstAbsToken(e.Command)
				if p == "" || seen[p] {
					continue
				}
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// firstAbsToken returns the leading shell token of a hook command when that token is an
// absolute path, else "". A leading quote is honored. No full shell parsing, so an
// interpreter-wrapped form like `bash /path/x.sh` yields "" by design.
func firstAbsToken(command string) string {
	s := strings.TrimSpace(command)
	if s == "" {
		return ""
	}
	var tok string
	if q := s[0]; q == '"' || q == '\'' {
		if end := strings.IndexByte(s[1:], q); end >= 0 {
			tok = s[1 : 1+end]
		} else {
			tok = s[1:]
		}
	} else {
		tok = strings.Fields(s)[0]
	}
	if filepath.IsAbs(tok) {
		return tok
	}
	return ""
}

func DefaultSettingsPath(home string) string {
	if dir := os.Getenv("CLAUDE_CONFIG_DIR"); dir != "" {
		return filepath.Join(dir, "settings.json")
	}
	return filepath.Join(home, ".claude", "settings.json")
}

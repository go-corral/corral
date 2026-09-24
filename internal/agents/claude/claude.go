// Package claude is the Claude Code adapter. It implements the agent contract
// (internal/agents/spec) and is registered by the facade (internal/agents).
package claude

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/agents/claude/claudecfg"
	"github.com/go-corral/corral/internal/agents/spec"
	"github.com/go-corral/corral/internal/health"
)

type agent struct{}

func New() spec.Agent { return agent{} }

var _ spec.Agent = agent{}

func (agent) Name() string       { return "claude" }
func (agent) Binaries() []string { return []string{"claude"} }

func (agent) ConfigDir(home string, host map[string]string) string {
	if d := strings.TrimSpace(host["CLAUDE_CONFIG_DIR"]); d != "" {
		return d
	}
	return filepath.Join(home, ".claude")
}

func (agent) Launch() spec.Launch {
	return spec.Launch{
		TempEnvAliases: []string{"CLAUDE_CODE_TMPDIR"},
	}
}

// ConfigPaths are Claude Code's account/auth files outside ~/.claude. Living on the agent
// (not the embedded baseline) keeps the baseline agent-neutral.
func (agent) ConfigPaths() []spec.ConfigPath {
	node := false
	return []spec.ConfigPath{
		{
			Path:        "$HOME/.claude.json",
			Description: "Claude auth/state",
			Writeable:   true,
			Recursive:   &node,
			Optional:    true,
		},
		{
			// The native installer puts the launcher at ~/.local/bin/claude (a symlink
			// into the versioned binary under ~/.local/share/claude); without this bind the
			// sandboxed exec resolves to an unbound path. Read-only so an in-sandbox update
			// cannot mutate the running binary. Optional: npm-global installs skip this bind.
			Path:        "$HOME/.local/share/claude",
			Description: "Claude Code native-installer binary + version files; read-only",
			Optional:    true,
		},
		{
			Path:        `^$HOME/\.claude\.json\.`,
			Description: "Claude auth/state backup + atomic-write temp files; macOS-only (bwrap cannot bind a regex)",
			Writeable:   true,
			Regex:       true,
			Archs:       []string{"macos"},
		},
		{
			Path:        "$HOME/Library/Caches/claude-cli-nodejs",
			Description: "Claude node cache",
			Writeable:   true,
			Archs:       []string{"macos"},
		},
	}
}

func (agent) ReservedEnv() []string {
	return []string{
		"ENABLE_CLAUDEAI_MCP_SERVERS",
		"DISABLE_TELEMETRY",
		"DISABLE_ERROR_REPORTING",
		"CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY",
		"CLAUDE_CODE_ATTRIBUTION_HEADER",
		"CLAUDE_CODE_DISABLE_AGENT_VIEW",
	}
}

// Doctor reports whether corral's policy hook is registered in claude's settings.json.
func (c agent) Doctor(in spec.StatusInput) []health.Check {
	path := filepath.Join(c.ConfigDir(in.Home, in.Host), "settings.json")
	hooks := health.Check{State: health.Warn, Label: "hooks", Fix: "corral sync claude"}
	data, err := os.ReadFile(path)
	switch {
	case err != nil && os.IsNotExist(err):
		hooks.Value, hooks.Reason = "not registered", path+" not present"
		return []health.Check{hooks}
	case err != nil:
		return []health.Check{{State: health.Warn, Label: "hooks", Value: "unreadable", Reason: err.Error()}}
	}
	report := claudecfg.HookRegistration(data, in.Self)
	switch {
	case report.Registered():
		return []health.Check{{Label: "hooks", Value: "registered for this binary"}}
	case len(report.Current) == 0 && len(report.Stale) == 0:
		hooks.Value, hooks.Reason = "not registered", "claude runs unhooked unless started with corral run"
	default:
		var parts []string
		if len(report.Stale) > 0 {
			parts = append(parts, "stale for "+strings.Join(report.Stale, ", "))
		}
		if len(report.Missing) > 0 {
			parts = append(parts, "missing for "+strings.Join(report.Missing, ", "))
		}
		hooks.Value, hooks.Reason = strings.Join(parts, "; "), path
		if len(report.Stale) > 0 {
			hooks.Reason = "an older shape, or a different corral binary"
		}
	}
	return []health.Check{hooks}
}

// Sync registers (or previews when in.DryRun) corral's policy hook in claude's settings.json.
// With in.Remove it de-registers instead.
func (c agent) Sync(in spec.SyncInput) (spec.SyncReport, error) {
	st, err := c.syncState(in)
	if err != nil {
		return spec.SyncReport{}, err
	}
	if in.Remove {
		return c.removeReport(in, st), nil
	}
	var (
		messages []string
		diff     *spec.SyncDiff
	)
	switch {
	case !st.changed:
		if in.DryRun {
			messages = append(messages, fmt.Sprintf("%s already up to date — no changes", st.path))
		} else {
			messages = append(messages, fmt.Sprintf("%s already up to date", st.path))
		}
	case st.reformatOnly:
		if in.DryRun {
			messages = append(messages, fmt.Sprintf("%s would only be reformatted (whitespace/key order) — no policy change (dry-run, not written)", st.path))
		} else {
			messages = append(messages, fmt.Sprintf("reformatted %s (whitespace/key order) — no policy change", st.path))
		}
	default:
		head := "updated " + st.path
		if in.DryRun {
			head = st.path + " would change (dry-run, not written)"
		}
		messages = append(messages, head+headlineSuffix(st.summary)+":")
		diff = &spec.SyncDiff{
			Before: st.baseline, After: st.rendered,
			FromLabel: st.path + " (current)", ToLabel: st.path + " (after sync)",
		}
	}
	return spec.SyncReport{Messages: messages, Diff: diff, Changed: st.changed}, nil
}

func (c agent) removeReport(in spec.SyncInput, st claudeSyncState) spec.SyncReport {
	switch {
	case st.absent:
		return spec.SyncReport{Messages: []string{fmt.Sprintf("%s not present — nothing to remove", st.path)}}
	case !st.changed:
		return spec.SyncReport{Messages: []string{fmt.Sprintf("no corral hooks in %s — nothing to remove", st.path)}}
	default:
		head := "updated " + st.path
		if in.DryRun {
			head = st.path + " would change (dry-run, not written)"
		}
		return spec.SyncReport{
			Messages: []string{head + headlineSuffix(st.summary) + ":"},
			Diff: &spec.SyncDiff{
				Before: st.baseline, After: st.rendered,
				FromLabel: st.path + " (current)", ToLabel: st.path + " (after removal)",
			},
			Changed: true,
		}
	}
}

func (c agent) LaunchWarnings(in spec.StatusInput) []string {
	var w []string
	path := c.settingsPath(in.Home, in.Host)
	if in.Self != "" {
		data, _ := os.ReadFile(path)
		if report := claudecfg.HookRegistration(data, in.Self); !report.Registered() {
			missing := append(append([]string{}, report.Missing...), report.Stale...)
			w = append(w, fmt.Sprintf("Claude settings.json (%s) does not register corral's hooks for this binary (%s) — run `corral sync`; "+
				"until then those events are ungated, in this session and in every bare `claude`", path, strings.Join(missing, ", ")))
		}
	}
	w = append(w, fullscreenBannerWarning(path)...)
	return append(w, mcpTransportWarnings(in.Home, in.WorkDir)...)
}

// settingsFiles are the Claude Code settings filenames corral reads for hook-script
// self-protection discovery. Claude merges all of them, so any one is an enforcement kill
// switch.
var settingsFiles = []string{"settings.json", "settings.local.json", "managed-settings.json"}

// ProtectedPaths returns the paths of every non-corral command hook registered across
// claude's merged settings files. Best-effort and read-only: an unreadable/missing/malformed
// file contributes nothing and never errors.
func (agent) ProtectedPaths(configDir string) []string {
	if configDir == "" {
		return nil
	}
	var out []string
	for _, name := range settingsFiles {
		data, err := os.ReadFile(filepath.Join(configDir, name))
		if err != nil {
			continue
		}
		out = append(out, claudecfg.HookCommandPaths(data)...)
	}
	return out
}

func (agent) Footprint() spec.Footprint {
	files := make(map[string]string, len(settingsFiles))
	for _, name := range settingsFiles {
		files[name] = "Claude Code's " + name
	}
	return spec.Footprint{
		Dir:            ".claude",
		DirReason:      "Claude Code's config directory",
		ProtectedFiles: files,
		ProtectedDirs:  map[string]string{"hooks": "Claude Code's hooks directory"},
	}
}

type claudeSyncState struct {
	path         string
	rendered     []byte
	baseline     []byte
	changed      bool
	reformatOnly bool
	absent       bool
	summary      claudecfg.SyncSummary
}

// syncState reads the current settings file, renders it through claudecfg.Sync (which writes
// the file when in.DryRun is false), and derives the diffable canonical baseline plus the
// changed/reformat-only flags. The same arithmetic serves in.Remove with the diff's sides
// swapping roles.
func (c agent) syncState(in spec.SyncInput) (claudeSyncState, error) {
	path := c.settingsPath(in.Home, in.Host)
	if in.SettingsPath != "" {
		path = in.SettingsPath
	}
	before, _ := os.ReadFile(path)

	rendered, changed, err := claudecfg.Sync(claudecfg.SyncOptions{
		SettingsPath: path,
		BinaryPath:   in.BinaryPath,
		DryRun:       in.DryRun,
		Remove:       in.Remove,
	})
	if err != nil {
		return claudeSyncState{}, err
	}

	var baseline []byte
	blank := len(bytes.TrimSpace(before)) == 0
	if !blank {
		if b, berr := claudecfg.CanonicalBaseline(before); berr == nil {
			baseline = b
		} else {
			baseline = before
		}
	}
	summary, _ := claudecfg.SummarizeSync(baseline, rendered)
	return claudeSyncState{
		path:         path,
		rendered:     rendered,
		baseline:     baseline,
		changed:      changed,
		reformatOnly: changed && len(baseline) > 0 && bytes.Equal(baseline, rendered),
		absent:       blank,
		summary:      summary,
	}, nil
}

func (c agent) settingsPath(home string, host map[string]string) string {
	return filepath.Join(c.ConfigDir(home, host), "settings.json")
}

func headlineSuffix(s claudecfg.SyncSummary) string {
	if str := s.String(); str != "" {
		return " — " + str
	}
	return ""
}

// fullscreenBannerWarning returns the advisory shown when Claude Code's TUI mode is not
// explicitly "default": in fullscreen rendering claude covers corral's startup banner.
func fullscreenBannerWarning(settingsPath string) []string {
	if claudeTUIMode(settingsPath) == "default" {
		return nil
	}
	return []string{
		`Claude Code may render in fullscreen, which covers this banner (corral's session summary and notices) the moment it launches — set "/tui default" in Claude Code to keep them visible inline, or pass --yes to skip this prompt.`,
	}
}

// claudeTUIMode reads the "tui" rendering mode from claude's settings.json, or "" when
// unset/unreadable. Only an explicit "default" is treated as banner-safe — the effective mode
// is driven by env vars and other invisible factors, so it is not reliably predictable.
func claudeTUIMode(settingsPath string) string {
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return ""
	}
	var s struct {
		TUI string `json:"tui"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return ""
	}
	return s.TUI
}

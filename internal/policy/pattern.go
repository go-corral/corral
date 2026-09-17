package policy

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// PathPatternRule denies credential-shaped paths by name over canonicalized paths. Writes also
// protect /etc and corral's config and runtime files from changes that could disable enforcement.
// BlockedPathRule handles always-blocked directories; this rule adds file and non-home cases.
type PathPatternRule struct {
	AgentConfigDir string
	// Footprint is the active agent's static enforcement footprint, anchored under AgentConfigDir.
	// AllFootprints is every registered agent's footprint, scanned by config-dir path segment.
	Footprint     AgentFootprint
	AllFootprints []AgentFootprint
	// HookPaths are canonical absolute paths of non-corral hook scripts; nil falls back to the
	// static AgentConfigDir/hooks assumption.
	HookPaths []string
	// ExtraProtectedPaths are additional canonical runtime artifacts whose Edit/Write is
	// self-protected, each mapped to a reason. Nil when none.
	ExtraProtectedPaths map[string]string
	// AuditLogBase is the canonical audit-log path; the live log and rotation backups are
	// prefix-protected from Edit/Write. Empty when unknown.
	AuditLogBase string
}

func (r *PathPatternRule) Name() string { return "path-pattern" }

var writeStyleTools = map[string]bool{
	"Write": true, "Edit": true, "MultiEdit": true, "NotebookEdit": true,
}

func (r *PathPatternRule) Evaluate(ev *HookEvent) (Decision, bool, error) {
	if ev.isMCP() {
		return r.evalMCPPaths(ev)
	}
	switch ev.ToolName {
	case "Read", "Write", "Edit", "MultiEdit", "NotebookEdit":
		return r.evalPaths(ev)
	case "Glob", "Grep":
		return r.evalGlob(ev)
	}
	return Decision{}, false, nil
}

// evalMCPPaths is the tier-2 audit signal for MCP tools. A path argument whose name classifies as
// sensitive is recorded but not denied: MCP path-args frequently name remote resources, and a
// configured MCP server is a deliberate grant, so name-blocking would false-block legitimate calls.
// Paths under a blocked root are already denied by BlockedPathRule (which runs earlier). The
// returned Allow decision rides through the engine as an audit-only note.
func (r *PathPatternRule) evalMCPPaths(ev *HookEvent) (Decision, bool, error) {
	paths, err := ev.FilePaths()
	if err != nil {
		return Decision{}, false, err
	}
	for _, raw := range paths {
		if reason, hit := classifySensitive(raw); hit {
			return Decision{
				Action: Allow,
				Rule:   "mcp-sensitive-path",
				Reason: fmt.Sprintf("%s referenced %s (%q); allowed and audited (MCP path arg)", ev.ToolName, reason, raw),
			}, true, nil
		}
	}
	return Decision{}, false, nil
}

func (r *PathPatternRule) evalPaths(ev *HookEvent) (Decision, bool, error) {
	paths, err := ev.FilePaths()
	if err != nil {
		return Decision{}, false, err
	}
	write := writeStyleTools[ev.ToolName]
	for _, raw := range paths {
		canon, err := Canonicalize(raw, ev.Cwd)
		if err != nil {
			return Decision{}, false, err
		}
		if reason, hit := classifySensitive(canon); hit {
			return r.deny(fmt.Sprintf("%s is %s; %s it is blocked by corral policy (resolved %q)", canon, reason, verb(ev.ToolName), raw)), true, nil
		}
		if write {
			if d, hit := r.writeGuards(canon); hit {
				return d, true, nil
			}
		}
	}
	return Decision{}, false, nil
}

// writeGuards adds write-only protections: no writing under /etc, and self-protection of corral's
// own hook configuration.
func (r *PathPatternRule) writeGuards(canon string) (Decision, bool) {
	// Match against the conventional /etc name: on macOS Canonicalize resolves /etc → /private/etc,
	// which would otherwise slip past this gate.
	if etc := logicalSysPath(canon); Within(etc, "/etc") {
		return r.deny(fmt.Sprintf("writing under /etc (%q) is blocked by corral policy", canon)), true
	}
	if reason, ok := selfConfigMatch(canon, selfProtect{configDir: r.AgentConfigDir, footprint: r.Footprint, allFootprints: r.AllFootprints, hookPaths: r.HookPaths, extraPaths: r.ExtraProtectedPaths, auditLogBase: r.AuditLogBase}); ok {
		return r.deny(fmt.Sprintf("%q is %s; editing it would disable enforcement and is blocked", canon, reason)), true
	}
	return Decision{}, false
}

func (r *PathPatternRule) evalGlob(ev *HookEvent) (Decision, bool, error) {
	var in struct {
		Pattern string `json:"pattern"`
		Path    string `json:"path"`
		Glob    string `json:"glob"` // Grep's optional file filter
	}
	if len(ev.ToolInput) > 0 {
		if err := json.Unmarshal(ev.ToolInput, &in); err != nil {
			return Decision{}, false, fmt.Errorf("decode tool_input: %w", err)
		}
	}
	// Test the raw pattern, Grep's glob filter, the base path, and the joins (the effective target),
	// so both `Glob ~/.ssh/*` and `Glob path=~/.ssh pattern=*` (and `Grep glob=~/.ssh/*`) are caught.
	candidates := []string{in.Pattern, in.Glob}
	if in.Path != "" {
		candidates = append(candidates, in.Path)
		if in.Pattern != "" {
			candidates = append(candidates, filepath.Join(in.Path, in.Pattern))
		}
		if in.Glob != "" {
			candidates = append(candidates, filepath.Join(in.Path, in.Glob))
		}
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if reason, hit := classifySensitive(c); hit {
			return r.deny(fmt.Sprintf("%s targets %s; enumerating it is blocked by corral policy", ev.ToolName, reason)), true, nil
		}
	}
	return Decision{}, false, nil
}

func (r *PathPatternRule) deny(reason string) Decision {
	return Decision{Action: Deny, Rule: r.Name(), Reason: reason}
}

func verb(tool string) string {
	if writeStyleTools[tool] {
		return "writing"
	}
	return "reading"
}

// Package enforce builds the policy engine from a session's inputs and answers the hook events
// with it, for the sidecar and for a bare session's in-process hook.
package enforce

import (
	"bytes"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/audit"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sidecar"
)

// Inputs is what the policy is built from: the config, the home directory, environment,
// working directory, and audit-log path of the agent's session, and the corral version.
type Inputs struct {
	Config    *config.Config
	Home      string
	Env       map[string]string
	WorkDir   string
	AuditPath string
	Version   string // the corral version the session-start note names
}

// Handler reads the policy files once, checks that the engine builds, and answers each hook
// event with the exit code, stdout, and stderr the hook must reproduce. It is safe for
// concurrent use.
func Handler(in Inputs) (sidecar.Handler, error) {
	files := readPolicyFiles(in)
	if _, err := newEngine(in, files, policy.OSFS{}); err != nil {
		return nil, err
	}
	return eventHandler(in, func(fsys policy.FS) (*policy.Engine, error) {
		return newEngine(in, files, fsys)
	}), nil
}

// Evaluate answers one hook event in-process. It reads the policy files and builds the engine
// only for pre-tool-use.
func Evaluate(in Inputs, req sidecar.Request, payload []byte) sidecar.Response {
	return eventHandler(in, func(fsys policy.FS) (*policy.Engine, error) {
		return newEngine(in, readPolicyFiles(in), fsys)
	})(req, payload, policy.OSFS{})
}

// eventHandler answers hook events. Pre-tool-use builds the engine in fsys for each event, so
// the protected paths resolve in the filesystem the event paths resolve in.
func eventHandler(in Inputs, build func(fsys policy.FS) (*policy.Engine, error)) sidecar.Handler {
	aud := buildAuditor(in.Config, in.AuditPath)
	entropy := in.Config.Policy.SecretScan.EntropyThreshold
	return func(req sidecar.Request, payload []byte, fsys policy.FS) sidecar.Response {
		var stdout, stderr bytes.Buffer
		var code int
		switch req.Type {
		case sidecar.EventPreToolUse:
			eng, err := build(fsys)
			if err != nil {
				return sidecar.Response{Error: err.Error()}
			}
			present := policy.PresentJSON
			if req.Decision == sidecar.DecisionExit2 {
				present = policy.PresentExit2
			}
			code = policy.RunHookWithAudit(eng, aud, fsys, bytes.NewReader(payload), &stdout, &stderr, present)
		case sidecar.EventPostToolUse:
			code = policy.RunPostToolUseHook(entropy, 0, aud, bytes.NewReader(payload), policy.NewPostToolUseGate(&stdout), &stderr)
		case sidecar.EventUserPromptSubmit:
			ev, _ := policy.ParseEvent(payload)
			code, _ = PromptSecretWarn(ev, entropy, aud, &stdout)
		case sidecar.EventSessionStart:
			code = policy.WriteSessionStartContext(&stdout, SystemNote(
				runtime.GOOS, in.Version, in.Env[sandbox.BackendNotesEnvVar], in.Env[sandbox.ProviderNotesEnvVar],
			))
		default:
			return sidecar.Response{Error: fmt.Sprintf("unknown request type %q", req.Type)}
		}
		return sidecar.Response{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
	}
}

// CanonicalAgentConfigDir resolves and canonicalizes the selected agent's config dir in fsys.
func CanonicalAgentConfigDir(cfg *config.Config, home string, env map[string]string, fsys policy.FS) (string, error) {
	configDir, err := policy.CanonicalizeIn(fsys, cfg.AgentConfigDir(home, env), "")
	if err != nil {
		return "", fmt.Errorf("canonicalize config dir: %w", err)
	}
	return configDir, nil
}

// policyFiles is what the policy reads from files: the hook scripts named in the active agent's
// settings, and the repo AI ignore files.
type policyFiles struct {
	hookPaths []string
	ai        policy.AIIgnoreDiscovery
}

// readPolicyFiles reads the policy files on the host. Best-effort: an unreadable file
// contributes nothing.
func readPolicyFiles(in Inputs) policyFiles {
	return policyFiles{
		hookPaths: agents.LookupOrDefault(in.Config.EffectiveAgent()).ProtectedPaths(in.Config.AgentConfigDir(in.Home, in.Env)),
		// Configured sources discovered by walking up from the working directory.
		ai: policy.DiscoverAIIgnore(in.WorkDir, in.Config.Providers.AIIgnore.EffectiveSources()),
	}
}

// newEngine constructs the policy engine: blocked paths, and the Bash, path-pattern, and
// content-secret-scan rules. It canonicalizes the protected paths in fsys, the filesystem the
// event paths resolve in. It reads no process environment and no cwd.
func newEngine(in Inputs, files policyFiles, fsys policy.FS) (*policy.Engine, error) {
	cfg := in.Config
	alwaysRoots, err := canonicalizeAll(config.AlwaysBlockedExpanded(in.Home), fsys)
	if err != nil {
		return nil, err
	}
	roots, err := canonicalizeAll(append(cfg.ConfigBlockedDirs(in.Home), cfg.ConfigBlockedFiles(in.Home)...), fsys)
	if err != nil {
		return nil, err
	}

	// Self-protect target + content-scan skip list, both canonicalized.
	configDir, err := CanonicalAgentConfigDir(cfg, in.Home, in.Env, fsys)
	if err != nil {
		return nil, err
	}
	skip, err := canonicalizeAll(cfg.Policy.SecretScan.SkipPaths, fsys)
	if err != nil {
		return nil, err
	}

	// Non-corral hook script paths from the active agent's settings. Best-effort.
	hookPaths := canonicalHookPaths(files.hookPaths, fsys)

	// Per-agent self-protect footprint: the active agent's anchors the configDir checks;
	// every registered agent's drives the defense-in-depth path-segment scan.
	footprint, allFootprints := agentFootprints(cfg)

	// Repo-level AI ignore globs, rooted at the directory that holds the sources. Best-effort.
	ai := files.ai
	aiRoot := ""
	if ai.Dir != "" {
		if aiRoot, err = policy.CanonicalizeRootIn(fsys, ai.Dir, ""); err != nil {
			aiRoot = filepath.Clean(ai.Dir)
		}
	}

	// Extra runtime artifacts the self-protect gate guards: the audit log and its rotation
	// backups, and the native repo AI ignore files.
	extraProtected := auditProtectedPaths(in.AuditPath, fsys)
	for canon, reason := range policy.AIIgnoreProtectedPaths(ai.ProtectFiles, fsys) {
		extraProtected[canon] = reason
	}

	// Canonical audit-log base: the live log and all its rotated backups are prefix-protected.
	// Best-effort: an unresolvable path degrades to the exact-match entries.
	auditBase, _ := policy.CanonicalizeRootIn(fsys, in.AuditPath, "")

	sp := policy.SelfProtect{
		ConfigDir:     configDir,
		Footprint:     footprint,
		AllFootprints: allFootprints,
		HookPaths:     hookPaths,
		ExtraPaths:    extraProtected,
		AuditLogBase:  auditBase,
	}

	eng := policy.NewEngine(
		&policy.BlockedPathRule{RuleName: "always-blocked", Roots: alwaysRoots},
		&policy.BlockedPathRule{RuleName: "blocked-path", Roots: roots},
		// Repo AI ignore globs: additive deny (no negation).
		&policy.AIIgnoreRule{Root: aiRoot, Patterns: ai.Patterns},
		&policy.BashRule{SelfProtect: sp},
		// Name-based gate before the costlier content scan.
		&policy.PathPatternRule{SelfProtect: sp},
		// Content secret scan: known formats always on; entropy heuristic on positive threshold.
		&policy.SecretScanRule{
			EntropyThreshold: cfg.Policy.SecretScan.EntropyThreshold,
			SkipRoots:        skip,
		},
	)
	return eng, nil
}

// canonicalHookPaths canonicalizes in fsys and de-duplicates the extra host artifacts the active
// agent needs the fail-closed hook to self-protect — for claude, the non-corral command hook scripts
// across its merged settings, whose code runs host-side next session. The agent supplies raw paths
// (it does not import policy). Best-effort: any unresolvable input contributes nothing. Never
// errors, so a broken config degrades to the static .claude/hooks assumption rather than breaking
// policy init.
func canonicalHookPaths(paths []string, fsys policy.FS) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range paths {
		canon, err := policy.CanonicalizeIn(fsys, p, "")
		if err != nil || seen[canon] {
			continue
		}
		seen[canon] = true
		out = append(out, canon)
	}
	return out
}

// agentFootprint maps an agent's static footprint (agents.Footprint) onto policy's mirror
// (policy.AgentFootprint). policy imports no agent, so this maps it.
func agentFootprint(a agents.Agent) policy.AgentFootprint {
	fp := a.Footprint()
	return policy.AgentFootprint{
		Dir:            fp.Dir,
		DirReason:      fp.DirReason,
		ProjectDir:     fp.ProjectDir,
		ProtectedFiles: fp.ProtectedFiles,
		ProtectedDirs:  fp.ProtectedDirs,
		ProtectedNames: fp.ProtectedNames,
	}
}

// agentFootprints returns the active agent's footprint (drives the configDir-anchored self-protect
// checks) and every registered agent's (drives the defense-in-depth path-segment scan, so one agent's
// session can't sabotage another's). Pure data, no I/O: the fail-closed hook's hot path stays fast.
func agentFootprints(cfg *config.Config) (policy.AgentFootprint, []policy.AgentFootprint) {
	active := agentFootprint(agents.LookupOrDefault(cfg.EffectiveAgent()))
	var all []policy.AgentFootprint
	for _, name := range agents.Known() {
		if a, ok := agents.Lookup(name); ok {
			all = append(all, agentFootprint(a))
		}
	}
	return active, all
}

// buildAuditor returns the always-on audit callback. Tool-call decisions are logged unconditionally,
// so it is non-disableable — no nil/off path. In a corral session the sidecar writes it from the
// host. Writing is best-effort: a logging error is swallowed, never changing a verdict or failing
// the hook.
func buildAuditor(cfg *config.Config, auditPath string) policy.AuditFunc {
	logger := audit.New(cfg.Policy.Audit, auditPath)
	return func(ev *policy.HookEvent, dec policy.Decision) {
		_ = logger.Log(audit.Record{
			SessionID: ev.SessionID,
			Tool:      ev.ToolName,
			Action:    dec.Action.String(),
			Rule:      dec.Rule,
			Reason:    dec.Reason,
			Cwd:       ev.Cwd,
			// Structural summary of the tool parameters: path/command/arg shapes, content bodies
			// reduced to a byte count. Sanitization runs under a recover, so it can't change the verdict.
			Input: ev.SanitizedInput(),
		})
	}
}

// auditProtectedPaths returns self-protect entries for the audit log at base and its backups,
// canonicalized in fsys. Canonicalized leniently: unresolvable paths are skipped.
func auditProtectedPaths(base string, fsys policy.FS) map[string]string {
	out := map[string]string{}
	add := func(p, reason string) {
		if canon, err := policy.CanonicalizeRootIn(fsys, p, ""); err == nil {
			out[canon] = reason
		}
	}
	add(base, "corral's audit log")
	add(filepath.Dir(base), "corral's audit-log directory")
	for _, b := range audit.Backups(base) {
		add(b, "corral's audit log")
	}
	return out
}

// canonicalizeAll canonicalizes trusted deny roots in fsys, failing closed on any error except
// a permission error on the root itself.
func canonicalizeAll(paths []string, fsys policy.FS) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		canon, err := policy.CanonicalizeRootIn(fsys, p, "")
		if err != nil {
			return nil, fmt.Errorf("canonicalize %q: %w", p, err)
		}
		out = append(out, canon)
	}
	return out, nil
}

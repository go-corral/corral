package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/audit"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers/aiignore"
	"github.com/go-corral/corral/internal/sandbox"
)

// hookDispatch maps each hook event to its handler. cmdHook fails closed on unknown events.
var hookDispatch = map[string]func(args []string) int{
	"pre-tool-use":       cmdHookPreToolUse,
	"post-tool-use":      cmdHookPostToolUse,
	"session-start":      cmdHookSessionStart,
	"user-prompt-submit": cmdHookUserPromptSubmit,
}

// cmdHook dispatches the hook enforcer subcommands (the hot path: fast, fail-closed).
func cmdHook(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "corral hook: missing event (e.g. pre-tool-use)")
		return policy.ExitBlock // a misinvoked gate blocks, never allows
	}
	// The kill switch: a deliberate opt-out that disables corral for the session. Checked
	// before any parse or config load. Refused inside corral's own sandbox.
	if sandbox.HooksDisabled() {
		noteHooksDisabled(args[0])
		return policy.ExitAllow
	}
	if h, ok := hookDispatch[args[0]]; ok {
		return h(args[1:])
	}
	fmt.Fprintf(os.Stderr, "corral hook: unknown event %q, blocking (fail-closed)\n", args[0])
	return policy.ExitBlock
}

// cmdHookSessionStart injects a model-only note about the sandbox into the session context.
func cmdHookSessionStart(args []string) int {
	return runSessionStartHook(os.Stdin, os.Stdout)
}

// runSessionStartHook is cmdHookSessionStart with stdin/stdout injected for tests.
func runSessionStartHook(stdin io.Reader, stdout io.Writer) int {
	// Drain stdin so claude's write completes; bounded against hostile payloads.
	_, _ = io.Copy(io.Discard, io.LimitReader(stdin, 1<<20))

	if !sandbox.InsideCorral() {
		return policy.ExitAllow // not sandboxed → say nothing
	}
	return policy.WriteSessionStartContext(stdout, sandboxSystemNote(
		os.Getenv(sandbox.BackendNotesEnvVar), os.Getenv(sandbox.ProviderNotesEnvVar),
	))
}

// cmdHookUserPromptSubmit is the sandbox-presence warning: swallows the first prompt with
// a warning then proceeds on resubmit (once per session).
func cmdHookUserPromptSubmit(args []string) int {
	return runUserPromptSubmitHook(os.Stdin, os.Stdout)
}

// runUserPromptSubmitHook is the testable core.
func runUserPromptSubmitHook(stdin io.Reader, stdout io.Writer) int {
	// Read the event (need session_id + prompt); bounded against hostile payloads.
	data, _ := io.ReadAll(io.LimitReader(stdin, 1<<20))
	ev, _ := policy.ParseEvent(data) // best-effort; the checks below are nil-safe

	// The prompt secret scan runs sandboxed or not. Soft warn-and-resubmit, keyed per prompt.
	if code, handled := promptSecretWarn(ev, stdout); handled {
		return code
	}

	if sandbox.InsideCorral() {
		return policy.ExitAllow // properly sandboxed
	}
	// Not sandboxed: CORRAL_PRESENCE_ACK silences the warning only (secret scan still ran).
	if sandbox.PresenceAcked() {
		return policy.ExitAllow
	}
	// Once-per-session marker keyed on the session id.
	sid := ""
	if ev != nil {
		sid = ev.SessionID
	}
	marker := presenceMarkerPath(sid)
	if _, err := os.Stat(marker); err == nil {
		return policy.ExitAllow // already warned this session → proceed
	}
	// Best-effort: a failed write only risks warning again, never a block.
	if f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600); err == nil {
		_ = f.Close()
	}
	return policy.WriteUserPromptBlock(stdout, presenceWarning())
}

// promptSecretWarn scans the submitted prompt for secret material. On a hit it emits a soft
// warn-and-resubmit notice and audit-logs the decision (kind only, never the prompt or value).
// Advisory, not a gate: degrades to known-formats-only on internal failure.
func promptSecretWarn(ev *policy.HookEvent, stdout io.Writer) (int, bool) {
	if ev == nil || ev.Prompt == "" {
		return policy.ExitAllow, false
	}
	entropy := 0.0
	hint := ""
	var aud policy.AuditFunc
	if cfg, configDir, err := loadHookConfig(nil); err == nil {
		entropy = cfg.Policy.SecretScan.EntropyThreshold
		hint = cfg.Policy.IncidentHint
		aud = buildAuditor(cfg, configDir)
	}
	kind, hit := policy.ScanPromptText([]byte(ev.Prompt), entropy, 0)
	if !hit {
		return policy.ExitAllow, false
	}
	// Resubmit-once per distinct prompt.
	marker := promptSecretMarkerPath(ev.SessionID, ev.Prompt)
	if _, err := os.Stat(marker); err == nil {
		return policy.ExitAllow, true
	}
	// Best-effort marker write; failure only risks warning again.
	if f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600); err == nil {
		_ = f.Close()
	}
	auditPromptSecret(aud, ev, kind)
	if hint == "" {
		hint = policy.IncidentHint
	}
	return policy.WriteUserPromptBlock(stdout, promptSecretWarning(kind, hint)), true
}

// auditPromptSecret records the prompt-secret-scan decision under its own recover.
func auditPromptSecret(aud policy.AuditFunc, ev *policy.HookEvent, kind policy.SecretKind) {
	if aud == nil {
		return
	}
	defer func() { _ = recover() }()
	aud(ev, policy.Decision{
		Action: policy.Deny,
		Rule:   "prompt-secret-scan",
		Reason: fmt.Sprintf("the submitted prompt appears to contain %s", kind),
	})
}

// presenceMarkerPath is the per-session marker under $TMPDIR.
func presenceMarkerPath(sessionID string) string {
	return filepath.Join(os.TempDir(), "corral-unsandboxed-"+sanitizeMarkerComponent(sessionID))
}

// noteHooksDisabled records, once per agent process, that CORRAL_DISABLE_HOOKS stood corral
// down — so a disabled session is never indistinguishable from one whose enforcement silently broke.
// Keyed on the parent pid (stable for the session, free to read).
func noteHooksDisabled(event string) {
	marker := filepath.Join(os.TempDir(), fmt.Sprintf("corral-hooksoff-%d", os.Getppid()))
	if _, err := os.Stat(marker); err == nil {
		return
	}
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return
	}
	_ = f.Close()

	cfg, configDir, err := loadHookConfig(nil)
	if err != nil {
		return
	}
	_ = audit.New(cfg.Policy.Audit, effectiveAuditPath(cfg, configDir)).Log(audit.Record{
		Action: policy.Allow.String(),

		Rule:   "hooks-disabled",
		Reason: sandbox.DisableHooksEnvVar + " is set: corral is disabled for this session (first event: " + event + ")",
	})
}

// promptSecretMarkerPath is the per-(session,prompt) marker under $TMPDIR. Hashing the
// prompt gives resubmit-once-per-distinct-prompt.
func promptSecretMarkerPath(sessionID, prompt string) string {
	sum := sha256.Sum256([]byte(prompt))
	return filepath.Join(os.TempDir(), "corral-promptsecret-"+sanitizeMarkerComponent(sessionID)+"-"+hex.EncodeToString(sum[:8]))
}

// sanitizeMarkerComponent maps an untrusted session id to a safe filename component,
// capped at 128 bytes.
func sanitizeMarkerComponent(s string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, s)
	if len(safe) > 128 {
		safe = safe[:128]
	}
	return safe
}

// presenceWarning is the user-facing notice shown when claude was launched without `corral run`.
func presenceWarning() string {
	return strings.Join([]string{
		"⚠  corral: this Claude session is NOT sandboxed — it was started without `corral run`.",
		"   Filesystem isolation and the credential masks (~/.ssh, ~/.gnupg, ~/.aws, ~/.kube,",
		"   ~/.config/gcloud, ~/.azure) are OFF; only the policy hook is active. To sandbox it,",
		"   exit and relaunch with:  corral run",
		"   To continue unsandboxed, just resubmit your prompt (this warning fires once per session).",
		"   Deliberately running under another sandbox? " + sandbox.PresenceAckEnvVar + "=1 silences this warning",
		"   and keeps the policy hook on; " + sandbox.DisableHooksEnvVar + "=1 disables corral entirely.",
	}, "\n")
}

// promptSecretWarning is the user-facing notice when a submitted prompt appears to contain a
// credential. Advisory: the prompt is swallowed and resubmitting proceeds. Names only the kind.
func promptSecretWarning(kind policy.SecretKind, hint string) string {
	return strings.Join([]string{
		fmt.Sprintf("⚠  corral: your prompt appears to contain %s — it was NOT sent.", kind),
		"   A secret typed into a prompt goes straight to the model provider. Remove or",
		"   pseudonymize it and resubmit. (To send this prompt anyway, just resubmit it.)",
		"   " + hint,
	}, "\n")
}

// sandboxSystemNote is the terse, model-facing description of the corral environment injected
// at session start. backendNotes and providerNotes are launcher-authored, appended as bullets.
func sandboxSystemNote(backendNotes, providerNotes string) string {
	lines := []string{
		"You are running inside corral, a security sandbox. For this session:",
		"- Writable: the working directory. Most other paths are read-only or absent.",
		"- Paths containing sensitive information (for example ~/.ssh, ~/.gnupg, ~/.aws, ~/.kube, ~/.config/gcloud, ~/.azure) are masked",
		"- Tool calls are policy-checked: credential reads/writes and destructive commands may be blocked.",
		"- Put scratch files, scripts, and intermediate output in a `scratchpad/` directory in the working directory, not /tmp. The harness may point you at a /tmp scratchpad path, but /tmp here is sandbox-private and the user can't see it; the working directory is writable and visible to you both.",
	}
	lines = appendNoteBullets(lines, backendNotes)
	lines = appendNoteBullets(lines, providerNotes)
	return strings.Join(lines, "\n")
}

// appendNoteBullets appends each non-blank line of raw as a "- " bullet.
func appendNoteBullets(lines []string, raw string) []string {
	for _, ln := range strings.Split(raw, "\n") {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		if !strings.HasPrefix(ln, "- ") {
			ln = "- " + ln
		}
		lines = append(lines, ln)
	}
	return lines
}

// stringSlice is a repeatable string flag.
type stringSlice []string

func (s *stringSlice) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// cmdHookPreToolUse runs the PreToolUse gate: install fail-closed signal handling, build
// the engine, evaluate stdin, exit 0 or 2. --block-path adds extra blocked roots.
func cmdHookPreToolUse(args []string) int {
	var extraRoots stringSlice
	fs := flag.NewFlagSet("pre-tool-use", flag.ContinueOnError)
	fs.Var(&extraRoots, "block-path", "additional path to block (repeatable)")
	profiles := addProfileFlags(fs)
	decision := fs.String("decision", "json", "how to report a block: \"json\" (clean policy decision) or \"exit2\"")
	if err := fs.Parse(args); err != nil {
		// A gate that can't parse its own flags must block.
		fmt.Fprintln(os.Stderr, "corral: bad hook arguments, blocking (fail-closed)")
		return policy.ExitBlock
	}

	present := policy.PresentJSON
	if *decision == "exit2" {
		present = policy.PresentExit2
	}

	stop := policy.InstallFailClosedSignals(os.Stderr)
	defer stop()

	eng, auditFn, err := buildEngine([]string(*profiles), extraRoots)
	if err != nil {
		// If we cannot construct the policy, block.
		fmt.Fprintf(os.Stderr, "corral: cannot initialize policy, blocking (fail-closed): %v\n", err)
		return policy.ExitBlock
	}
	return policy.RunHookWithAudit(eng, auditFn, os.Stdin, os.Stdout, os.Stderr, present)
}

// cmdHookPostToolUse runs the MCP response ingress scan: scans the tool response for secrets
// and withholds on a hit. Fail-closed means suppress (emit a replacement), since exit 2 is
// non-blocking for PostToolUse.
func cmdHookPostToolUse(args []string) (code int) {
	// One owner for the single replacement write — prevents garbled JSON from concurrent paths.
	gate := policy.NewPostToolUseGate(os.Stdout)
	stop := policy.InstallPostToolUseSignals(gate, os.Stderr)
	defer stop()

	// A panic in this prologue must withhold too: exit 2 is non-blocking for PostToolUse.
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(os.Stderr, "corral: internal error, withholding the tool response (fail-closed): %v\n", rec)
			code = gate.Replace("[corral] tool response withheld — internal error before the scan could run (fail-closed)")
		}
	}()

	fs := flag.NewFlagSet("post-tool-use", flag.ContinueOnError)
	profiles := addProfileFlags(fs)
	if err := fs.Parse(args); err != nil {
		// Learn the tool name before withholding: otherwise pre-parse paths fall back to the
		// Bash schema, which an mcp__* caller silently ignores.
		gate.ObserveShapeFrom(os.Stdin)
		return gate.Replace("[corral] tool response withheld — bad hook arguments (fail-closed)")
	}
	cfg, configDir, err := loadHookConfig([]string(*profiles))
	if err != nil {
		gate.ObserveShapeFrom(os.Stdin)
		return gate.Replace("[corral] tool response withheld — could not initialize policy (fail-closed)")
	}
	aud := buildAuditor(cfg, configDir)
	return policy.RunPostToolUseHook(cfg.Policy.SecretScan.EntropyThreshold, 0, cfg.Policy.IncidentHint, aud, os.Stdin, gate, os.Stderr)
}

// loadHookConfig loads config and the canonical effective agent config dir for a hook
// invocation. A failure is returned so the caller can fail closed.
func loadHookConfig(profiles []string) (*config.Config, string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, "", fmt.Errorf("resolve home: %w", err)
	}
	cfg, _, err := loadConfig(profiles)
	if err != nil {
		return nil, "", fmt.Errorf("load config: %w", err)
	}
	applyHookAgent(cfg)
	configDir, err := canonicalAgentConfigDir(cfg, home)
	if err != nil {
		return nil, "", err
	}
	return cfg, configDir, nil
}

// applyHookAgent overrides cfg.Agent with the agent the launcher pinned, so the in-sandbox
// hook self-protects the agent actually launched. Honored only for a registered agent.
func applyHookAgent(cfg *config.Config) {
	if name := os.Getenv(sandbox.AgentEnvVar); name != "" {
		if _, ok := agents.Lookup(name); ok {
			cfg.Agent = name
		}
	}
}

// canonicalAgentConfigDir resolves and canonicalizes the selected agent's config dir.
func canonicalAgentConfigDir(cfg *config.Config, home string) (string, error) {
	configDir, err := policy.Canonicalize(cfg.AgentConfigDir(home, envMap()), "")
	if err != nil {
		return "", fmt.Errorf("canonicalize config dir: %w", err)
	}
	return configDir, nil
}

// buildEngine constructs the policy engine: blocked paths plus --block-path roots, and the
// Bash, path-pattern, and content-secret-scan rules. A load failure fails the hook closed.
func buildEngine(profiles []string, extraRoots []string) (*policy.Engine, policy.AuditFunc, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve home: %w", err)
	}
	cfg, _, err := loadConfig(profiles)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	applyHookAgent(cfg)

	raw := append(cfg.EffectiveBlockedPaths(home), extraRoots...)
	roots, err := canonicalizeAll(raw)
	if err != nil {
		return nil, nil, err
	}

	// Self-protect target + content-scan skip list, both canonicalized.
	configDir, err := canonicalAgentConfigDir(cfg, home)
	if err != nil {
		return nil, nil, err
	}
	skip, err := canonicalizeAll(cfg.Policy.SecretScan.SkipPaths)
	if err != nil {
		return nil, nil, err
	}

	// Derive non-corral hook script paths from the active agent's live config. Best-effort.
	hookPaths := agentProtectedPaths(cfg, configDir)

	// Per-agent self-protect footprint: the active agent's anchors the configDir checks;
	// every registered agent's drives the defense-in-depth path-segment scan.
	footprint, allFootprints := agentFootprints(cfg)

	// Repo-level AI ignore: configured sources discovered by walking up from cwd, compiled
	// into deny globs. Best-effort.
	wd, _ := os.Getwd()
	ai := aiignore.Discover(wd, cfg.Providers.AIIgnore.EffectiveSources())

	// Extra runtime artifacts the self-protect gate guards: the audit log and its rotation
	// backups, and the native repo AI ignore files.
	extraProtected := auditProtectedPaths(cfg, configDir)
	for canon, reason := range aiignore.ProtectedPaths(ai.ProtectFiles) {
		extraProtected[canon] = reason
	}

	// Canonical audit-log base: the live log and all its rotated backups are prefix-protected.
	// Best-effort: an unresolvable path degrades to the exact-match entries.
	auditBase, _ := policy.CanonicalizeRoot(effectiveAuditPath(cfg, configDir), "")

	eng := policy.NewEngine(
		&policy.BlockedPathRule{RuleName: "blocked-path", Roots: roots},
		// Repo AI ignore globs: additive deny (no negation).
		&policy.AIIgnoreRule{Root: ai.Root, Patterns: ai.Patterns},
		&policy.BashRule{ConfigDir: configDir, Footprint: footprint, AllFootprints: allFootprints, HookPaths: hookPaths, ExtraProtectedPaths: extraProtected, AuditLogBase: auditBase},
		// Name-based gate before the costlier content scan.
		&policy.PathPatternRule{AgentConfigDir: configDir, Footprint: footprint, AllFootprints: allFootprints, HookPaths: hookPaths, ExtraProtectedPaths: extraProtected, AuditLogBase: auditBase},
		// Content secret scan: known formats always on; entropy heuristic on positive threshold.
		&policy.SecretScanRule{
			EntropyThreshold: cfg.Policy.SecretScan.EntropyThreshold,
			SkipRoots:        skip,
			IncidentHint:     cfg.Policy.IncidentHint,
		},
	)
	return eng, buildAuditor(cfg, configDir), nil
}

// agentProtectedPaths returns the canonical absolute paths of the extra host artifacts the active
// agent needs the fail-closed hook to self-protect — for claude, the non-corral command hook scripts
// across its merged settings, whose code runs host-side next session. The agent supplies raw paths
// (it does not import policy); this canonicalizes and de-duplicates them. Best-effort: an unknown
// agent falls back to the default, and any unresolvable input contributes nothing. Never errors, so a
// broken config degrades to the static .claude/hooks assumption rather than breaking policy init.
func agentProtectedPaths(cfg *config.Config, configDir string) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range activeAgent(cfg).ProtectedPaths(configDir) {
		canon, err := policy.Canonicalize(p, "")
		if err != nil || seen[canon] {
			continue
		}
		seen[canon] = true
		out = append(out, canon)
	}
	return out
}

// activeAgent resolves the active agent's adapter: the configured (launcher-pinned) agent, else the
// default for an unregistered name — defensive, since the fail-closed hook must never nil-deref.
func activeAgent(cfg *config.Config) agents.Agent {
	if a, ok := agents.Lookup(cfg.EffectiveAgent()); ok {
		return a
	}
	a, _ := agents.Lookup(agents.Default)
	return a
}

// agentFootprint maps an agent's static footprint (agents.Footprint) onto policy's mirror
// (policy.AgentFootprint). policy imports no agent; cli, the composition root, translates.
func agentFootprint(a agents.Agent) policy.AgentFootprint {
	fp := a.Footprint()
	return policy.AgentFootprint{
		Dir:            fp.Dir,
		DirReason:      fp.DirReason,
		ProtectedFiles: fp.ProtectedFiles,
		ProtectedDirs:  fp.ProtectedDirs,
	}
}

// agentFootprints returns the active agent's footprint (drives the configDir-anchored self-protect
// checks) and every registered agent's (drives the defense-in-depth path-segment scan, so one agent's
// session can't sabotage another's). Pure data, no I/O: the fail-closed hook's hot path stays fast.
func agentFootprints(cfg *config.Config) (policy.AgentFootprint, []policy.AgentFootprint) {
	active := agentFootprint(activeAgent(cfg))
	var all []policy.AgentFootprint
	for _, name := range agents.Known() {
		if a, ok := agents.Lookup(name); ok {
			all = append(all, agentFootprint(a))
		}
	}
	return active, all
}

// effectiveAuditPath returns the resolved audit-log path: the launcher's pin
// (CORRAL_AUDIT_PATH) when set, else the configured path. Shared by the auditor (writes)
// and the self-protect gate (guards), so they never diverge.
func effectiveAuditPath(cfg *config.Config, configDir string) string {
	if p := os.Getenv(sandbox.AuditPathEnvVar); p != "" {
		return p
	}
	return configuredAuditPath(cfg, configDir)
}

// configuredAuditPath returns the audit path from config alone: policy.audit.path or
// the default <configDir>/corral-audit.jsonl. The launcher resolves with this half — a
// nested launch must resolve from its own config, not inherit the enclosing sandbox's pin.
func configuredAuditPath(cfg *config.Config, configDir string) string {
	if p := cfg.Policy.Audit.Path; p != "" {
		return p
	}
	return filepath.Join(configDir, "corral-audit.jsonl")
}

// buildAuditor returns the always-on audit callback. Tool-call decisions are logged unconditionally,
// so it is non-disableable — no nil/off path. The default log lives under the effective agent config
// dir (for claude, $CLAUDE_CONFIG_DIR or ~/.claude), bound read-write into the sandbox. Writing is
// best-effort: a logging error is swallowed, never changing a verdict or failing the hook.
func buildAuditor(cfg *config.Config, configDir string) policy.AuditFunc {
	logger := audit.New(cfg.Policy.Audit, effectiveAuditPath(cfg, configDir))
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

// auditProtectedPaths returns self-protect entries for the audit log and its backups.
// Canonicalized leniently: unresolvable paths are skipped.
func auditProtectedPaths(cfg *config.Config, configDir string) map[string]string {
	base := effectiveAuditPath(cfg, configDir)
	out := map[string]string{}
	add := func(p, reason string) {
		if canon, err := policy.CanonicalizeRoot(p, ""); err == nil {
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

// canonicalizeAll canonicalizes trusted deny roots, failing closed on any error except a
// permission error on the root itself.
func canonicalizeAll(paths []string) ([]string, error) {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		canon, err := policy.CanonicalizeRoot(p, "")
		if err != nil {
			return nil, fmt.Errorf("canonicalize %q: %w", p, err)
		}
		out = append(out, canon)
	}
	return out, nil
}

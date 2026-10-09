package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/audit"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers/aiignore"
	"github.com/go-corral/corral/internal/providers/home"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sidecar"
	"github.com/go-corral/corral/internal/trust"
)

// Hook event names: the `corral hook` subcommands and the sidecar request types.
const (
	eventPreToolUse       = "pre-tool-use"
	eventPostToolUse      = "post-tool-use"
	eventSessionStart     = "session-start"
	eventUserPromptSubmit = "user-prompt-submit"
)

// Deny presentations: the `--decision` values of pre-tool-use.
const (
	decisionJSON  = "json"
	decisionExit2 = "exit2"
)

// hookVersion is the corral version, set once by Main. The session-start note names it.
var hookVersion = "dev"

// hookDispatch maps each hook event to its handler. cmdHook fails closed on unknown events.
var hookDispatch = map[string]func(args []string) int{
	eventPreToolUse:       cmdHookPreToolUse,
	eventPostToolUse:      cmdHookPostToolUse,
	eventSessionStart:     cmdHookSessionStart,
	eventUserPromptSubmit: cmdHookUserPromptSubmit,
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
	return policy.BlockFailClosed(os.Stderr, "unknown hook event %q", args[0])
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
		runtime.GOOS, hookVersion, os.Getenv(sandbox.BackendNotesEnvVar), os.Getenv(sandbox.ProviderNotesEnvVar),
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
	// When the policy cannot be evaluated, it scans for known credential formats only.
	resp := evaluate(sidecar.Request{Type: eventUserPromptSubmit}, data)
	if resp.Error != "" {
		if code, handled := promptSecretWarn(ev, 0, nil, stdout); handled {
			return code
		}
	} else {
		fmt.Fprint(os.Stderr, resp.Stderr)
		if resp.Stdout != "" {
			_, _ = io.WriteString(stdout, resp.Stdout)
			return resp.Code
		}
	}

	if sandbox.InsideCorral() {
		return policy.ExitAllow // properly sandboxed
	}
	// Not sandboxed: CORRAL_PRESENCE_ACK silences the warning only (secret scan still ran).
	if sandbox.PresenceAcked() {
		return policy.ExitAllow
	}
	// A resubmitted secret-bearing prompt proceeds without the presence warning.
	if ev != nil && ev.Prompt != "" {
		if _, err := os.Stat(promptSecretMarkerPath(ev.SessionID, ev.Prompt)); err == nil {
			return policy.ExitAllow
		}
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
// warn-and-resubmit notice and audit-logs the decision through aud when set (kind only, never
// the prompt or value).
func promptSecretWarn(ev *policy.HookEvent, entropy float64, aud policy.AuditFunc, stdout io.Writer) (int, bool) {
	if ev == nil || ev.Prompt == "" {
		return policy.ExitAllow, false
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
	return policy.WriteUserPromptBlock(stdout, promptSecretWarning(kind)), true
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

	in, err := localEngineInputs()
	if err != nil {
		return
	}
	_ = audit.New(in.cfg.Policy.Audit, in.auditPath).Log(audit.Record{
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
func promptSecretWarning(kind policy.SecretKind) string {
	return strings.Join([]string{
		fmt.Sprintf("⚠  corral: your prompt appears to contain %s — it was NOT sent.", kind),
		"   A secret typed into a prompt goes straight to the model provider. Remove or",
		"   pseudonymize it and resubmit. (To send this prompt anyway, just resubmit it.)",
	}, "\n")
}

// sandboxSystemNote is the terse, model-facing description of the corral environment injected
// at session start. goos selects how a sandbox deny reads. backendNotes and providerNotes are
// launcher-authored, appended as bullets.
func sandboxSystemNote(goos, version, backendNotes, providerNotes string) string {
	silentDeny := "a masked directory is empty, a masked file reads as `File content masked by corral`, a file under a masked directory or an unmounted path reads as `No such file or directory`, and a write to a read-only path fails with `Read-only file system`. A write outside the working directory and the granted paths can also work, but it goes to sandbox-private storage that the user does not see"
	if goos == "darwin" {
		silentDeny = "a masked path or a path without a grant fails with `Operation not permitted`"
	}
	lines := []string{
		"You are running inside corral " + version + ", a security sandbox. For this session:",
		"- Writable: the working directory. Most other paths are read-only or absent.",
		"- Always-blocked: `" + strings.Join(config.AlwaysBlockedPaths, "`, `") + "`. No setting can open them. If one of them is a symlink, its target is blocked too.",
		"- Two layers can block you. The sandbox (`os`) gives no policy message: " + silentDeny + ". A path that is missing here can exist on the host.",
		"- The policy hook (`hook`) checks your own tool calls. It blocks credential access, secrets, destructive commands, and edits to corral's own files. Its deny starts with `blocked by corral policy [hook:<rule>]` and names a fix. When a call ran but corral hid its output, the message starts with `output withheld by corral policy [hook:<rule>]`. It reads the text of a Bash command, but not what the started processes do. A shell probe that works does not show that a tool call is allowed.",
		"- When something is blocked, propose a fix to the user. For a hook deny, propose the named fix. For a sandbox deny, propose a `providers.paths.ro` grant to read or a `providers.paths.rw` grant to write, unless the path is always-blocked, in the `block` list, or excluded by an AI ignore file. Never work around a block with a rename, a subprocess, or a symlink. In Claude Code, `dangerouslyDisableSandbox` removes only its own per-command sandbox, never corral's.",
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

// cmdHookPreToolUse runs the PreToolUse gate: install fail-closed signal handling, evaluate
// stdin, reproduce the answer, exit 0 or 2.
func cmdHookPreToolUse(args []string) int {
	fs := flag.NewFlagSet(eventPreToolUse, flag.ContinueOnError)
	decision := fs.String("decision", decisionJSON, fmt.Sprintf("how to report a block: %q (clean policy decision) or %q", decisionJSON, decisionExit2))
	if err := fs.Parse(args); err != nil || (*decision != decisionJSON && *decision != decisionExit2) {
		// A gate that can't parse its own flags must block.
		return policy.BlockFailClosed(os.Stderr, "bad hook arguments")
	}

	stop := policy.InstallFailClosedSignals(os.Stderr)
	defer stop()

	data, err := io.ReadAll(io.LimitReader(os.Stdin, policy.MaxEventBytes+1))
	if err != nil {
		return policy.BlockFailClosed(os.Stderr, "cannot read hook input: %v", err)
	}
	resp := evaluate(sidecar.Request{Type: eventPreToolUse, Decision: *decision}, data)
	if resp.Error != "" {
		return policy.BlockFailClosed(os.Stderr, "cannot evaluate policy: %s", resp.Error)
	}
	if resp.Stdout != "" {
		if _, err := io.WriteString(os.Stdout, resp.Stdout); err != nil {
			// A deny JSON that never reached the agent must not become an allow.
			return policy.BlockFailClosed(os.Stderr, "cannot write the policy decision: %v", err)
		}
	}
	fmt.Fprint(os.Stderr, resp.Stderr)
	if resp.Code == policy.ExitAllow {
		return policy.ExitAllow
	}
	return policy.ExitBlock
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
			code = gate.Replace(policy.Unscanned("internal error"))
		}
	}()

	fs := flag.NewFlagSet(eventPostToolUse, flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		// Learn the tool name before withholding: otherwise pre-parse paths fall back to the
		// Bash schema, which an mcp__* caller silently ignores.
		gate.ObserveShapeFrom(os.Stdin)
		return gate.Replace(policy.Unscanned("bad hook arguments"))
	}
	data, err := io.ReadAll(io.LimitReader(os.Stdin, policy.MaxEventBytes+1))
	if err != nil {
		return gate.Replace(policy.Unscanned("cannot read the output"))
	}
	if ev, err := policy.ParseEvent(data); err == nil {
		gate.Observe(ev.ToolName, ev.ResponseBytes())
	} else {
		gate.ObserveShapeFrom(bytes.NewReader(data))
	}
	resp := evaluate(sidecar.Request{Type: eventPostToolUse}, data)
	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "corral: cannot evaluate policy, withholding the tool response (fail-closed): %s\n", resp.Error)
		return gate.Replace(policy.Unscanned("cannot evaluate policy"))
	}
	fmt.Fprint(os.Stderr, resp.Stderr)
	return gate.Forward(resp.Stdout, resp.Code)
}

// engineInputs is what the policy is built from: the config, and the home directory,
// environment, working directory, and audit-log path of the agent's session.
type engineInputs struct {
	cfg       *config.Config
	home      string
	env       map[string]string
	workDir   string
	auditPath string
}

// localEngineInputs resolves the engine inputs from this process: a bare session's hook.
func localEngineInputs() (engineInputs, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return engineInputs{}, fmt.Errorf("resolve home: %w", err)
	}
	cfg, _, err := loadConfig(nil)
	if err != nil {
		return engineInputs{}, fmt.Errorf("load config: %w", err)
	}
	env := envMap()
	// Fail closed on an agent config dir the engine cannot canonicalize, for every event. The
	// audit path keys on the uncanonicalized dir, as the launcher's does.
	if _, err := canonicalAgentConfigDir(cfg, home, env, policy.OSFS{}); err != nil {
		return engineInputs{}, err
	}
	wd, _ := os.Getwd()
	auditPath := effectiveAuditPath(cfg, trust.StateDir(home, env["XDG_STATE_HOME"]), cfg.AgentConfigDir(home, env))
	return engineInputs{cfg: cfg, home: home, env: env, workDir: wd, auditPath: auditPath}, nil
}

// evaluate answers one hook event. With a sidecar it forwards the event. Inside the sandbox
// without one it refuses, so nothing in the sandbox can bypass the policy fixed at launch.
// Otherwise it evaluates in-process from this process's own config.
func evaluate(req sidecar.Request, payload []byte) sidecar.Response {
	if path := os.Getenv(sandbox.SidecarSocketEnvVar); path != "" {
		return sidecar.Call(path, req, payload, policy.OSFS{})
	}
	if sandbox.InsideCorral() {
		return sidecar.Response{Error: "no sidecar: " + sandbox.SidecarSocketEnvVar + " is not set inside the sandbox"}
	}
	in, err := localEngineInputs()
	if err != nil {
		return sidecar.Response{Error: err.Error()}
	}
	return eventHandler(in, func(fsys policy.FS) (*policy.Engine, error) {
		return newEngine(in, readPolicyFiles(in), fsys)
	})(req, payload, policy.OSFS{})
}

// policyHandler reads the policy files once, checks that the engine builds, and answers each
// hook event with the exit code, stdout, and stderr the hook must reproduce. It is safe for
// concurrent use.
func policyHandler(in engineInputs) (sidecar.Handler, error) {
	files := readPolicyFiles(in)
	if _, err := newEngine(in, files, policy.OSFS{}); err != nil {
		return nil, err
	}
	return eventHandler(in, func(fsys policy.FS) (*policy.Engine, error) {
		return newEngine(in, files, fsys)
	}), nil
}

// eventHandler answers hook events. Pre-tool-use builds the engine in fsys for each event, so
// the protected paths resolve in the filesystem the event paths resolve in.
func eventHandler(in engineInputs, build func(fsys policy.FS) (*policy.Engine, error)) sidecar.Handler {
	aud := buildAuditor(in.cfg, in.auditPath)
	entropy := in.cfg.Policy.SecretScan.EntropyThreshold
	return func(req sidecar.Request, payload []byte, fsys policy.FS) sidecar.Response {
		var stdout, stderr bytes.Buffer
		var code int
		switch req.Type {
		case eventPreToolUse:
			eng, err := build(fsys)
			if err != nil {
				return sidecar.Response{Error: err.Error()}
			}
			present := policy.PresentJSON
			if req.Decision == decisionExit2 {
				present = policy.PresentExit2
			}
			code = policy.RunHookWithAudit(eng, aud, fsys, bytes.NewReader(payload), &stdout, &stderr, present)
		case eventPostToolUse:
			code = policy.RunPostToolUseHook(entropy, 0, aud, bytes.NewReader(payload), policy.NewPostToolUseGate(&stdout), &stderr)
		case eventUserPromptSubmit:
			ev, _ := policy.ParseEvent(payload)
			code, _ = promptSecretWarn(ev, entropy, aud, &stdout)
		default:
			return sidecar.Response{Error: fmt.Sprintf("unknown request type %q", req.Type)}
		}
		return sidecar.Response{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
	}
}

// canonicalAgentConfigDir resolves and canonicalizes the selected agent's config dir in fsys.
func canonicalAgentConfigDir(cfg *config.Config, home string, env map[string]string, fsys policy.FS) (string, error) {
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
	ai        aiignore.Discovery
}

// readPolicyFiles reads the policy files on the host. Best-effort: an unreadable file
// contributes nothing.
func readPolicyFiles(in engineInputs) policyFiles {
	return policyFiles{
		hookPaths: activeAgent(in.cfg).ProtectedPaths(in.cfg.AgentConfigDir(in.home, in.env)),
		// Configured sources discovered by walking up from the working directory.
		ai: aiignore.Discover(in.workDir, in.cfg.Providers.AIIgnore.EffectiveSources()),
	}
}

// newEngine constructs the policy engine: blocked paths, and the Bash, path-pattern, and
// content-secret-scan rules. It canonicalizes the protected paths in fsys, the filesystem the
// event paths resolve in. It reads no process environment and no cwd.
func newEngine(in engineInputs, files policyFiles, fsys policy.FS) (*policy.Engine, error) {
	cfg := in.cfg
	alwaysRoots, err := canonicalizeAll(config.AlwaysBlockedExpanded(in.home), fsys)
	if err != nil {
		return nil, err
	}
	roots, err := canonicalizeAll(append(cfg.ConfigBlockedDirs(in.home), cfg.ConfigBlockedFiles(in.home)...), fsys)
	if err != nil {
		return nil, err
	}

	// Self-protect target + content-scan skip list, both canonicalized.
	configDir, err := canonicalAgentConfigDir(cfg, in.home, in.env, fsys)
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
	extraProtected := auditProtectedPaths(in.auditPath, fsys)
	for canon, reason := range aiignore.ProtectedPaths(ai.ProtectFiles, fsys) {
		extraProtected[canon] = reason
	}

	// Canonical audit-log base: the live log and all its rotated backups are prefix-protected.
	// Best-effort: an unresolvable path degrades to the exact-match entries.
	auditBase, _ := policy.CanonicalizeRootIn(fsys, in.auditPath, "")

	eng := policy.NewEngine(
		&policy.BlockedPathRule{RuleName: "always-blocked", Roots: alwaysRoots},
		&policy.BlockedPathRule{RuleName: "blocked-path", Roots: roots},
		// Repo AI ignore globs: additive deny (no negation).
		&policy.AIIgnoreRule{Root: aiRoot, Patterns: ai.Patterns},
		&policy.BashRule{ConfigDir: configDir, Footprint: footprint, AllFootprints: allFootprints, HookPaths: hookPaths, ExtraProtectedPaths: extraProtected, AuditLogBase: auditBase},
		// Name-based gate before the costlier content scan.
		&policy.PathPatternRule{AgentConfigDir: configDir, Footprint: footprint, AllFootprints: allFootprints, HookPaths: hookPaths, ExtraProtectedPaths: extraProtected, AuditLogBase: auditBase},
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

// activeAgent resolves the active agent's adapter: the configured agent, else the
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
func effectiveAuditPath(cfg *config.Config, stateDir, configDir string) string {
	if p := os.Getenv(sandbox.AuditPathEnvVar); p != "" {
		return p
	}
	return configuredAuditPath(cfg, stateDir, configDir)
}

// configuredAuditPath returns the audit path from config alone: policy.audit.path or the
// default. The launcher resolves with this half — a nested launch must resolve from its own
// config, not inherit the enclosing sandbox's pin.
func configuredAuditPath(cfg *config.Config, stateDir, configDir string) string {
	if p := cfg.Policy.Audit.Path; p != "" {
		return p
	}
	return defaultAuditPath(stateDir, configDir)
}

// defaultAuditPath is the default audit log of the agent config dir configDir, in a state
// directory the sandbox does not mount. configDir is uncanonicalized, as for the private home,
// so the launcher and a bare session with the same inputs resolve the same file.
func defaultAuditPath(stateDir, configDir string) string {
	return filepath.Join(stateDir, "corral", "audit", home.ConfigDirKey(configDir), "corral-audit.jsonl")
}

// legacyAuditPath is the former default audit log, inside the agent config dir.
func legacyAuditPath(configDir string) string {
	return filepath.Join(configDir, "corral-audit.jsonl")
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

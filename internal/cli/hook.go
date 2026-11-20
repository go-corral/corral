package cli

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-corral/corral/internal/audit"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/enforce"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers/home"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sidecar"
	"github.com/go-corral/corral/internal/trust"
)

// hookVersion is the corral version, set once by Main. The session-start note names it.
var hookVersion = "dev"

// hookDispatch maps each hook event to its handler. cmdHook fails closed on unknown events.
var hookDispatch = map[string]func(args []string) int{
	sidecar.EventPreToolUse:       cmdHookPreToolUse,
	sidecar.EventPostToolUse:      cmdHookPostToolUse,
	sidecar.EventSessionStart:     cmdHookSessionStart,
	sidecar.EventUserPromptSubmit: cmdHookUserPromptSubmit,
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
	return policy.WriteSessionStartContext(stdout, enforce.SystemNote(
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
	resp := evaluate(sidecar.Request{Type: sidecar.EventUserPromptSubmit}, data)
	if resp.Error != "" {
		if code, handled := enforce.PromptSecretWarn(ev, 0, nil, stdout); handled {
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
		if _, err := os.Stat(enforce.PromptSecretMarkerPath(ev.SessionID, ev.Prompt)); err == nil {
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

// presenceMarkerPath is the per-session marker under $TMPDIR.
func presenceMarkerPath(sessionID string) string {
	return filepath.Join(os.TempDir(), "corral-unsandboxed-"+enforce.SanitizeMarkerComponent(sessionID))
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
	_ = audit.New(in.Config.Policy.Audit, in.AuditPath).Log(audit.Record{
		Action: policy.Allow.String(),

		Rule:   "hooks-disabled",
		Reason: sandbox.DisableHooksEnvVar + " is set: corral is disabled for this session (first event: " + event + ")",
	})
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
	fs := flag.NewFlagSet(sidecar.EventPreToolUse, flag.ContinueOnError)
	decision := fs.String("decision", sidecar.DecisionJSON, fmt.Sprintf("how to report a block: %q (clean policy decision) or %q", sidecar.DecisionJSON, sidecar.DecisionExit2))
	if err := fs.Parse(args); err != nil || (*decision != sidecar.DecisionJSON && *decision != sidecar.DecisionExit2) {
		// A gate that can't parse its own flags must block.
		return policy.BlockFailClosed(os.Stderr, "bad hook arguments")
	}

	stop := policy.InstallFailClosedSignals(os.Stderr)
	defer stop()

	data, err := io.ReadAll(io.LimitReader(os.Stdin, policy.MaxEventBytes+1))
	if err != nil {
		return policy.BlockFailClosed(os.Stderr, "cannot read hook input: %v", err)
	}
	resp := evaluate(sidecar.Request{Type: sidecar.EventPreToolUse, Decision: *decision}, data)
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

	fs := flag.NewFlagSet(sidecar.EventPostToolUse, flag.ContinueOnError)
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
	resp := evaluate(sidecar.Request{Type: sidecar.EventPostToolUse}, data)
	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "corral: cannot evaluate policy, withholding the tool response (fail-closed): %s\n", resp.Error)
		return gate.Replace(policy.Unscanned("cannot evaluate policy"))
	}
	fmt.Fprint(os.Stderr, resp.Stderr)
	return gate.Forward(resp.Stdout, resp.Code)
}

// localEngineInputs resolves the engine inputs from this process: a bare session's hook.
func localEngineInputs() (enforce.Inputs, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return enforce.Inputs{}, fmt.Errorf("resolve home: %w", err)
	}
	cfg, _, err := loadConfig(nil)
	if err != nil {
		return enforce.Inputs{}, fmt.Errorf("load config: %w", err)
	}
	env := envMap()
	// Fail closed on an agent config dir the engine cannot canonicalize, for every event. The
	// audit path keys on the uncanonicalized dir, as the launcher's does.
	if _, err := enforce.CanonicalAgentConfigDir(cfg, home, env, policy.OSFS{}); err != nil {
		return enforce.Inputs{}, err
	}
	wd, _ := os.Getwd()
	auditPath := effectiveAuditPath(cfg, trust.StateDir(home, env["XDG_STATE_HOME"]), cfg.AgentConfigDir(home, env))
	return enforce.Inputs{Config: cfg, Home: home, Env: env, WorkDir: wd, AuditPath: auditPath, Version: hookVersion}, nil
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
	return enforce.Evaluate(in, req, payload)
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

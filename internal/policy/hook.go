package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// Exit codes for the hook enforcer. Claude Code treats exit 0 as no-op, exit 2 as block, and any
// other code as a non-blocking error (the tool call proceeds). So corral must only ever exit 0 or
// 2 — any other code fails open. Every path in this package funnels to one of these two codes.
const (
	ExitAllow = 0
	ExitBlock = 2
)

const maxEventBytes = 16 << 20 // 16 MiB; exceeding it fails closed

// Presentation selects how an intentional policy Deny is reported. Error paths always use the
// exit-2 fail-closed path regardless of presentation.
type Presentation int

const (
	PresentExit2 Presentation = iota
	// PresentJSON reports a Deny by printing a PreToolUse permissionDecision "deny" object to
	// stdout and exiting 0. Claude renders this as a clean policy decision rather than a "hook error".
	PresentJSON
)

// AuditFunc records a finalized decision for observability. It is isolated from the verdict: a
// panic or error inside it never changes the allow/deny outcome.
type AuditFunc func(ev *HookEvent, dec Decision)

// RunHook is the simple default (exit-2 Deny path), retained for tests.
func RunHook(eng *Engine, r io.Reader, errw io.Writer) int {
	return RunHookWith(eng, r, io.Discard, errw, PresentExit2)
}

func RunHookWith(eng *Engine, r io.Reader, out, errw io.Writer, present Presentation) int {
	return RunHookWithAudit(eng, nil, r, out, errw, present)
}

// RunHookWithAudit never returns a code other than ExitAllow or ExitBlock (fail-closed). It
// installs no signal handlers and does not call os.Exit, so it is testable.
func RunHookWithAudit(eng *Engine, aud AuditFunc, r io.Reader, out, errw io.Writer, present Presentation) (code int) {
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(errw, "corral: internal error, blocking (fail-closed): %v\n", rec)
			code = ExitBlock
		}
	}()

	data, err := io.ReadAll(io.LimitReader(r, maxEventBytes+1))
	if err != nil {
		fmt.Fprintf(errw, "corral: cannot read hook input, blocking: %v\n", err)
		return ExitBlock
	}
	if len(data) > maxEventBytes {
		fmt.Fprintf(errw, "corral: hook input exceeds %d bytes, blocking\n", maxEventBytes)
		return ExitBlock
	}

	ev, err := ParseEvent(data)
	if err != nil {
		fmt.Fprintf(errw, "corral: cannot parse hook event, blocking: %v\n", err)
		return ExitBlock
	}

	dec, err := eng.Evaluate(ev)
	if err != nil {
		// Never echo the raw error, which could contain tool input.
		safeAudit(aud, ev, Decision{Action: Deny, Rule: "engine-error", Reason: "policy evaluation error"}, errw)
		fmt.Fprintf(errw, "corral: policy evaluation error, blocking: %v\n", err)
		return ExitBlock
	}

	safeAudit(aud, ev, dec, errw)

	// Allow-list gate: only an explicit Allow proceeds. Any other verdict blocks, so a new
	// Action constant can never silently fail open by being unhandled here.
	if dec.Action != Allow {
		return presentDeny(dec, out, errw, present)
	}
	return ExitAllow
}

func safeAudit(aud AuditFunc, ev *HookEvent, dec Decision, errw io.Writer) {
	if aud == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(errw, "corral: audit logging panicked (ignored): %v\n", r)
		}
	}()
	aud(ev, dec)
}

func presentDeny(dec Decision, out, errw io.Writer, present Presentation) int {
	reason := fmt.Sprintf("blocked by corral policy [%s]: %s", dec.Rule, dec.Reason)
	if present == PresentJSON {
		payload, err := json.Marshal(denyOutput{
			HookSpecificOutput: preToolUseDeny{
				HookEventName:            "PreToolUse",
				PermissionDecision:       "deny",
				PermissionDecisionReason: reason,
			},
		})
		if err == nil {
			if _, werr := fmt.Fprintln(out, string(payload)); werr == nil {
				return ExitAllow
			}
			// stdout write failed: the deny JSON never reached Claude. Fall through to exit-2:
			// a Deny must never become an allow.
		}
	}
	fmt.Fprintf(errw, "corral: %s\n", reason)
	return ExitBlock
}

// postToolUseUpdate replaces what the model sees for a tool result via
// hookSpecificOutput.updatedToolOutput — the only mechanism that withholds an already-produced
// PostToolUse result. decision:"block" does not: the model would receive both the real result and
// the reason.
//
// The replacement's shape must match the original tool result's shape, or Claude Code silently
// ignores it and passes the original (secret-bearing) result to the model — a fail-open. See
// updatedToolOutputFor.
type postToolUseUpdate struct {
	HookSpecificOutput postToolUseUpdatedOutput `json:"hookSpecificOutput"`
}

type postToolUseUpdatedOutput struct {
	HookEventName     string `json:"hookEventName"`
	UpdatedToolOutput any    `json:"updatedToolOutput"`
}

type contentText struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

var bashTextKeys = []string{"stdout", "stderr", "output"}

// updatedToolOutputFor builds the updatedToolOutput value whose shape matches the original tool
// result, so Claude Code actually applies the replacement. MCP results are content-block arrays;
// built-in Bash results are a {stdout,stderr,...} object. When toolName/origResponse are unknown
// it defaults to the Bash object schema.
func updatedToolOutputFor(toolName string, origResponse []byte, marker string) any {
	if strings.HasPrefix(toolName, "mcp__") {
		return []contentText{{Type: "text", Text: marker}}
	}
	trimmed := bytes.TrimSpace(origResponse)
	if len(trimmed) > 0 {
		switch trimmed[0] {
		case '[':
			return []contentText{{Type: "text", Text: marker}}
		case '{':
			if obj := mirrorObjectWithMarker(trimmed, marker); obj != nil {
				return obj
			}
		case '"':
			return marker
		}
	}
	return bashResult(marker)
}

// mirrorObjectWithMarker decodes a Bash-shaped result object and overwrites its text-bearing
// fields with marker, preserving every other field. It returns nil if the bytes are not an object
// or if no known text field was present (the caller then falls back to a clean Bash result).
func mirrorObjectWithMarker(data []byte, marker string) map[string]json.RawMessage {
	var obj map[string]json.RawMessage
	if json.Unmarshal(data, &obj) != nil {
		return nil
	}
	markerJSON, err := json.Marshal(marker)
	if err != nil {
		return nil
	}
	emptyJSON, _ := json.Marshal("")
	replaced := false
	for _, k := range bashTextKeys {
		if _, ok := obj[k]; ok {
			if k == "stdout" || k == "output" {
				obj[k] = markerJSON
			} else { // stderr: blank it rather than echo the marker twice
				obj[k] = emptyJSON
			}
			replaced = true
		}
	}
	if !replaced {
		return nil
	}
	return obj
}

func bashResult(marker string) map[string]any {
	return map[string]any{"stdout": marker, "stderr": "", "interrupted": false, "isImage": false}
}

func probeToolName(data []byte) string {
	var probe struct {
		ToolName string `json:"tool_name"`
	}
	_ = json.Unmarshal(data, &probe)
	return probe.ToolName
}

// WritePostToolUseReplace replaces the tool result the model sees with marker, in a shape matching
// the original result. It returns ExitAllow (the replacement rides in the JSON). Used both for a
// real secret hit and for the ingress fail-closed path: because neither exit 2 nor decision:block
// withholds a PostToolUse result, every ingress error replaces the result here instead. On the
// near-impossible marshal failure it returns ExitBlock.
func WritePostToolUseReplace(out io.Writer, toolName string, origResponse []byte, marker string) int {
	payload, err := json.Marshal(postToolUseUpdate{
		HookSpecificOutput: postToolUseUpdatedOutput{
			HookEventName:     "PostToolUse",
			UpdatedToolOutput: updatedToolOutputFor(toolName, origResponse, marker),
		},
	})
	if err != nil {
		return ExitBlock
	}
	fmt.Fprintln(out, string(payload))
	return ExitAllow
}

// PostToolUseGate owns the one replacement write a PostToolUse invocation may make. Withholding a
// PostToolUse result is only possible by writing a replacement to stdout — neither exit 2 nor
// decision:block suppresses a result that already exists. That makes stdout the single point every
// fail-closed path has to reach: the scan's own error paths, a recovered panic, a panic in the CLI
// prologue, and a termination signal. Those paths are not mutually exclusive in time: the signal
// handler runs on its own goroutine and can fire mid-write. Two interleaved writes produce garbled
// JSON, Claude Code silently ignores it, and the model receives the original unscanned response —
// a fail-open created by the code meant to prevent one. So the gate serializes on a mutex and
// writes exactly once. The first caller wins; every later caller is a no-op returning the first
// write's exit code.
type PostToolUseGate struct {
	mu       sync.Mutex
	out      io.Writer
	written  bool
	code     int
	toolName string
	origResp []byte
}

func NewPostToolUseGate(out io.Writer) *PostToolUseGate {
	return &PostToolUseGate{out: out, code: ExitAllow}
}

// Observe records what is known about the event so a fail-closed write later can still match the
// original result's shape. Shape is load-bearing: an mcp__* result needs the content-block array
// form and the Bash-object default would be silently ignored. Empty values are ignored, so a
// best-effort probe can never erase a better-known value.
func (g *PostToolUseGate) Observe(toolName string, origResp []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if toolName != "" {
		g.toolName = toolName
	}
	if len(origResp) > 0 {
		g.origResp = origResp
	}
}

// ObserveShapeFrom reads a pending hook payload purely to learn its tool name, for a fail-closed
// write that must happen before the event is parsed (a bad-flags or config-error path in the CLI
// prologue). Without it those paths default to the Bash object schema, which an mcp__* caller
// silently ignores — the withhold would not apply. Best-effort: on any error the gate keeps what
// it already had.
func (g *PostToolUseGate) ObserveShapeFrom(r io.Reader) {
	data, err := io.ReadAll(io.LimitReader(r, maxEventBytes+1))
	if err != nil || len(data) == 0 {
		return
	}
	g.Observe(probeToolName(data), nil)
}

// Replace withholds the tool response, substituting marker. It writes at most once per process.
func (g *PostToolUseGate) Replace(marker string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.written {
		return g.code
	}
	g.written = true
	g.code = WritePostToolUseReplace(g.out, g.toolName, g.origResp, marker)
	return g.code
}

// InstallPostToolUseSignals makes a termination signal withhold the tool response instead of
// leaking it. PostToolUse has no blocking exit code: Go's default handler exits 128+signo and exit 2
// is equally non-blocking, so both let the original unscanned response through. The only way to
// fail closed is to perform the same stdout write the panic path performs — which is why this
// handler goes through the gate rather than just exiting. (A signal after the normal path already
// wrote is harmless: the gate no-ops.) Returns a stop function to uninstall the handler.
func InstallPostToolUseSignals(g *PostToolUseGate, errw io.Writer) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		s, ok := <-ch
		if !ok {
			return
		}
		fmt.Fprintf(errw, "corral: received %v, withholding the tool response (fail-closed)\n", s)
		os.Exit(g.Replace("[corral] tool response withheld — the secret scan was interrupted before it could finish (fail-closed)"))
	}()
	return func() { signal.Stop(ch); close(ch) }
}

// RunPostToolUseHook reads a PostToolUse event, scans the tool response for secret material, and
// replaces the response on a hit (ingress — the priority direction). Fail-closed for ingress means
// replace the response, not exit 2 or decision:block — neither withholds a PostToolUse result. So
// every error path and a recovered panic replaces the response with a withheld-marker; an unscanned
// response never reaches the model. A clean response is allowed (exit 0, no output).
func RunPostToolUseHook(entropyThreshold float64, maxScanBytes int64, incidentHint string, aud AuditFunc, r io.Reader, gate *PostToolUseGate, errw io.Writer) (code int) {
	defer func() {
		if rec := recover(); rec != nil {
			fmt.Fprintf(errw, "corral: internal error scanning tool response, withholding (fail-closed): %v\n", rec)
			code = gate.Replace("[corral] tool response withheld — internal error while scanning it (fail-closed)")
		}
	}()

	data, err := io.ReadAll(io.LimitReader(r, maxEventBytes+1))
	if err != nil {
		return gate.Replace("[corral] tool response withheld — could not read it to scan (fail-closed)")
	}
	if len(data) > maxEventBytes {
		gate.Observe(probeToolName(data), nil)
		return gate.Replace("[corral] tool response withheld — exceeds the scan size cap (fail-closed)")
	}
	ev, err := ParseEvent(data)
	if err != nil {
		gate.Observe(probeToolName(data), nil)
		return gate.Replace("[corral] tool response withheld — could not parse the hook event (fail-closed)")
	}
	gate.Observe(ev.ToolName, nil)

	resp := ev.ResponseBytes()
	if len(resp) == 0 {
		return ExitAllow
	}
	gate.Observe(ev.ToolName, resp)
	if kind, hit := ScanResponseBytes(capForScan(resp, maxScanBytes), entropyThreshold); hit {
		marker := fmt.Sprintf("[corral policy] This %s tool response was withheld: it contained %s, and corral kept it out of the model context to prevent secret exposure. %s", ev.ToolName, kind, incidentHintOr(incidentHint))
		safeAudit(aud, ev, Decision{
			Action: Deny,
			Rule:   "response-secret",
			Reason: fmt.Sprintf("response from %s contained %s; replaced via updatedToolOutput", ev.ToolName, kind),
		}, errw)
		return gate.Replace(marker)
	}
	return ExitAllow
}

// WriteSessionStartContext writes a SessionStart hook stdout that injects context into the model
// (Claude adds hookSpecificOutput.additionalContext to the session context). It always returns
// ExitAllow: SessionStart cannot block, and on a marshal error it writes nothing and still allows.
func WriteSessionStartContext(out io.Writer, context string) int {
	if context == "" {
		return ExitAllow
	}
	payload, err := json.Marshal(sessionStartOutput{
		HookSpecificOutput: sessionStartContext{
			HookEventName:     "SessionStart",
			AdditionalContext: context,
		},
	})
	if err != nil {
		return ExitAllow
	}
	fmt.Fprintln(out, string(payload))
	return ExitAllow
}

// WriteUserPromptBlock emits a UserPromptSubmit "block" decision: Claude swallows the submitted
// prompt and shows reason to the user. The decision rides in the JSON, so the exit code is 0. On a
// marshal error it writes nothing and allows (it must never wall off the session).
func WriteUserPromptBlock(out io.Writer, reason string) int {
	payload, err := json.Marshal(userPromptDecision{Decision: "block", Reason: reason})
	if err != nil {
		return ExitAllow
	}
	fmt.Fprintln(out, string(payload))
	return ExitAllow
}

type userPromptDecision struct {
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type sessionStartOutput struct {
	HookSpecificOutput sessionStartContext `json:"hookSpecificOutput"`
}

type sessionStartContext struct {
	HookEventName     string `json:"hookEventName"`
	AdditionalContext string `json:"additionalContext"`
}

type denyOutput struct {
	HookSpecificOutput preToolUseDeny `json:"hookSpecificOutput"`
}

type preToolUseDeny struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// InstallFailClosedSignals makes termination signals fail closed. Go's default handler exits
// 128+signo (e.g. 130 for SIGINT), which Claude treats as "non-blocking error → proceed". We exit 2
// instead so an interrupted hook blocks rather than silently allows. Returns a stop function.
func InstallFailClosedSignals(errw io.Writer) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		s, ok := <-ch
		if !ok {
			return
		}
		fmt.Fprintf(errw, "corral: received %v, blocking (fail-closed)\n", s)
		os.Exit(ExitBlock)
	}()
	return func() { signal.Stop(ch); close(ch) }
}

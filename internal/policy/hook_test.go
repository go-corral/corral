package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func hookEngine(t *testing.T) (*Engine, string, string) {
	t.Helper()
	home, ssh := setupHomeWithSSH(t)
	return NewEngine(sshRule(t, home)), home, ssh
}

func runHookJSON(t *testing.T, eng *Engine, payload any) (int, string) {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var errBuf bytes.Buffer
	code := RunHook(eng, bytes.NewReader(data), &errBuf)
	return code, errBuf.String()
}

func TestRunHookAllows(t *testing.T) {
	eng, home, _ := hookEngine(t)
	code, msg := runHookJSON(t, eng, map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": filepath.Join(home, "readme.md")},
		"cwd":             home,
	})
	if code != ExitAllow {
		t.Fatalf("expected allow (0), got %d: %s", code, msg)
	}
	if msg != "" {
		t.Errorf("allow should be silent, got stderr: %q", msg)
	}
}

func TestRunHookBlocksSecret(t *testing.T) {
	eng, home, ssh := hookEngine(t)
	code, msg := runHookJSON(t, eng, map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": filepath.Join(ssh, "id_rsa")},
		"cwd":             home,
	})
	if code != ExitBlock {
		t.Fatalf("expected block (2), got %d: %s", code, msg)
	}
	if !strings.Contains(msg, "block-ssh") {
		t.Errorf("block message missing rule name: %q", msg)
	}
}

func TestRunHookEmptyStdinFailsClosed(t *testing.T) {
	eng, _, _ := hookEngine(t)
	var errBuf bytes.Buffer
	if code := RunHook(eng, strings.NewReader(""), &errBuf); code != ExitBlock {
		t.Fatalf("empty stdin must fail closed (2), got %d", code)
	}
}

func TestRunHookMalformedJSONFailsClosed(t *testing.T) {
	eng, _, _ := hookEngine(t)
	var errBuf bytes.Buffer
	if code := RunHook(eng, strings.NewReader("{not json"), &errBuf); code != ExitBlock {
		t.Fatalf("malformed JSON must fail closed (2), got %d", code)
	}
}

func TestRunHookOversizedFailsClosed(t *testing.T) {
	eng, _, _ := hookEngine(t)
	big := bytes.Repeat([]byte("a"), maxEventBytes+10)
	var errBuf bytes.Buffer
	if code := RunHook(eng, bytes.NewReader(big), &errBuf); code != ExitBlock {
		t.Fatalf("oversized input must fail closed (2), got %d", code)
	}
}

func TestRunHookNeverReturnsOtherCodes(t *testing.T) {
	// Property: across a spread of inputs, RunHook only ever returns 0 or 2.
	eng, home, ssh := hookEngine(t)
	inputs := [][]byte{
		[]byte(""),
		[]byte("garbage"),
		[]byte(`{}`),
		[]byte(`{"tool_name":"Read","tool_input":42}`),
		[]byte(`{"tool_name":"Read","tool_input":"x"}`),
		mustJSON(map[string]any{"tool_name": "Read", "tool_input": map[string]any{"file_path": filepath.Join(ssh, "id_rsa")}, "cwd": home}),
		mustJSON(map[string]any{"tool_name": "Read", "tool_input": map[string]any{"file_path": filepath.Join(home, "ok")}, "cwd": home}),
	}
	for i, in := range inputs {
		var errBuf bytes.Buffer
		code := RunHook(eng, bytes.NewReader(in), &errBuf)
		if code != ExitAllow && code != ExitBlock {
			t.Errorf("input %d returned %d (must be 0 or 2)", i, code)
		}
	}
}

func TestRunHookJSONDenyShape(t *testing.T) {
	eng, home, ssh := hookEngine(t)
	payload := mustJSON(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": filepath.Join(ssh, "id_rsa")},
		"cwd":             home,
	})
	var out, errBuf bytes.Buffer
	code := RunHookWith(eng, bytes.NewReader(payload), &out, &errBuf, PresentJSON)
	// JSON presentation carries the decision in stdout and exits 0.
	if code != ExitAllow {
		t.Fatalf("JSON deny should exit 0 (decision in stdout), got %d", code)
	}
	var parsed struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out.String())
	}
	if parsed.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("hookEventName = %q", parsed.HookSpecificOutput.HookEventName)
	}
	if parsed.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want deny", parsed.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(parsed.HookSpecificOutput.PermissionDecisionReason, "block-ssh") {
		t.Errorf("reason missing rule name: %q", parsed.HookSpecificOutput.PermissionDecisionReason)
	}
}

// failWriter is an io.Writer that always errors, to drive the stdout-write failure
// path. (errBuf in the test below uses a real buffer; only stdout fails.)
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("stdout gone") }

// A JSON-presentation Deny whose stdout write fails must not silently become an
// allow: the deny JSON never reached Claude, so the hook must fall back to exit 2.
func TestRunHookJSONDenyWriteFailureFailsClosed(t *testing.T) {
	eng, home, ssh := hookEngine(t)
	payload := mustJSON(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": filepath.Join(ssh, "id_rsa")},
		"cwd":             home,
	})
	var errBuf bytes.Buffer
	code := RunHookWith(eng, bytes.NewReader(payload), failWriter{}, &errBuf, PresentJSON)
	if code != ExitBlock {
		t.Fatalf("a Deny whose stdout write fails must fail closed (2), got %d", code)
	}
	if !strings.Contains(errBuf.String(), "block-ssh") {
		t.Errorf("fallback block must still name the rule on stderr: %q", errBuf.String())
	}
}

func TestRunHookJSONAllowIsSilent(t *testing.T) {
	eng, home, _ := hookEngine(t)
	payload := mustJSON(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"tool_input":      map[string]any{"file_path": filepath.Join(home, "ok.txt")},
		"cwd":             home,
	})
	var out, errBuf bytes.Buffer
	if code := RunHookWith(eng, bytes.NewReader(payload), &out, &errBuf, PresentJSON); code != ExitAllow {
		t.Fatalf("allow should exit 0, got %d", code)
	}
	if out.Len() != 0 {
		t.Errorf("allow must be silent on stdout, got %q", out.String())
	}
}

func TestRunHookJSONErrorStillFailsClosed(t *testing.T) {
	// Even in JSON presentation, a parse error must exit 2 (cannot trust stdout).
	eng, _, _ := hookEngine(t)
	var out, errBuf bytes.Buffer
	if code := RunHookWith(eng, strings.NewReader("{bad"), &out, &errBuf, PresentJSON); code != ExitBlock {
		t.Fatalf("parse error must fail closed (2) even in JSON mode, got %d", code)
	}
	if out.Len() != 0 {
		t.Errorf("error path must not write a fake allow/deny to stdout, got %q", out.String())
	}
}

func TestInstallFailClosedSignalsStops(t *testing.T) {
	// Just verify install/stop don't panic and the handler is removable.
	stop := InstallFailClosedSignals(os.Stderr)
	stop()
}

// TestSignalFailsClosed proves the critical property that a termination
// signal makes the hook exit 2 (block), not Go's default 128+signo (which Claude
// would treat as a non-blocking error and proceed — a fail-open bug). It uses the
// canonical helper-process idiom because the behavior under test calls os.Exit.
func TestSignalFailsClosed(t *testing.T) {
	if sig := os.Getenv("CORRAL_TEST_SIGNAL"); sig != "" {
		// Child: install the handler, signal ourselves with the requested signal, then
		// block. The handler goroutine must call os.Exit(ExitBlock).
		InstallFailClosedSignals(os.Stderr)
		n, _ := strconv.Atoi(sig)
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			os.Exit(99)
		}
		_ = p.Signal(syscall.Signal(n))
		select {} // block forever; the signal handler ends the process
	}

	// every termination signal the hook traps must fail closed (exit 2), never exit
	// 128+signo, which Claude treats as a non-blocking error → proceed (fail-open).
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestSignalFailsClosed", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), fmt.Sprintf("CORRAL_TEST_SIGNAL=%d", int(sig)))
			err := cmd.Run()

			var ee *exec.ExitError
			if !errors.As(err, &ee) {
				t.Fatalf("expected the helper to exit non-zero, got err=%v", err)
			}
			if got := ee.ExitCode(); got != ExitBlock {
				t.Fatalf("%v must fail closed with exit %d, got %d (128+signo would be fail-OPEN)", sig, ExitBlock, got)
			}
		})
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// errRule always fails — it drives the engine's rule-error path so we can prove the
// hook converts a propagated rule error into a fail-closed block (exit 2), never an
// allow. panicRule panics — it drives the blanket recover in RunHookWithAudit, proving
// a panic anywhere in evaluation becomes a block, not a crash with an arbitrary
// (Claude-treats-as-proceed) exit code.
type errRule struct{}

func (errRule) Name() string { return "always-errors" }
func (errRule) Evaluate(*HookEvent) (Decision, bool, error) {
	return Decision{}, false, errors.New("rule failure")
}

type panicRule struct{}

func (panicRule) Name() string                                { return "always-panics" }
func (panicRule) Evaluate(*HookEvent) (Decision, bool, error) { panic("rule boom") }

func TestRunHookRuleErrorFailsClosed(t *testing.T) {
	eng := NewEngine(errRule{})
	payload := mustJSON(map[string]any{"tool_name": "Read", "tool_input": map[string]any{"file_path": "/x"}, "cwd": "/"})
	var errBuf bytes.Buffer
	code := RunHook(eng, bytes.NewReader(payload), &errBuf)
	if code != ExitBlock {
		t.Fatalf("a propagated rule error must fail closed (block, %d), got %d", ExitBlock, code)
	}
	if !strings.Contains(errBuf.String(), "policy evaluation error") {
		t.Errorf("expected the engine-error block reason on stderr, got %q", errBuf.String())
	}
}

func TestRunHookPanicFailsClosed(t *testing.T) {
	eng := NewEngine(panicRule{})
	payload := mustJSON(map[string]any{"tool_name": "Read", "tool_input": map[string]any{"file_path": "/x"}, "cwd": "/"})
	var errBuf bytes.Buffer
	code := RunHook(eng, bytes.NewReader(payload), &errBuf)
	if code != ExitBlock {
		t.Fatalf("a panicking rule must fail closed (block, %d), got %d", ExitBlock, code)
	}
	if !strings.Contains(errBuf.String(), "fail-closed") {
		t.Errorf("expected the panic-recovery block reason on stderr, got %q", errBuf.String())
	}
}

// unknownActionRule matches and returns a verdict whose Action is neither Allow nor Deny
// — simulating a future Action constant (or a corrupted Decision) whose handling was never
// wired into the gate. The allow-list gate must treat it as a block, not silently allow.
type unknownActionRule struct{}

func (unknownActionRule) Name() string { return "unknown-action" }
func (unknownActionRule) Evaluate(*HookEvent) (Decision, bool, error) {
	return Decision{Action: Action(99), Rule: "unknown-action", Reason: "synthetic out-of-range action"}, true, nil
}

// TestRunHookUnknownActionFailsClosed pins the allow-list gate: a verdict that is not an
// explicit Allow must block (exit 2), and the audit log must record it as "deny" — never
// "allow" — so the log can never misreport a non-Allow verdict as a clean allow.
func TestRunHookUnknownActionFailsClosed(t *testing.T) {
	eng := NewEngine(unknownActionRule{})
	payload := mustJSON(map[string]any{"tool_name": "Read", "tool_input": map[string]any{"file_path": "/x"}, "cwd": "/"})

	var captured Decision
	aud := func(_ *HookEvent, dec Decision) { captured = dec }
	var out, errBuf bytes.Buffer
	code := RunHookWithAudit(eng, aud, bytes.NewReader(payload), &out, &errBuf, PresentExit2)

	if code != ExitBlock {
		t.Fatalf("an unrecognized (non-Allow) action must fail closed (block, %d), got %d", ExitBlock, code)
	}
	if got := captured.Action.String(); got != "deny" {
		t.Errorf("a non-Allow action must be logged with the fail-closed label %q, got %q", "deny", got)
	}
}

// An auditor that panics must not change the policy verdict: a panicking auditor is
// isolated by safeAudit's own recover, so an allow stays an allow and a deny stays a
// deny. (The audit callback is observability, never the verdict.)
func TestRunHookAuditPanicDoesNotChangeVerdict(t *testing.T) {
	eng, home, ssh := hookEngine(t)
	panicAud := func(*HookEvent, Decision) { panic("audit boom") }

	t.Run("allow survives auditor panic", func(t *testing.T) {
		payload := mustJSON(map[string]any{"tool_name": "Read", "tool_input": map[string]any{"file_path": filepath.Join(home, "ok.txt")}, "cwd": home})
		var out, errBuf bytes.Buffer
		code := RunHookWithAudit(eng, panicAud, bytes.NewReader(payload), &out, &errBuf, PresentExit2)
		if code != ExitAllow {
			t.Fatalf("auditor panic must not flip an allow, got %d", code)
		}
		if !strings.Contains(errBuf.String(), "audit logging panicked") {
			t.Errorf("auditor panic should be logged and swallowed, got %q", errBuf.String())
		}
	})

	t.Run("deny survives auditor panic", func(t *testing.T) {
		payload := mustJSON(map[string]any{"tool_name": "Read", "tool_input": map[string]any{"file_path": filepath.Join(ssh, "id_rsa")}, "cwd": home})
		var out, errBuf bytes.Buffer
		code := RunHookWithAudit(eng, panicAud, bytes.NewReader(payload), &out, &errBuf, PresentExit2)
		if code != ExitBlock {
			t.Fatalf("auditor panic must not flip a deny, got %d", code)
		}
	})
}

// fullEngine wires every rule type the production hook uses, so the property test
// below exercises each rule's decode/canonicalize error path end-to-end through the
// real harness.
func fullEngine(t *testing.T) (*Engine, string, string) {
	t.Helper()
	home, ssh := setupHomeWithSSH(t)
	return NewEngine(sshRule(t, home), &PathPatternRule{}, &SecretScanRule{}, &BashRule{}), home, ssh
}

// TestRunHookOnlyZeroOrTwo is the package's headline fail-closed invariant: across a
// broad spread of malformed, error-inducing, and valid inputs — fed through a full
// rule set — RunHook returns only ExitAllow (0) or ExitBlock (2). Any other code is a
// fail-open bug (Claude treats a non-0/2 exit as "proceed").
func TestRunHookOnlyZeroOrTwo(t *testing.T) {
	eng, home, ssh := fullEngine(t)
	valid := func(tool string, in map[string]any) []byte {
		return mustJSON(map[string]any{"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": in, "cwd": home})
	}
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte("")},
		{"garbage", []byte("@@@not-json@@@")},
		{"truncated", []byte(`{"tool_name":"Read","tool_input":`)},
		{"empty-object", []byte(`{}`)},
		{"tool_name-wrong-type", []byte(`{"tool_name":123}`)},
		{"read-input-number", []byte(`{"tool_name":"Read","tool_input":42,"cwd":"/"}`)},
		{"read-input-string", []byte(`{"tool_name":"Read","tool_input":"x","cwd":"/"}`)},
		{"read-input-array", []byte(`{"tool_name":"Read","tool_input":[1,2],"cwd":"/"}`)},
		{"write-input-array", []byte(`{"tool_name":"Write","tool_input":[1],"cwd":"/"}`)},
		{"bash-input-array", []byte(`{"tool_name":"Bash","tool_input":[1],"cwd":"/"}`)},
		{"glob-input-string", []byte(`{"tool_name":"Glob","tool_input":"nope","cwd":"/"}`)},
		{"multiedit-bad-edits", []byte(`{"tool_name":"MultiEdit","tool_input":{"edits":[123]},"cwd":"/"}`)},
		{"relative-path-no-cwd", []byte(`{"tool_name":"Read","tool_input":{"file_path":"rel/path"}}`)},
		{"oversized", bytes.Repeat([]byte("a"), maxEventBytes+1)},
		{"valid-allow", valid("Read", map[string]any{"file_path": filepath.Join(home, "ok.txt")})},
		{"valid-deny-secret", valid("Read", map[string]any{"file_path": filepath.Join(ssh, "id_rsa")})},
		{"valid-deny-bash", valid("Bash", map[string]any{"command": "rm -rf ~/.ssh"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var errBuf bytes.Buffer
			code := RunHook(eng, bytes.NewReader(tc.in), &errBuf)
			if code != ExitAllow && code != ExitBlock {
				t.Fatalf("input %q returned %d (must be %d or %d) — fail OPEN", tc.name, code, ExitAllow, ExitBlock)
			}
		})
	}
}

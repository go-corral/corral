package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// decodeUpdatedToolOutput pulls hookSpecificOutput.updatedToolOutput out of a PostToolUse
// replacement payload so a test can assert its shape — the property that decides whether
// Claude Code actually applies the replacement (an array for MCP, an object for Bash). A
// shape mismatch is silently ignored by Claude Code, so "present" is not enough to assert.
func decodeUpdatedToolOutput(t *testing.T, payload string) any {
	t.Helper()
	var top struct {
		HookSpecificOutput struct {
			UpdatedToolOutput any `json:"updatedToolOutput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(payload), &top); err != nil {
		t.Fatalf("replacement payload is not valid JSON: %v (%q)", err, payload)
	}
	return top.HookSpecificOutput.UpdatedToolOutput
}

// PostToolUse must replace secret-bearing or malformed responses; exit 2 cannot withhold a result
// already in context. The AWS-shaped fixture is assembled at runtime to keep it out of the source.

func TestRunPostToolUseSuppressesSecretResponse(t *testing.T) {
	key := "AKIA" + strings.Repeat("Q", 16)
	ev := `{"hook_event_name":"PostToolUse","tool_name":"mcp__db__get","tool_response":"the value is ` + key + `"}`
	var out, errw bytes.Buffer
	code := RunPostToolUseHook(0, 0, "", nil, strings.NewReader(ev), NewPostToolUseGate(&out), &errw)
	if code != ExitAllow {
		t.Fatalf("the replacement rides in the JSON with exit 0; got code %d", code)
	}
	if strings.Contains(out.String(), key) {
		t.Errorf("the withheld marker must not echo the secret value: %q", out.String())
	}
	// An MCP result is a content-block array; the replacement must mirror that shape or
	// Claude Code ignores it.
	if _, ok := decodeUpdatedToolOutput(t, out.String()).([]any); !ok {
		t.Errorf("an MCP replacement must be a content-block array; got %q", out.String())
	}
}

func TestRunPostToolUseAllowsCleanResponse(t *testing.T) {
	ev := `{"hook_event_name":"PostToolUse","tool_name":"mcp__docs__search","tool_response":[{"type":"text","text":"nothing sensitive here"}]}`
	var out, errw bytes.Buffer
	code := RunPostToolUseHook(0, 0, "", nil, strings.NewReader(ev), NewPostToolUseGate(&out), &errw)
	if code != ExitAllow {
		t.Fatalf("a clean response must allow; got %d", code)
	}
	if out.Len() != 0 {
		t.Errorf("a clean response must produce no output (no suppression); got %q", out.String())
	}
}

// Ingress fail-closed: an unparseable event must replace the response (emit
// updatedToolOutput), never exit 2 (which would not withhold it). Empty input → parse
// error → replace.
func TestRunPostToolUseSuppressesOnError(t *testing.T) {
	var out, errw bytes.Buffer
	code := RunPostToolUseHook(0, 0, "", nil, strings.NewReader(""), NewPostToolUseGate(&out), &errw)
	if code != ExitAllow {
		t.Fatalf("the error path returns ExitAllow with the replacement in JSON; got %d", code)
	}
	if !strings.Contains(out.String(), `"updatedToolOutput"`) {
		t.Errorf("the error path must withhold via updatedToolOutput; got %q", out.String())
	}
}

// A valid event whose response is null/absent: nothing to scan, allow with no output.
func TestRunPostToolUseAllowsEmptyResponse(t *testing.T) {
	ev := `{"hook_event_name":"PostToolUse","tool_name":"mcp__noop__ping","tool_response":null}`
	var out, errw bytes.Buffer
	code := RunPostToolUseHook(0, 0, "", nil, strings.NewReader(ev), NewPostToolUseGate(&out), &errw)
	if code != ExitAllow || out.Len() != 0 {
		t.Errorf("an empty response must allow with no output; code=%d out=%q", code, out.String())
	}
}

// Bash response with a secret in stdout: withheld like MCP responses.
//
// A Bash result is a {stdout,stderr,...} object, not a content-block array. An
// array-shaped replacement is silently ignored by Claude Code, which then passes the raw
// secret-bearing stdout to the model while the audit log still records "replaced": a
// fail-open. This asserts the replacement is an object carrying stdout, and that no
// original field survives.
func TestRunPostToolUseSuppressesBashSecretInStdout(t *testing.T) {
	token := "ghp_" + strings.Repeat("0123456789abcdef", 3) // 48 chars of token after prefix (>36 required)
	ev := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"token=` + token + `","stderr":"secret too: ` + token + `","interrupted":false,"isImage":false}}`
	var out, errw bytes.Buffer
	code := RunPostToolUseHook(0, 0, "", nil, strings.NewReader(ev), NewPostToolUseGate(&out), &errw)
	if code != ExitAllow {
		t.Fatalf("the replacement rides in the JSON with exit 0; got code %d", code)
	}
	if strings.Contains(out.String(), token) {
		t.Errorf("the withheld marker must not echo the secret value (from stdout OR stderr): %q", out.String())
	}
	upd := decodeUpdatedToolOutput(t, out.String())
	obj, ok := upd.(map[string]any)
	if !ok {
		t.Fatalf("a Bash replacement must be an OBJECT (not a content-block array) or Claude Code ignores it; got %T: %q", upd, out.String())
	}
	stdout, ok := obj["stdout"].(string)
	if !ok || !strings.Contains(stdout, "withheld") {
		t.Errorf("the Bash replacement must carry the withheld marker in stdout; got %v", obj)
	}
	// The non-text fields of the original shape are preserved so the result stays valid.
	if _, ok := obj["interrupted"]; !ok {
		t.Errorf("the Bash replacement should preserve the original result's non-text fields; got %v", obj)
	}
}

// updatedToolOutputFor must pick a replacement shape that matches the original tool result:
// MCP → content-block array; Bash → object. Emitting the wrong shape is a fail-open:
// Claude Code silently ignores a mismatched replacement.
func TestUpdatedToolOutputForShape(t *testing.T) {
	const m = "[withheld]"

	// MCP by tool name → array, regardless of (absent) original bytes.
	if _, ok := updatedToolOutputFor("mcp__db__get", nil, m).([]contentText); !ok {
		t.Errorf("mcp__* must yield a content-block array")
	}
	// MCP-shaped original bytes (array) with unknown tool name → array.
	if _, ok := updatedToolOutputFor("", []byte(`[{"type":"text","text":"x"}]`), m).([]contentText); !ok {
		t.Errorf("an array original must yield a content-block array")
	}
	// Bash object original → object that overwrites text fields but keeps the rest.
	got := updatedToolOutputFor("Bash", []byte(`{"stdout":"s","stderr":"e","interrupted":false}`), m)
	obj, ok := got.(map[string]json.RawMessage)
	if !ok {
		t.Fatalf("a Bash object original must yield an object; got %T", got)
	}
	if string(obj["stdout"]) != `"`+m+`"` {
		t.Errorf("stdout must be the marker; got %s", obj["stdout"])
	}
	if string(obj["stderr"]) != `""` {
		t.Errorf("stderr must be blanked; got %s", obj["stderr"])
	}
	if _, ok := obj["interrupted"]; !ok {
		t.Errorf("non-text fields must be preserved")
	}
	// Unknown tool name + no/garbled original → safe Bash default object carrying the marker.
	for _, in := range [][]byte{nil, []byte("not json"), []byte(`{"weird":1}`)} {
		def, ok := updatedToolOutputFor("", in, m).(map[string]any)
		if !ok {
			t.Fatalf("the fallback must be a Bash object; got %T for input %q", updatedToolOutputFor("", in, m), in)
		}
		if def["stdout"] != m {
			t.Errorf("the fallback object must carry the marker in stdout; got %v", def)
		}
	}
}

// The gate must write exactly one replacement per process. Every fail-closed path
// (the scan's errors, a recovered panic, the CLI prologue's recover, and the signal
// handler) reaches for stdout, and the signal handler does so from another goroutine.
// Two interleaved writes are invalid JSON, which Claude Code ignores — handing the model
// the unscanned response, i.e. a fail-open introduced by the fail-closed machinery.
func TestPostToolUseGateWritesOnce(t *testing.T) {
	var out bytes.Buffer
	g := NewPostToolUseGate(&out)

	first := g.Replace("[corral] withheld — first")
	second := g.Replace("[corral] withheld — second")

	if first != ExitAllow || second != ExitAllow {
		t.Errorf("both calls must report the first write's code; got %d and %d", first, second)
	}
	if n := strings.Count(strings.TrimSpace(out.String()), "\n"); n != 0 {
		t.Fatalf("the gate must emit exactly one line; got %d extra newlines: %q", n, out.String())
	}
	if !strings.Contains(out.String(), "first") || strings.Contains(out.String(), "second") {
		t.Errorf("the FIRST marker must win and the second must not be written; got %q", out.String())
	}
	// The single line must still be valid, appliable JSON.
	decodeUpdatedToolOutput(t, out.String())
}

// Same property under concurrency — this is the race the mutex exists for. Run with -race.
func TestPostToolUseGateConcurrentReplaceWritesOnce(t *testing.T) {
	var out bytes.Buffer
	g := NewPostToolUseGate(&out)

	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			g.Replace(fmt.Sprintf("[corral] withheld — %d", i))
		}(i)
	}
	wg.Wait()

	if got := strings.TrimSpace(out.String()); strings.Count(got, "\n") != 0 {
		t.Fatalf("concurrent Replace must still emit one line; got %q", got)
	}
	decodeUpdatedToolOutput(t, out.String()) // must be parseable, not interleaved
}

// Observe must not let a best-effort probe erase a better-known value: a later empty
// tool name or response keeps whatever the gate already learned, so the replacement shape
// stays correct.
func TestPostToolUseGateObserveKeepsKnownShape(t *testing.T) {
	var out bytes.Buffer
	g := NewPostToolUseGate(&out)
	g.Observe("mcp__db__get", nil)
	g.Observe("", nil) // must not clear it
	g.Replace("[corral] withheld")

	if _, ok := decodeUpdatedToolOutput(t, out.String()).([]any); !ok {
		t.Errorf("the known mcp__* name must still drive the content-array shape; got %q", out.String())
	}
}

// A scalar-string tool result gets a string replacement. Emitting the Bash object for a
// string original is a shape mismatch, silently ignored and therefore fail-open,
// so the withhold would not apply at all.
func TestUpdatedToolOutputForScalarStringShape(t *testing.T) {
	const m = "[withheld]"
	got := updatedToolOutputFor("Grep", []byte(`"matched line one\nmatched line two"`), m)
	if s, ok := got.(string); !ok || s != m {
		t.Errorf("a scalar-string original must yield the marker string; got %T %v", got, got)
	}
}

// TestPostToolUseSignalWithholds proves the property the PreToolUse handler cannot provide
// here. For PreToolUse a signal can just exit 2, because exit 2 means "block". PostToolUse
// has no blocking exit code at all: Go's default 128+signo and exit 2 alike are treated as a
// non-blocking hook error, so both let the original unscanned response reach the model. The
// handler must therefore write the replacement. Without it a SIGTERM produces exit 143
// with empty stdout — a reproducible fail-open. Helper-process idiom because os.Exit is
// involved.
func TestPostToolUseSignalWithholds(t *testing.T) {
	if sig := os.Getenv("CORRAL_TEST_POSTTOOLUSE_SIGNAL"); sig != "" {
		// Child: a gate over the real stdout, the handler installed, then signal ourselves
		// and block. The handler must write the replacement and exit.
		gate := NewPostToolUseGate(os.Stdout)
		gate.Observe("Bash", []byte(`{"stdout":"pretend output","stderr":""}`))
		InstallPostToolUseSignals(gate, io.Discard)
		n, _ := strconv.Atoi(sig)
		p, err := os.FindProcess(os.Getpid())
		if err != nil {
			os.Exit(99)
		}
		_ = p.Signal(syscall.Signal(n))
		select {} // block forever; the handler ends the process
	}

	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=TestPostToolUseSignalWithholds", "-test.timeout=30s")
			cmd.Env = append(os.Environ(), fmt.Sprintf("CORRAL_TEST_POSTTOOLUSE_SIGNAL=%d", int(sig)))
			stdout, err := cmd.Output()

			// Exit 0 is correct here: the withhold rides in the JSON, exactly as on the
			// normal replacement path. A non-zero status would be read as a hook error and
			// the response would proceed.
			if err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					t.Fatalf("%v must exit %d after withholding, got %d (128+signo or 2 would both fail OPEN here)", sig, ExitAllow, ee.ExitCode())
				}
				t.Fatalf("helper failed: %v", err)
			}

			line := replacementLine(string(stdout))
			if line == "" {
				t.Fatalf("%v must WRITE a replacement — an empty stdout means the model got the unscanned response; stdout=%q", sig, stdout)
			}
			upd := decodeUpdatedToolOutput(t, line)
			obj, ok := upd.(map[string]any)
			if !ok {
				t.Fatalf("the observed Bash shape must be preserved on the signal path; got %T", upd)
			}
			if s, _ := obj["stdout"].(string); !strings.Contains(s, "withheld") {
				t.Errorf("the replacement must carry a withheld marker; got %v", obj)
			}
		})
	}
}

// replacementLine returns the PostToolUse replacement JSON line out of captured stdout,
// ignoring any surrounding test-framework noise.
func replacementLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, `"hookSpecificOutput"`) {
			return line
		}
	}
	return ""
}

// Bash response with clean stdout: allowed through.
func TestRunPostToolUseAllowsBashCleanResponse(t *testing.T) {
	ev := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":{"stdout":"hello world","stderr":"","exit_code":0}}`
	var out, errw bytes.Buffer
	code := RunPostToolUseHook(0, 0, "", nil, strings.NewReader(ev), NewPostToolUseGate(&out), &errw)
	if code != ExitAllow {
		t.Fatalf("a clean Bash response must allow; got %d", code)
	}
	if out.Len() != 0 {
		t.Errorf("a clean Bash response must produce no output (no suppression); got %q", out.String())
	}
}

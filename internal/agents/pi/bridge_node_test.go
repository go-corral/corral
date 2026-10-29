package pi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sidecar"
)

// nodeBinary returns the node binary. CI must run the node tests, so a missing node fails there.
func nodeBinary(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err == nil {
		return node
	}
	if os.Getenv("CI") != "" {
		t.Fatal("node not installed; CI must run the pi node tests")
	}
	t.Skip("node not installed; skipping pi node test")
	return ""
}

func sourceDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve this test's path")
	}
	return filepath.Dir(file)
}

// runBridgeHarness runs testdata/bridge_harness.mjs against the bridge with the sidecar socket set.
func runBridgeHarness(t *testing.T, socket string, args ...string) ([]byte, error) {
	t.Helper()
	node := nodeBinary(t)
	dir := sourceDir(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, append([]string{filepath.Join(dir, "testdata", "bridge_harness.mjs"), filepath.Join(dir, "pi-bridge.ts")}, args...)...)
	cmd.Env = append(os.Environ(), sandbox.SidecarSocketEnvVar+"="+socket)
	return cmd.CombinedOutput()
}

func serve(t *testing.T, h sidecar.Handler) string {
	t.Helper()
	s, err := sidecar.Start(h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s.Path()
}

// scriptedHandler answers by request type and by a marker in the event: /echo returns the
// event in the reason, the marker text, or the prompt block reason, /deny denies, /error
// answers with an error, and /garbage answers a prompt with unreadable output.
func scriptedHandler() sidecar.Handler {
	return func(req sidecar.Request, payload []byte, _ policy.FS) sidecar.Response {
		ev := string(payload)
		switch {
		case req.Type == "session-start":
			if len(payload) != 0 || req.Decision != "" {
				return sidecar.Response{Error: fmt.Sprintf("session-start request %+v with payload %q", req, payload)}
			}
			return sidecar.Response{Stdout: `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"NOTE"}}` + "\n"}
		case req.Type == "pre-tool-use" && req.Decision != "exit2":
			return sidecar.Response{Error: "pre-tool-use without exit2"}
		case strings.Contains(ev, "/error"):
			return sidecar.Response{Error: "scripted error"}
		}
		echo := strings.Contains(ev, "/echo")
		deny := strings.Contains(ev, "/deny")
		switch req.Type {
		case "pre-tool-use":
			if echo {
				return sidecar.Response{Code: 2, Stderr: ev + "\n"}
			}
			if deny {
				return sidecar.Response{Code: 2, Stderr: "corral: DENIED\n"}
			}
		case "post-tool-use":
			if echo {
				out, _ := json.Marshal(map[string]any{"hookSpecificOutput": map[string]any{"updatedToolOutput": []any{map[string]string{"type": "text", "text": ev}}}})
				return sidecar.Response{Stdout: string(out) + "\n"}
			}
			if deny {
				return sidecar.Response{Code: 2}
			}
		case "user-prompt-submit":
			if echo {
				out, _ := json.Marshal(map[string]string{"decision": "block", "reason": ev})
				return sidecar.Response{Stdout: string(out) + "\n"}
			}
			if deny {
				return sidecar.Response{Code: 2}
			}
			if strings.Contains(ev, "/garbage") {
				return sidecar.Response{Stdout: "not json\n"}
			}
		default:
			return sidecar.Response{Error: "unknown request type " + req.Type}
		}
		return sidecar.Response{}
	}
}

// TestPiBridgeNodeHarness exercises the embedded pi bridge against a real sidecar server: the
// tool name/key mapping, the sidecar's answers, and pi's asymmetric fail-closed rules (tool_call
// throws to block; tool_result/user_bash return a withhold/deny, never throw). The pi->bridge
// direction against a real pi binary needs a configured model and is verified by hand.
func TestPiBridgeNodeHarness(t *testing.T) {
	out, err := runBridgeHarness(t, serve(t, scriptedHandler()), "events")
	if err != nil {
		t.Fatalf("pi bridge harness failed: %v\n%s", err, out)
	}
}

// harnessToolCall runs one tool_call through the bridge and returns the harness's report.
func harnessToolCall(t *testing.T, socket, toolName string, input map[string]any) (result map[string]any, threw string) {
	t.Helper()
	arg, err := json.Marshal(map[string]any{"toolName": toolName, "input": input})
	if err != nil {
		t.Fatal(err)
	}
	out, err := runBridgeHarness(t, socket, "tool_call", string(arg))
	if err != nil {
		t.Fatalf("pi bridge harness failed: %v\n%s", err, out)
	}
	var rep struct {
		Result map[string]any `json:"result"`
		Threw  string         `json:"threw"`
	}
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatalf("harness output %q: %v", out, err)
	}
	return rep.Result, rep.Threw
}

func errKind(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "not-exist"
	case errors.Is(err, fs.ErrPermission):
		return "permission"
	}
	return ""
}

type fsAnswer struct {
	Path    string
	Data    []byte
	Regular bool
	Err     bool
	Kind    string
}

type fsQuestion struct {
	op    string
	path  string
	limit int64
	// want pins the kind and the error, so the case cannot pass with two wrong answers.
	wantErr  bool
	wantKind string
}

func ask(fsys policy.FS, q fsQuestion) fsAnswer {
	var a fsAnswer
	var err error
	if q.op == "eval-symlinks" {
		a.Path, err = fsys.EvalSymlinks(q.path)
	} else {
		a.Data, a.Regular, err = fsys.ReadRegular(q.path, q.limit)
	}
	a.Err, a.Kind = err != nil, errKind(err)
	return a
}

// TestPiBridgeFilesystemParity has a sidecar handler ask the bridge the filesystem questions of
// a fixture tree and compare each answer with policy.OSFS, the filesystem of the hook.
func TestPiBridgeFilesystemParity(t *testing.T) {
	dir := t.TempDir()
	p := func(rel string) string { return filepath.Join(dir, rel) }
	big := bytes.Repeat([]byte("0123456789abcdef"), 200<<10/16)
	for _, f := range []struct{ name, data string }{{"file", "0123456789"}, {"big", string(big)}, {"sub/inner", "in"}} {
		if err := os.MkdirAll(filepath.Dir(p(f.name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p(f.name), []byte(f.data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"l1": "l2", "l2": "l3", "l3": "file",
		"dlink":    "sub",
		"loopA":    "loopB",
		"loopB":    "loopA",
		"dangling": "missing",
	} {
		if err := os.Symlink(target, p(link)); err != nil {
			t.Fatal(err)
		}
	}
	if err := syscall.Mkfifo(p("fifo"), 0o644); err != nil {
		t.Fatal(err)
	}

	questions := []fsQuestion{}
	both := func(path string, limit int64, wantErr bool, wantKind string) {
		questions = append(questions,
			fsQuestion{op: "eval-symlinks", path: path, wantErr: wantErr, wantKind: wantKind},
			fsQuestion{op: "read-regular", path: path, limit: limit, wantErr: wantErr, wantKind: wantKind})
	}
	both(p("file"), 1<<20, false, "")
	both(p("l1"), 1<<20, false, "")
	both(p("dlink/inner"), 1<<20, false, "")
	both(p("big"), 150<<10, false, "")
	both(p("fifo"), 1<<20, false, "")
	both(p("sub/missing"), 1<<20, true, "not-exist")
	questions = append(questions,
		fsQuestion{op: "eval-symlinks", path: p("loopA"), wantErr: true},
		fsQuestion{op: "read-regular", path: p("loopA"), limit: 1 << 20},
		fsQuestion{op: "eval-symlinks", path: p("dangling"), wantErr: true, wantKind: "not-exist"},
		fsQuestion{op: "read-regular", path: p("dangling"), limit: 1 << 20},
		fsQuestion{op: "eval-symlinks", path: p("file/below"), wantErr: true},
		fsQuestion{op: "read-regular", path: p("file/below"), limit: 1 << 20, wantErr: true},
	)
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping the unreadable directory case")
	} else {
		if err := os.MkdirAll(p("locked"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p("locked/f"), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p("locked"), 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p("locked"), 0o755) })
		both(p("locked/f"), 1<<20, true, "permission")
	}

	var asked atomic.Bool
	socket := serve(t, func(_ sidecar.Request, _ []byte, client policy.FS) sidecar.Response {
		asked.Store(true)
		for _, q := range questions {
			got, want := ask(client, q), ask(policy.OSFS{}, q)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: bridge %+v, hook %+v", q.op, q.path, got, want)
			}
			if want.Err != q.wantErr || want.Kind != q.wantKind {
				t.Errorf("%s %s: hook %+v, want err %v kind %q", q.op, q.path, want, q.wantErr, q.wantKind)
			}
		}
		return sidecar.Response{}
	})

	if result, threw := harnessToolCall(t, socket, "read", map[string]any{"path": "/x"}); threw != "" || result != nil {
		t.Fatalf("tool call: threw %q, result %v", threw, result)
	}
	if !asked.Load() {
		t.Fatal("the sidecar handler never ran")
	}
}

// TestPiBridgeParityProtectedSymlink writes through a symlink that a process in the sandbox
// created to a protected file, as with /tmp/e. The policy resolves the link through the bridge.
func TestPiBridgeParityProtectedSymlink(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "vault", "secret")
	if err := os.MkdirAll(filepath.Dir(secret), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "e")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	socket := serve(t, func(req sidecar.Request, payload []byte, client policy.FS) sidecar.Response {
		root, err := policy.CanonicalizeRootIn(client, secret, "")
		if err != nil {
			return sidecar.Response{Error: err.Error()}
		}
		eng := policy.NewEngine(&policy.BlockedPathRule{Roots: []string{root}})
		var stdout, stderr bytes.Buffer
		code := policy.RunHookWithAudit(eng, nil, client, bytes.NewReader(payload), &stdout, &stderr, policy.PresentExit2)
		return sidecar.Response{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
	})

	result, threw := harnessToolCall(t, socket, "write", map[string]any{"path": link, "content": "x"})
	reason, _ := result["reason"].(string)
	if threw != "" || result["block"] != true || !strings.Contains(reason, "[hook:blocked-path]") {
		t.Fatalf("write through %s: want a blocked-path block, got threw %q, result %v", link, threw, result)
	}
	result, threw = harnessToolCall(t, socket, "write", map[string]any{"path": filepath.Join(dir, "other"), "content": "x"})
	if threw != "" || result != nil {
		t.Fatalf("write to an unprotected path: want allow, got threw %q, result %v", threw, result)
	}
}

// TestPiBridgeOversizedEvent sends a tool_call over the event cap. The bridge sends
// MaxEventBytes+1 bytes, so the policy sees the overflow.
func TestPiBridgeOversizedEvent(t *testing.T) {
	socket := serve(t, func(_ sidecar.Request, payload []byte, _ policy.FS) sidecar.Response {
		if len(payload) != policy.MaxEventBytes+1 {
			return sidecar.Response{Error: fmt.Sprintf("got %d payload bytes, want %d", len(payload), policy.MaxEventBytes+1)}
		}
		return sidecar.Response{}
	})
	if out, err := runBridgeHarness(t, socket, "oversize"); err != nil {
		t.Fatalf("pi bridge harness failed: %v\n%s", err, out)
	}
}

// TestPiPresenceNodeHarness exercises the presence backstop's JS: silent inside corral
// (CORRAL_SANDBOX set), warns once with the removal hint outside corral.
func TestPiPresenceNodeHarness(t *testing.T) {
	node := nodeBinary(t)
	dir := sourceDir(t)
	presence := filepath.Join(dir, "pi-presence.ts")
	harness := filepath.Join(dir, "testdata", "presence_harness.mjs")

	out, err := exec.Command(node, harness, presence).CombinedOutput()
	if err != nil {
		t.Fatalf("pi presence harness failed: %v\n%s", err, out)
	}
}

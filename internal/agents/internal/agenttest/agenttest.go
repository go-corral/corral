// Package agenttest holds test helpers for agent extensions that talk to the corral sidecar.
package agenttest

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
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sidecar"
)

// RunNode runs node with args and env added to the test's environment, and returns the
// combined output. It fails the test when node fails. CI must run the node tests, so a missing
// node fails there and skips the test elsewhere.
func RunNode(t *testing.T, env []string, args ...string) []byte {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("node not installed; CI must run the node tests")
		}
		t.Skip("node not installed; skipping node test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node %v failed: %v\n%s", args, err, out)
	}
	return out
}

// Serve starts a sidecar server with h for the test and returns its socket path.
func Serve(t *testing.T, h sidecar.Handler) string {
	t.Helper()
	s, err := sidecar.Start(h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s.Path()
}

// ServeScripted serves a sidecar that answers by request type and by a marker in the tool input
// or the prompt of the event:
// /echo returns the event as the pre-tool-use deny reason, the post-tool-use output text, or the
// prompt block reason, /deny denies, /error answers with an error, /hang answers when the test
// ends, /garbage answers a prompt with unreadable output, and a pre-tool-use /log denies with the
// JSON list of the events received since the last /log.
func ServeScripted(t *testing.T) string {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var mu sync.Mutex
	var received []json.RawMessage
	return Serve(t, func(req sidecar.Request, payload []byte, _ policy.FS) sidecar.Response {
		ev := string(payload)
		var fields struct {
			ToolInput json.RawMessage `json:"tool_input"`
			Prompt    string          `json:"prompt"`
		}
		_ = json.Unmarshal(payload, &fields)
		marked := string(fields.ToolInput) + "\n" + fields.Prompt
		switch {
		case req.Type == "session-start":
			if len(payload) != 0 || req.Decision != "" {
				return sidecar.Response{Error: fmt.Sprintf("session-start request %+v with payload %q", req, payload)}
			}
			return sidecar.Response{Stdout: `{"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"NOTE"}}` + "\n"}
		case req.Type == "pre-tool-use" && req.Decision != "exit2":
			return sidecar.Response{Error: "pre-tool-use without exit2"}
		case strings.Contains(marked, "/error"):
			return sidecar.Response{Error: "scripted error"}
		case strings.Contains(marked, "/hang"):
			<-release
			return sidecar.Response{}
		case req.Type == "pre-tool-use" && strings.Contains(marked, "/log"):
			mu.Lock()
			out, err := json.Marshal(append([]json.RawMessage{}, received...))
			received = nil
			mu.Unlock()
			if err != nil {
				return sidecar.Response{Error: err.Error()}
			}
			return sidecar.Response{Code: 2, Stderr: string(out) + "\n"}
		}
		mu.Lock()
		received = append(received, json.RawMessage(bytes.Clone(payload)))
		mu.Unlock()
		echo := strings.Contains(marked, "/echo")
		deny := strings.Contains(marked, "/deny")
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
			if strings.Contains(marked, "/garbage") {
				return sidecar.Response{Stdout: "not json\n"}
			}
		default:
			return sidecar.Response{Error: "unknown request type " + req.Type}
		}
		return sidecar.Response{}
	})
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

// FilesystemParity serves a sidecar whose handler asks the agent the filesystem questions of a
// fixture tree and compares each answer with policy.OSFS, the filesystem of the hook. call must
// send one allowed tool call to socket through the agent's sidecar client.
func FilesystemParity(t *testing.T, call func(socket string)) {
	t.Helper()
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
	call(Serve(t, func(_ sidecar.Request, _ []byte, client policy.FS) sidecar.Response {
		asked.Store(true)
		for _, q := range questions {
			got, want := ask(client, q), ask(policy.OSFS{}, q)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: agent %+v, hook %+v", q.op, q.path, got, want)
			}
			if want.Err != q.wantErr || want.Kind != q.wantKind {
				t.Errorf("%s %s: hook %+v, want err %v kind %q", q.op, q.path, want, q.wantErr, q.wantKind)
			}
		}
		return sidecar.Response{}
	}))
	if !asked.Load() {
		t.Fatal("the sidecar handler never ran")
	}
}

// ProtectedSymlink serves a sidecar that runs the hook with a blocked-path rule on a secret file,
// and resolves the rule's root through the agent. It returns the socket, a symlink to the secret
// (like one that a process in the sandbox creates), and an unprotected path.
func ProtectedSymlink(t *testing.T) (socket, link, other string) {
	t.Helper()
	dir := t.TempDir()
	secret := filepath.Join(dir, "vault", "secret")
	if err := os.MkdirAll(filepath.Dir(secret), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("s"), 0o600); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(dir, "e")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	socket = Serve(t, func(_ sidecar.Request, payload []byte, client policy.FS) sidecar.Response {
		root, err := policy.CanonicalizeRootIn(client, secret, "")
		if err != nil {
			return sidecar.Response{Error: err.Error()}
		}
		eng := policy.NewEngine(&policy.BlockedPathRule{Roots: []string{root}})
		var stdout, stderr bytes.Buffer
		code := policy.RunHookWithAudit(eng, nil, client, bytes.NewReader(payload), &stdout, &stderr, policy.PresentExit2)
		return sidecar.Response{Code: code, Stdout: stdout.String(), Stderr: stderr.String()}
	})
	return socket, link, filepath.Join(dir, "other")
}

// AssertContains reports each of wants that src does not contain.
func AssertContains(t *testing.T, name, src string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(src, want) {
			t.Errorf("%s missing %q", name, want)
		}
	}
}

// AssertFailureTexts checks that src holds a copy of corral's fail-closed texts, which an agent
// extension needs when it cannot ask corral for them.
func AssertFailureTexts(t *testing.T, name, src string) {
	t.Helper()
	for _, text := range []string{policy.FailClosed("\x00"), policy.Unscanned("\x00")} {
		AssertContains(t, name, src, strings.Split(text, "\x00")...)
	}
}

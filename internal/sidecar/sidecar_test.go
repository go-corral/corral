package sidecar

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-corral/corral/internal/policy"
)

// fakeFS answers with fixed results.
type fakeFS struct {
	resolved string
	data     []byte
	err      error
}

func (f fakeFS) EvalSymlinks(string) (string, error) { return f.resolved, f.err }

func (f fakeFS) ReadRegular(string, int64) ([]byte, bool, error) {
	return f.data, f.err == nil, f.err
}

// dialRaw sends a request header with an empty payload and returns the connection.
func dialRaw(t *testing.T, s *Server, header string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.Dial("unix", s.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(header)); err != nil {
		t.Fatal(err)
	}
	return conn, bufio.NewReader(conn)
}

// readMessage reads one server line.
func readMessage(t *testing.T, r *bufio.Reader) message {
	t.Helper()
	line, err := r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read server line: %v", err)
	}
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		t.Fatalf("malformed server line %q: %v", line, err)
	}
	return m
}

func start(t *testing.T, h Handler) *Server {
	t.Helper()
	s, err := Start(h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestRoundTrip(t *testing.T) {
	type got struct {
		req     Request
		payload []byte
	}
	gotc := make(chan got, 1)
	s := start(t, func(req Request, payload []byte, _ policy.FS) Response {
		gotc <- got{req, payload}
		return Response{Code: 2, Stdout: "out", Stderr: "err"}
	})

	fi, err := os.Stat(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", fi.Mode().Perm())
	}
	if filepath.Dir(s.Path()) != s.Dir() {
		t.Errorf("socket %q is not inside %q", s.Path(), s.Dir())
	}

	req := Request{Type: "pre-tool-use", Decision: "json"}
	payload := []byte("{\"a\":1}\nnot json\x00\xff")
	resp := Call(s.Path(), req, payload, nil)
	if want := (Response{Code: 2, Stdout: "out", Stderr: "err"}); resp != want {
		t.Errorf("answer = %+v, want %+v", resp, want)
	}
	g := <-gotc
	if g.req != req {
		t.Errorf("request = %+v, want %+v", g.req, req)
	}
	if !bytes.Equal(g.payload, payload) {
		t.Errorf("payload = %q, want %q", g.payload, payload)
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.Dir()); !os.IsNotExist(err) {
		t.Errorf("Close left %s behind: %v", s.Dir(), err)
	}
}

func TestOversizedPayloadReachesHandler(t *testing.T) {
	got := make(chan int, 1)
	s := start(t, func(_ Request, payload []byte, _ policy.FS) Response {
		got <- len(payload)
		return Response{}
	})
	if resp := Call(s.Path(), Request{Type: "pre-tool-use"}, make([]byte, policy.MaxEventBytes+1), nil); resp.Error != "" {
		t.Fatalf("answer = %+v, want no error", resp)
	}
	if n := <-got; n != policy.MaxEventBytes+1 {
		t.Errorf("handler got %d bytes, want %d", n, policy.MaxEventBytes+1)
	}
}

func TestStartRejectsLongSocketPath(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), strings.Repeat("d", 120))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmp)
	if s, err := Start(func(Request, []byte, policy.FS) Response { return Response{} }); err == nil {
		_ = s.Close()
		t.Fatal("Start succeeded with a socket path over the unix socket limit")
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("Start left %d entries in %s", len(left), tmp)
	}
}

func TestCallMissingSocket(t *testing.T) {
	resp := Call(filepath.Join(t.TempDir(), "sock"), Request{Type: "pre-tool-use"}, nil, nil)
	if resp.Error == "" {
		t.Errorf("answer = %+v, want an error", resp)
	}
}

func TestHandlerPanic(t *testing.T) {
	s := start(t, func(req Request, _ []byte, _ policy.FS) Response {
		if req.Type == "boom" {
			panic("boom")
		}
		return Response{Stdout: "ok"}
	})
	if resp := Call(s.Path(), Request{Type: "boom"}, nil, nil); resp.Error == "" {
		t.Errorf("panicking handler: answer = %+v, want an error", resp)
	}
	if resp := Call(s.Path(), Request{Type: "fine"}, nil, nil); resp != (Response{Stdout: "ok"}) {
		t.Errorf("request after a panic: answer = %+v, want stdout ok", resp)
	}
}

func TestConcurrentRequests(t *testing.T) {
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	s := start(t, func(req Request, _ []byte, _ policy.FS) Response {
		arrived <- struct{}{}
		<-release
		return Response{Stdout: req.Type}
	})
	answers := make(chan Response, 2)
	for _, typ := range []string{"a", "b"} {
		go func() { answers <- Call(s.Path(), Request{Type: typ}, nil, nil) }()
	}
	for range 2 {
		select {
		case <-arrived:
		case <-time.After(5 * time.Second):
			t.Fatal("the second request was not served while the first one was pending")
		}
	}
	close(release)
	got := map[string]bool{}
	for range 2 {
		resp := <-answers
		got[resp.Stdout] = true
	}
	if !got["a"] || !got["b"] {
		t.Errorf("answers = %v, want one for a and one for b", got)
	}
}

func TestCallTimeout(t *testing.T) {
	old := callTimeout
	callTimeout = 100 * time.Millisecond
	t.Cleanup(func() { callTimeout = old })

	release := make(chan struct{})
	s := start(t, func(Request, []byte, policy.FS) Response {
		<-release
		return Response{}
	})
	t.Cleanup(func() { close(release) })

	begin := time.Now()
	resp := Call(s.Path(), Request{Type: "pre-tool-use"}, nil, nil)
	if resp.Error == "" {
		t.Errorf("answer = %+v, want a timeout error", resp)
	}
	if d := time.Since(begin); d > 2*time.Second {
		t.Errorf("Call returned after %v, want about %v", d, callTimeout)
	}
}

func TestQuestionRoundTrip(t *testing.T) {
	s := start(t, func(_ Request, _ []byte, fsys policy.FS) Response {
		p, err := fsys.EvalSymlinks("/tmp/e")
		if err != nil {
			return Response{Stderr: err.Error()}
		}
		data, regular, err := fsys.ReadRegular(p, 1<<20)
		if err != nil {
			return Response{Stderr: err.Error()}
		}
		return Response{Stdout: fmt.Sprintf("%s %d %v", p, len(data), regular)}
	})
	fsys := fakeFS{resolved: "/home/u/.claude/settings.json", data: bytes.Repeat([]byte{0xff}, 1<<20)}
	resp := Call(s.Path(), Request{Type: "pre-tool-use"}, []byte("{}"), fsys)
	if want := "/home/u/.claude/settings.json 1048576 true"; resp.Stdout != want || resp.Error != "" {
		t.Errorf("answer = %+v, want stdout %q", resp, want)
	}
}

func TestQuestionErrorKinds(t *testing.T) {
	type result struct {
		notExist   bool
		permission bool
		msg        string
	}
	got := make(chan result, 1)
	s := start(t, func(_ Request, _ []byte, fsys policy.FS) Response {
		_, err := fsys.EvalSymlinks("/x")
		got <- result{errors.Is(err, fs.ErrNotExist), errors.Is(err, fs.ErrPermission), fmt.Sprint(err)}
		return Response{}
	})
	for _, tc := range []struct {
		name string
		err  error
		want result
	}{
		{"not exist", &fs.PathError{Op: "lstat", Path: "/x", Err: syscall.ENOENT}, result{notExist: true, msg: "eval-symlinks /x: lstat /x: no such file or directory"}},
		{"permission", &fs.PathError{Op: "lstat", Path: "/x", Err: syscall.EACCES}, result{permission: true, msg: "eval-symlinks /x: lstat /x: permission denied"}},
		{"other", errors.New("EvalSymlinks: too many links"), result{msg: "eval-symlinks /x: EvalSymlinks: too many links"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if resp := Call(s.Path(), Request{}, nil, fakeFS{err: tc.err}); resp.Error != "" {
				t.Fatalf("answer = %+v, want no error", resp)
			}
			if r := <-got; r != tc.want {
				t.Errorf("handler saw %+v, want %+v", r, tc.want)
			}
		})
	}
}

// A handler that ignores a failed question still answers with an error.
func TestBadQuestionAnswerFailsClosed(t *testing.T) {
	s := start(t, func(_ Request, _ []byte, fsys policy.FS) Response {
		_, _ = fsys.EvalSymlinks("/x")
		_, _ = fsys.EvalSymlinks("/y")
		return Response{Stdout: "allow"}
	})
	for _, tc := range []struct{ name, answer string }{
		{"malformed", "not json\n"},
		{"oversized", `{"path":"` + strings.Repeat("a", maxLine) + `"}` + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, r := dialRaw(t, s, `{"type":"pre-tool-use","size":0}`+"\n")
			if m := readMessage(t, r); m.Question == nil || m.Question.Path != "/x" {
				t.Fatalf("first line = %+v, want a question about /x", m)
			}
			if _, err := conn.Write([]byte(tc.answer)); err != nil {
				t.Fatal(err)
			}
			if m := readMessage(t, r); m.Response == nil || m.Response.Error == "" || m.Response.Stdout != "" {
				t.Errorf("final line = %+v, want only an error response", m)
			}
		})
	}
}

func TestBadHeaderFailsClosed(t *testing.T) {
	called := make(chan struct{}, 1)
	s := start(t, func(Request, []byte, policy.FS) Response {
		called <- struct{}{}
		return Response{}
	})
	for _, tc := range []struct{ name, header string }{
		{"malformed", "not json\n"},
		{"oversized", `{"type":"` + strings.Repeat("a", maxHeader) + `"}` + "\n"},
		{"payload too large", fmt.Sprintf(`{"size":%d}`+"\n", policy.MaxEventBytes+2)},
		{"negative size", `{"size":-1}` + "\n"},
		{"short payload", `{"size":10}` + "\nabc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, r := dialRaw(t, s, tc.header)
			if tc.name == "short payload" {
				_ = conn.(*net.UnixConn).CloseWrite()
			}
			if m := readMessage(t, r); m.Response == nil || m.Response.Error == "" {
				t.Errorf("answer = %+v, want an error response", m)
			}
		})
	}
	select {
	case <-called:
		t.Error("the handler ran for a bad request")
	default:
	}
}

// A client that disconnects while a question is open fails the question.
func TestClientDisconnectsMidQuestion(t *testing.T) {
	errc := make(chan error, 1)
	s := start(t, func(_ Request, _ []byte, fsys policy.FS) Response {
		_, err := fsys.EvalSymlinks("/x")
		errc <- err
		return Response{}
	})
	conn, r := dialRaw(t, s, `{"size":0}`+"\n")
	readMessage(t, r)
	_ = conn.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Error("EvalSymlinks succeeded after the client disconnected")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler did not return after the client disconnected")
	}
}

// Call fails on a server line that is malformed or holds neither or both of question and response.
func TestCallBadServerLine(t *testing.T) {
	for _, line := range []string{"not json\n", "{}\n", `{"question":{"op":"eval-symlinks"},"response":{}}` + "\n", `{"question":{"op":"unlink","path":"/x"}}` + "\n"} {
		// The parent's TempDir keeps the subtest name out of the path, which would push it over
		// the unix socket limit on macOS.
		dir := t.TempDir()
		t.Run(line, func(t *testing.T) {
			path := filepath.Join(dir, "sock")
			ln, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = ln.Close() })
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				defer func() { _ = conn.Close() }()
				_, _ = conn.Write([]byte(line))
				_, _ = bufio.NewReader(conn).ReadBytes('\n')
			}()
			if resp := Call(path, Request{}, nil, fakeFS{}); resp.Error == "" {
				t.Errorf("answer = %+v, want an error", resp)
			}
		})
	}
}

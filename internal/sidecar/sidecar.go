// Package sidecar serves typed requests from the sandbox over a unix socket.
//
// A client writes one JSON header line with the request and the payload size, then the
// payload. The server answers with JSON lines. Each line holds either a filesystem question
// or the final response. The client answers each question with one JSON line from its own
// filesystem, so the handler sees paths as the sandbox sees them:
//
//	client: {"type":"pre-tool-use","decision":"json","size":61}\n<61 payload bytes>
//	server: {"question":{"op":"eval-symlinks","path":"/tmp/e"}}\n
//	client: {"path":"/home/u/.claude/settings.json"}\n
//	server: {"question":{"op":"read-regular","path":"/tmp/r","limit":1048576}}\n
//	client: {"err":"lstat /tmp/r: no such file or directory","kind":"not-exist"}\n
//	server: {"response":{"code":0,"stdout":"","stderr":"","error":""}}\n
//
// Any protocol error ends the connection with Response.Error set.
package sidecar

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/go-corral/corral/internal/policy"
)

const (
	maxHeader = 4 << 10
	// JSON escaping can grow one byte to six, and stdout can be as large as the payload.
	maxAnswer = 8 * policy.MaxEventBytes
	// maxLine bounds a question answer without file data.
	maxLine       = 64 << 10
	serverTimeout = 30 * time.Second
)

// callTimeout stays below the 10 second Claude Code hook timeout.
var callTimeout = 8 * time.Second

// Request is the header line of a connection.
type Request struct {
	Type     string `json:"type"`
	Decision string `json:"decision"`
}

// Response is the final line of a connection.
type Response struct {
	Code   int    `json:"code"`
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
	Error  string `json:"error"`
}

// Handler answers one request. payload holds at most 16 MiB plus one byte, so the handler
// can detect an oversized payload. fsys asks the client and is valid until the handler returns.
type Handler func(req Request, payload []byte, fsys policy.FS) Response

type header struct {
	Request
	Size int `json:"size"`
}

const (
	opEvalSymlinks = "eval-symlinks"
	opReadRegular  = "read-regular"

	kindNotExist   = "not-exist"
	kindPermission = "permission"
)

type question struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Limit int64  `json:"limit,omitempty"`
}

// message is a server line. Exactly one field is set.
type message struct {
	Question *question `json:"question,omitempty"`
	Response *Response `json:"response,omitempty"`
}

type answer struct {
	Path    string `json:"path,omitempty"`
	Data    []byte `json:"data,omitempty"`
	Regular bool   `json:"regular,omitempty"`
	Err     string `json:"err,omitempty"`
	Kind    string `json:"kind,omitempty"`
}

// Server listens on a unix socket inside a private directory.
type Server struct {
	dir  string
	path string
	ln   net.Listener
	h    Handler
}

// Start creates a mode 0700 directory under the host temp dir and serves h on
// a socket inside it.
func Start(h Handler) (*Server, error) {
	dir, err := os.MkdirTemp("", "corral-sidecar-*")
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	s := &Server{dir: dir, path: path, ln: ln, h: h}
	go s.serve()
	return s, nil
}

// Dir returns the directory that holds the socket.
func (s *Server) Dir() string { return s.dir }

// Path returns the socket path.
func (s *Server) Path() string { return s.path }

// Close stops the listener and removes the directory.
func (s *Server) Close() error {
	return errors.Join(s.ln.Close(), os.RemoveAll(s.dir))
}

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(serverTimeout))
	resp := s.answer(conn)
	_ = json.NewEncoder(conn).Encode(message{Response: &resp})
}

func (s *Server) answer(conn net.Conn) Response {
	r := bufio.NewReaderSize(conn, maxHeader)
	line, err := r.ReadSlice('\n')
	if err != nil {
		return Response{Error: fmt.Sprintf("read request header: %v", err)}
	}
	var h header
	if err := json.Unmarshal(line, &h); err != nil {
		return Response{Error: fmt.Sprintf("malformed request header: %v", err)}
	}
	if h.Size < 0 || h.Size > policy.MaxEventBytes+1 {
		return Response{Error: fmt.Sprintf("request payload size %d is outside 0 to %d", h.Size, policy.MaxEventBytes+1)}
	}
	payload := make([]byte, h.Size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Response{Error: fmt.Sprintf("read request payload: %v", err)}
	}
	fsys := &connFS{r: r, w: conn}
	resp := s.call(h.Request, payload, fsys)
	if fsys.err != nil {
		return Response{Error: fsys.err.Error()}
	}
	return resp
}

func (s *Server) call(req Request, payload []byte, fsys policy.FS) (resp Response) {
	defer func() {
		if p := recover(); p != nil {
			resp = Response{Error: fmt.Sprintf("sidecar handler panicked: %v", p)}
		}
	}()
	return s.h(req, payload, fsys)
}

// connFS asks the client. The first protocol error sticks and fails every later question.
type connFS struct {
	r   *bufio.Reader
	w   io.Writer
	err error
}

func (c *connFS) EvalSymlinks(path string) (string, error) {
	a, err := c.ask(question{Op: opEvalSymlinks, Path: path}, maxLine)
	if err != nil {
		return "", err
	}
	return a.Path, a.error(opEvalSymlinks, path)
}

func (c *connFS) ReadRegular(path string, limit int64) ([]byte, bool, error) {
	a, err := c.ask(question{Op: opReadRegular, Path: path, Limit: limit}, maxLine+base64.StdEncoding.EncodedLen(int(limit)))
	if err != nil {
		return nil, false, err
	}
	return a.Data, a.Regular, a.error(opReadRegular, path)
}

func (c *connFS) ask(q question, max int) (answer, error) {
	if c.err != nil {
		return answer{}, c.err
	}
	var a answer
	if err := json.NewEncoder(c.w).Encode(message{Question: &q}); err != nil {
		c.err = fmt.Errorf("write sidecar question: %w", err)
	} else if line, err := readLine(c.r, max); err != nil {
		c.err = fmt.Errorf("read sidecar question answer: %w", err)
	} else if err := json.Unmarshal(line, &a); err != nil {
		c.err = fmt.Errorf("malformed sidecar question answer: %w", err)
	}
	return a, c.err
}

// remoteError is an error from the client's filesystem.
type remoteError struct{ msg, kind string }

func (e *remoteError) Error() string { return e.msg }

func (e *remoteError) Is(target error) bool {
	return e.kind == kindNotExist && target == fs.ErrNotExist ||
		e.kind == kindPermission && target == fs.ErrPermission
}

func (a answer) error(op, path string) error {
	if a.Err == "" {
		return nil
	}
	return &fs.PathError{Op: op, Path: path, Err: &remoteError{msg: a.Err, kind: a.Kind}}
}

func answerFor(fsys policy.FS, q question) (answer, error) {
	var a answer
	var err error
	switch q.Op {
	case opEvalSymlinks:
		a.Path, err = fsys.EvalSymlinks(q.Path)
	case opReadRegular:
		a.Data, a.Regular, err = fsys.ReadRegular(q.Path, q.Limit)
	default:
		return answer{}, fmt.Errorf("unknown sidecar question %q", q.Op)
	}
	if err != nil {
		a.Err = err.Error()
		switch {
		case errors.Is(err, fs.ErrNotExist):
			a.Kind = kindNotExist
		case errors.Is(err, fs.ErrPermission):
			a.Kind = kindPermission
		}
	}
	return a, nil
}

// readLine reads one newline-terminated line of at most max bytes.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > max {
			return nil, fmt.Errorf("line exceeds %d bytes", max)
		}
		line = append(line, chunk...)
		if !errors.Is(err, bufio.ErrBufferFull) {
			return line, err
		}
	}
}

// Call sends one request to the socket at path, answers the server's questions from fsys, and
// waits for the response. Any failure is returned in Response.Error.
func Call(path string, req Request, payload []byte, fsys policy.FS) Response {
	d := net.Dialer{Deadline: time.Now().Add(callTimeout)}
	conn, err := d.Dial("unix", path)
	if err != nil {
		return Response{Error: fmt.Sprintf("dial sidecar: %v", err)}
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(d.Deadline)
	if err := json.NewEncoder(conn).Encode(header{Request: req, Size: len(payload)}); err != nil {
		return Response{Error: fmt.Sprintf("write sidecar request: %v", err)}
	}
	// A zero-length write fails with EPIPE once the server has answered and closed.
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return Response{Error: fmt.Sprintf("write sidecar request: %v", err)}
		}
	}
	r := bufio.NewReader(conn)
	for {
		line, err := readLine(r, maxAnswer)
		if err != nil {
			return Response{Error: fmt.Sprintf("read sidecar answer: %v", err)}
		}
		var m message
		if err := json.Unmarshal(line, &m); err != nil {
			return Response{Error: fmt.Sprintf("malformed sidecar answer: %v", err)}
		}
		switch {
		case m.Response != nil && m.Question == nil:
			return *m.Response
		case m.Question != nil && m.Response == nil:
			a, err := answerFor(fsys, *m.Question)
			if err != nil {
				return Response{Error: err.Error()}
			}
			if err := json.NewEncoder(conn).Encode(a); err != nil {
				return Response{Error: fmt.Sprintf("write sidecar question answer: %v", err)}
			}
		default:
			return Response{Error: "malformed sidecar answer: want exactly one of question and response"}
		}
	}
}

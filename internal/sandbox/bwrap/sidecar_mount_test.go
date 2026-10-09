package bwrap

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sidecar"
)

const sidecarClientEnv = "CORRAL_TEST_SIDECAR_CLIENT"

// The sidecar directory, mounted as the launcher mounts it, lets the sandbox connect to the
// socket but not replace it, even when an ancestor of the directory is writable or masked.
func TestReadOnlySidecarDirBlocksReplacement(t *testing.T) {
	if p := os.Getenv(sidecarClientEnv); p != "" {
		sidecarClient(t, p)
		return
	}
	b := New("")
	if !b.Available() {
		t.Skip("bwrap not available on this system")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mounts func(parent string) []sandbox.Mount
		masks  func(parent string) []string
	}{
		{
			name: "writable ancestor",
			mounts: func(parent string) []sandbox.Mount {
				return []sandbox.Mount{{Src: parent}}
			},
		},
		{
			name:  "masked ancestor",
			masks: func(parent string) []string { return []string{parent} },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A long TMPDIR could push the socket path over the unix socket limit.
			parent, err := os.MkdirTemp("", "corral-test-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(parent) })
			t.Setenv("TMPDIR", parent)
			srv, err := sidecar.Start(func(sidecar.Request, []byte, policy.FS) sidecar.Response { return sidecar.Response{} })
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = srv.Close() }()

			spec := sandbox.SandboxSpec{
				SetEnv: map[string]string{sidecarClientEnv: srv.Path()},
				Mounts: []sandbox.Mount{{Src: "/", ReadOnly: true}},
			}
			if tc.mounts != nil {
				spec.Mounts = append(spec.Mounts, tc.mounts(parent)...)
			}
			if tc.masks != nil {
				spec.BlockedPaths = tc.masks(parent)
			}
			spec.Mounts = append(spec.Mounts, sandbox.Mount{Src: srv.Dir(), ReadOnly: true, Overlay: true})
			argv, err := b.Argv(spec, []string{self, "-test.run=^TestReadOnlySidecarDirBlocksReplacement$", "-test.v"})
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Env = spec.Environ()
			out, err := cmd.CombinedOutput()
			if err != nil {
				if strings.Contains(string(out), "Creating new namespace failed") {
					t.Skipf("bwrap cannot run here: %s", out)
				}
				t.Fatalf("in-sandbox client failed: %v\n%s", err, out)
			}
		})
	}
}

func sidecarClient(t *testing.T, sock string) {
	t.Helper()
	t.Logf("client: connecting to %s", sock)
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("client: connect must succeed: %v", err)
	}
	_ = conn.Close()
	if err := os.Remove(sock); err == nil {
		t.Error("client: removing the socket must fail")
	}
	dir := filepath.Dir(sock)
	if f, err := os.Create(filepath.Join(dir, "new-file")); err == nil {
		_ = f.Close()
		t.Error("client: creating a file in the directory must fail")
	}
	if l, err := net.Listen("unix", filepath.Join(dir, "new-sock")); err == nil {
		_ = l.Close()
		t.Error("client: binding a new socket in the directory must fail")
	}
}

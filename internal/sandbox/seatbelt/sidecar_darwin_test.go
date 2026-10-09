//go:build darwin

package seatbelt

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/sidecar"
)

const sidecarClientEnv = "CORRAL_TEST_SIDECAR_CLIENT"

// Under the generated profile with net: none, the sandbox connects to the sidecar socket but
// cannot replace it, even though an ancestor of the socket directory is writable.
func TestGeneratedProfileSidecarSocket(t *testing.T) {
	if p := os.Getenv(sidecarClientEnv); p != "" {
		sidecarClient(t, p)
		return
	}
	if os.Getenv(sandbox.SandboxEnvVar) != "" {
		t.Skip("running inside corral: nested sandbox-exec is denied, cannot apply a test profile")
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not found")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
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
		Tokens: map[string]string{"HOME": home},
		// TMPDIR gives a -cover test binary a writable place for its coverage data; /tmp is denied.
		SetEnv: map[string]string{sidecarClientEnv: srv.Path(), sandbox.SidecarSocketEnvVar: srv.Path(), "TMPDIR": parent},
		Mounts: []sandbox.Mount{
			{Src: filepath.Dir(self), ReadOnly: true},
			{Src: parent},
			{Src: srv.Dir(), ReadOnly: true, Overlay: true},
		},
		Net: sandbox.NetNone,
	}
	argv, err := New("", Config{}).Argv(spec, []string{self, "-test.run=^TestGeneratedProfileSidecarSocket$", "-test.v"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = spec.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("in-sandbox client failed: %v\n%s", err, out)
	}
}

func sidecarClient(t *testing.T, sock string) {
	t.Helper()
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

//go:build darwin

package seatbelt

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

const overlayClientEnv = "CORRAL_TEST_OVERLAY_CLIENT"

// Under the generated profile, an Overlay mount inside a blocked dir is usable while the rest of
// the dir stays hidden, even though an ancestor of the dir is writable: the ssh provider's
// ~/.ssh/config reads, a key file next to it does not, and the forwarded agent socket connects
// but cannot be removed. A block.files entry stays denied under an overlay. A read-write overlay
// outside any blocked dir (launchd's /tmp/launch-…/Listeners shape) still connects with its
// file-write-data-only grant.
func TestGeneratedProfileOverlayInBlockedDir(t *testing.T) {
	if p := os.Getenv(overlayClientEnv); p != "" {
		overlayClient(t, p)
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

	sshDir := filepath.Join(parent, ".ssh")
	if err := os.Mkdir(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(sshDir, "config"),
		filepath.Join(sshDir, "id_ed25519"),
		filepath.Join(parent, "hosts"),
	} {
		if err := os.WriteFile(p, []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(sshDir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	// A read-write overlay OUTSIDE any blocked dir, shaped like launchd's
	// /tmp/launch-…/Listeners agent socket.
	sock2 := filepath.Join(parent, "launchd.sock")
	l2, err := net.Listen("unix", sock2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l2.Close() }()

	spec := sandbox.SandboxSpec{
		Tokens: map[string]string{"HOME": home},
		// TMPDIR gives a -cover test binary a writable place for its coverage data; /tmp is denied.
		SetEnv: map[string]string{overlayClientEnv: parent, "TMPDIR": parent},
		Mounts: []sandbox.Mount{
			{Src: filepath.Dir(self), ReadOnly: true},
			{Src: parent},
			{Src: filepath.Join(sshDir, "config"), ReadOnly: true, Overlay: true},
			{Src: sock, Overlay: true},
			{Src: filepath.Join(parent, "hosts"), ReadOnly: true, Overlay: true},
			{Src: sock2, Overlay: true},
		},
		BlockedPaths: []string{sshDir},
		BlockedFiles: []string{filepath.Join(parent, "hosts")},
	}
	argv, err := New("", Config{}).Argv(spec, []string{self, "-test.run=^TestGeneratedProfileOverlayInBlockedDir$", "-test.v"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = spec.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("in-sandbox client failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Errorf("agent socket must survive the session: %v", err)
	}
}

func overlayClient(t *testing.T, parent string) {
	t.Helper()
	sshDir := filepath.Join(parent, ".ssh")
	config := filepath.Join(sshDir, "config")
	if _, err := os.ReadFile(config); err != nil {
		t.Errorf("client: reading the read-only overlay must succeed: %v", err)
	}
	if f, err := os.OpenFile(config, os.O_WRONLY|os.O_APPEND, 0); err == nil {
		_ = f.Close()
		t.Error("client: writing the read-only overlay must fail")
	}
	if err := os.Remove(config); err == nil {
		t.Error("client: removing the read-only overlay must fail")
	}
	if _, err := os.ReadFile(filepath.Join(sshDir, "id_ed25519")); err == nil {
		t.Error("client: reading a non-overlay file in the blocked dir must fail")
	}
	if _, err := os.ReadDir(sshDir); err == nil {
		t.Error("client: listing the blocked dir must fail")
	}
	if f, err := os.Create(filepath.Join(sshDir, "new-file")); err == nil {
		_ = f.Close()
		t.Error("client: creating a file in the blocked dir must fail")
	}
	if _, err := os.ReadFile(filepath.Join(parent, "hosts")); err == nil {
		t.Error("client: reading a block.files entry must fail even under an overlay")
	}

	sock := filepath.Join(sshDir, "agent.sock")
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("client: connecting to the read-write overlay socket must succeed: %v", err)
	}
	_ = conn.Close()
	if err := os.Remove(sock); err == nil {
		t.Error("client: removing the read-write overlay socket must fail")
	}

	conn, err = net.Dial("unix", filepath.Join(parent, "launchd.sock"))
	if err != nil {
		t.Fatalf("client: connecting to a read-write overlay outside a blocked dir must succeed: %v", err)
	}
	_ = conn.Close()
}

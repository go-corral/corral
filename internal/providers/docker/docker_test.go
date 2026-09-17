package docker

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
)

// newUnixSocket creates a listening unix socket in a short-pathed temp dir and
// returns its path.
func newUnixSocket(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(shortSocketDir(t), "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return sock
}

// shortSocketDir returns a writable temp dir whose path is short enough to bind a
// unix socket under. It deliberately avoids t.TempDir(): bind(2) caps the socket
// path near 104 bytes on macOS, and t.TempDir() nests under
// /var/folders/<uid>/T/<TestName>/NNN/ — the per-test nesting overflows the cap.
// Binding directly under the temp root (no nesting) stays well under it; /tmp is a
// fallback for an unusually long or unwritable $TMPDIR.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	for _, base := range []string{os.TempDir(), "/tmp"} {
		dir, err := os.MkdirTemp(base, "s")
		if err != nil {
			continue
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		return dir
	}
	t.Fatal("no writable temp dir for unix socket")
	return ""
}

func TestDockerAvailableAndMint(t *testing.T) {
	sock := newUnixSocket(t)
	home := t.TempDir()
	dockerCfg := filepath.Join(home, ".docker")
	if err := os.MkdirAll(dockerCfg, 0o700); err != nil {
		t.Fatal(err)
	}

	// Construct directly to point at our fake socket (New hard-codes the
	// default location, which won't exist in the test sandbox).
	d := &docker{socketPath: sock, dockerCfg: dockerCfg}
	if !d.Available(context.Background()) {
		t.Fatal("docker should be available with a live socket")
	}
	c, err := d.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if len(c.Mounts) != 2 {
		t.Fatalf("expected socket + ~/.docker mounts, got %+v", c.Mounts)
	}
	// Src is the canonical (symlink-resolved) socket path; Dst stays the path as given.
	realSock, err := filepath.EvalSymlinks(sock)
	if err != nil {
		t.Fatal(err)
	}
	if c.Mounts[0].Src != realSock || c.Mounts[0].Dst != sock || c.Mounts[0].ReadOnly {
		t.Errorf("socket mount should be rw, Src=%q (real) Dst=%q: %+v", realSock, sock, c.Mounts[0])
	}
	if c.Mounts[1].Src != dockerCfg || !c.Mounts[1].ReadOnly || !c.Mounts[1].Optional {
		t.Errorf("~/.docker should be ro + optional: %+v", c.Mounts[1])
	}
	if c.Cleanup != nil {
		t.Error("socket-broker should register no cleanup")
	}
	// The AgentNote states the one fact invisible from inside: the socket is the host daemon.
	if len(c.AgentNotes) != 1 || !strings.Contains(c.AgentNotes[0], "HOST daemon") {
		t.Errorf("docker AgentNotes should name the host-daemon fact, got %v", c.AgentNotes)
	}
	// The Status line is the provider's row in the banner's providers section — without
	// it an enabled docker would be invisible there.
	if len(c.Status) != 1 || !strings.Contains(c.Status[0], "docker daemon socket") || !strings.Contains(c.Status[0], dockerCfg) {
		t.Errorf("docker Status should name the socket grant and the ~/.docker overlay, got %v", c.Status)
	}
}

// A symlinked socket path is bound by its real target (Src), with the symlink path
// preserved as the in-sandbox Dst, so a symlink can't redirect the bind source.
func TestDockerMintResolvesSocketSymlink(t *testing.T) {
	sock := newUnixSocket(t)
	link := filepath.Join(t.TempDir(), "docker.sock") // symlink → sock
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	// Mint binds the fully-resolved realpath: EvalSymlinks follows both the docker.sock
	// symlink and, on macOS, the /tmp→/private/tmp firmlink. The expectation must be
	// resolved too, not the raw socket path.
	realSock, err := filepath.EvalSymlinks(sock)
	if err != nil {
		t.Fatal(err)
	}
	d := &docker{socketPath: link}
	c, err := d.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if c.Mounts[0].Src != realSock {
		t.Errorf("Src should be the resolved real socket %q, got %q", realSock, c.Mounts[0].Src)
	}
	if c.Mounts[0].Dst != link {
		t.Errorf("Dst should stay the conventional (symlink) path %q, got %q", link, c.Mounts[0].Dst)
	}
}

func TestDockerUnavailableWhenSocketMissing(t *testing.T) {
	d := &docker{socketPath: filepath.Join(t.TempDir(), "absent.sock")}
	if d.Available(context.Background()) {
		t.Fatal("docker should be unavailable without a socket")
	}
	if _, err := d.Mint(context.Background(), spec.Session{}, false); err == nil {
		t.Fatal("Mint should fail closed when the socket is missing")
	}
}

func TestNewDockerHomeEmptySkipsConfig(t *testing.T) {
	d := New("").(*docker)
	if d.dockerCfg != "" {
		t.Errorf("empty home should skip ~/.docker, got %q", d.dockerCfg)
	}
}

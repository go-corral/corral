package ssh

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
	"github.com/go-corral/corral/internal/sandbox"
)

func sshHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

func writeSSHFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// findMount returns the first mount whose Dst equals dst, or nil.
func findMount(ms []sandbox.Mount, dst string) *sandbox.Mount {
	for i := range ms {
		if ms[i].Dst == dst {
			return &ms[i]
		}
	}
	return nil
}

func TestSSHAvailable(t *testing.T) {
	t.Run("nothing", func(t *testing.T) {
		home := sshHome(t)
		if New(home, "", nil).Available(context.Background()) {
			t.Error("no agent, no config, no known_hosts → unavailable")
		}
	})
	t.Run("live agent only", func(t *testing.T) {
		home := sshHome(t)
		sock := newUnixSocket(t)
		if !New(home, sock, nil).Available(context.Background()) {
			t.Error("live agent socket → available")
		}
	})
	t.Run("config only", func(t *testing.T) {
		home := sshHome(t)
		writeSSHFile(t, filepath.Join(home, ".ssh", "config"), "Host x\n")
		if !New(home, "", nil).Available(context.Background()) {
			t.Error("config present → available")
		}
	})
}

func TestSSHMintAgentIsOverlayRWPlusEnv(t *testing.T) {
	home := sshHome(t)
	sock := newUnixSocket(t)
	c, err := New(home, sock, nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	m := findMount(c.Mounts, sock)
	if m == nil {
		t.Fatalf("agent socket not mounted: %+v", c.Mounts)
	}
	if !m.Overlay || m.ReadOnly {
		t.Errorf("agent socket must be overlay + rw (gpg-agent socket lives under a masked dir): %+v", *m)
	}
	if c.Env["SSH_AUTH_SOCK"] != sock {
		t.Errorf("SSH_AUTH_SOCK env = %q, want %q", c.Env["SSH_AUTH_SOCK"], sock)
	}
	if c.Cleanup != nil {
		t.Error("ssh provider registers no cleanup")
	}
	// With an agent forwarded, the AgentNote counters the base note's "~/.ssh is masked"
	// (else the model concludes ssh auth can't work).
	if len(c.AgentNotes) != 1 || !strings.Contains(c.AgentNotes[0], "SSH_AUTH_SOCK") {
		t.Errorf("ssh AgentNotes should name the forwarded agent, got %v", c.AgentNotes)
	}
	// The Status line is the provider's row in the banner's providers section.
	if len(c.Status) != 1 || !strings.Contains(c.Status[0], "ssh-agent") {
		t.Errorf("ssh Status should name the forwarded agent socket, got %v", c.Status)
	}
}

func TestSSHMintBindsAgentSocketRealpath(t *testing.T) {
	home := sshHome(t)
	sock := newUnixSocket(t)
	// SSH_AUTH_SOCK is a symlink to the real socket (e.g. a stable ~/.ssh/agent link).
	link := filepath.Join(home, "agent-link.sock")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	c, err := New(home, link, nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	m := findMount(c.Mounts, link) // dst is the path clients expect (the symlink)
	if m == nil {
		t.Fatalf("agent socket not mounted: %+v", c.Mounts)
	}
	realSock, _ := filepath.EvalSymlinks(sock)
	if m.Src != realSock {
		t.Errorf("socket Src must be the resolved realpath %q (bwrap can't follow a symlink at mount time), got %q", realSock, m.Src)
	}
	if c.Env["SSH_AUTH_SOCK"] != link {
		t.Errorf("SSH_AUTH_SOCK env must stay the client-expected path %q, got %q", link, c.Env["SSH_AUTH_SOCK"])
	}
}

func TestSSHMintConfigAndKnownHostsAreReadOnlyOverlays(t *testing.T) {
	home := sshHome(t)
	cfgPath := filepath.Join(home, ".ssh", "config")
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	writeSSHFile(t, cfgPath, "Host example\n  User me\n")
	writeSSHFile(t, khPath, "example ssh-ed25519 AAAA...\n")

	c, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, dst := range []string{cfgPath, khPath} {
		m := findMount(c.Mounts, dst)
		if m == nil {
			t.Fatalf("%s not overlaid: %+v", dst, c.Mounts)
		}
		if !m.Overlay || !m.ReadOnly || !m.Optional {
			t.Errorf("%s must be overlay+ro+optional: %+v", dst, *m)
		}
	}
	// No agent → no AgentNote: config/known_hosts overlays alone grant no auth, and a
	// note claiming ssh "works" would oversell the session's capability.
	if len(c.AgentNotes) != 0 {
		t.Errorf("config-only ssh mint must contribute no AgentNotes, got %v", c.AgentNotes)
	}
	// The Status line reflects only what was granted: file overlays, no agent claim.
	if len(c.Status) != 1 || !strings.Contains(c.Status[0], "2 vetted config file(s)") || strings.Contains(c.Status[0], "ssh-agent") {
		t.Errorf("config-only ssh Status should count the overlays and not claim an agent, got %v", c.Status)
	}
}

func TestSSHMintFollowsIncludes(t *testing.T) {
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")
	writeSSHFile(t, filepath.Join(sshDir, "config"), "Include config.d/*\nHost x\n")
	extra := filepath.Join(sshDir, "config.d", "10-extra")
	writeSSHFile(t, extra, "Host extra\n  Port 2222\n")

	c, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if m := findMount(c.Mounts, extra); m == nil || !m.Overlay || !m.ReadOnly {
		t.Errorf("included file %s should be overlaid ro: %+v", extra, c.Mounts)
	}
}

func TestSSHMintExcludesForbiddenRoots(t *testing.T) {
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")
	gnupg := filepath.Join(home, ".gnupg")
	// A config that tries to Include a file inside the forbidden ~/.gnupg.
	writeSSHFile(t, filepath.Join(sshDir, "config"), "Include ../.gnupg/leak\n")
	writeSSHFile(t, filepath.Join(gnupg, "leak"), "secret\n")

	c, err := New(home, "", []string{gnupg}).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range c.Mounts {
		if strings.Contains(m.Dst, ".gnupg") || strings.Contains(m.Src, ".gnupg") {
			t.Errorf("ssh overlay must never reach into a forbidden root: %+v", m)
		}
	}
}

// New receives the full always-blocked set (config.AlwaysBlockedExpanded, including ~/.ssh)
// and owns the containment policy: it must exclude its own ~/.ssh — the dir the overlay
// legitimately re-grants files from — while the remaining roots stay forbidden. A
// regression here would either kill the overlay entirely (~/.ssh forbidden) or side-door
// the other secret dirs (floor dropped).
func TestSSHMintAlwaysBlockedExcludesOwnSSHDirOnly(t *testing.T) {
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")
	gnupg := filepath.Join(home, ".gnupg")
	aws := filepath.Join(home, ".aws")
	writeSSHFile(t, filepath.Join(sshDir, "config"), "Include ../.gnupg/leak\n")
	writeSSHFile(t, filepath.Join(gnupg, "leak"), "secret\n")

	floor := []string{sshDir, gnupg, aws}
	c, err := New(home, "", floor).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	var sawConfig bool
	for _, m := range c.Mounts {
		if strings.Contains(m.Dst, ".gnupg") || strings.Contains(m.Src, ".gnupg") {
			t.Errorf("full-floor input must still forbid ~/.gnupg: %+v", m)
		}
		if m.Dst == filepath.Join(sshDir, "config") {
			sawConfig = true
		}
	}
	if !sawConfig {
		t.Errorf("~/.ssh in the floor input must NOT forbid the provider's own overlay; mounts: %+v", c.Mounts)
	}
}

func TestSSHMintExcludesForbiddenRootReachedViaSymlink(t *testing.T) {
	// The forbidden root is reached through a symlink, so its realpath differs from its
	// lexical form — the exact shape resolveForbidden must see through, and the same code
	// path the macOS /var→/private/var firmlink exercises. Comparing against the un-resolved
	// root would miss the resolved Include candidate and leak it into the overlay.
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")
	realSecrets := t.TempDir()
	if err := os.WriteFile(filepath.Join(realSecrets, "leak"), []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gnupg := filepath.Join(home, ".gnupg") // a symlink into the real secrets dir
	if err := os.Symlink(realSecrets, gnupg); err != nil {
		t.Fatal(err)
	}
	writeSSHFile(t, filepath.Join(sshDir, "config"), "Include ../.gnupg/leak\n")

	c, err := New(home, "", []string{gnupg}).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	realLeak, _ := filepath.EvalSymlinks(filepath.Join(gnupg, "leak"))
	for _, m := range c.Mounts {
		if (realLeak != "" && m.Src == realLeak) || strings.Contains(m.Dst, ".gnupg") {
			t.Errorf("ssh overlay must not reach a forbidden root via symlink: %+v", m)
		}
	}
}

func TestSSHMintResolvesSymlinkConfigToRealpath(t *testing.T) {
	home := sshHome(t)
	// dotfiles case: ~/.ssh/config is a symlink to a file outside ~/.ssh.
	real := filepath.Join(home, "dotfiles", "ssh_config")
	writeSSHFile(t, real, "Host d\n")
	link := filepath.Join(home, ".ssh", "config")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	c, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	m := findMount(c.Mounts, link) // dst is the path ssh opens (~/.ssh/config)
	if m == nil {
		t.Fatalf("symlinked config not overlaid: %+v", c.Mounts)
	}
	realResolved, _ := filepath.EvalSymlinks(real)
	if m.Src != realResolved {
		t.Errorf("src must be the resolved realpath %q (not the symlink), got %q", realResolved, m.Src)
	}
}

func TestSSHMintSkipsNonRegularInclude(t *testing.T) {
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")
	// Include points at a directory — must be skipped (regular-file guard).
	if err := os.MkdirAll(filepath.Join(sshDir, "adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeSSHFile(t, filepath.Join(sshDir, "config"), "Include adir\n")
	c, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if m := findMount(c.Mounts, filepath.Join(sshDir, "adir")); m != nil {
		t.Errorf("a directory Include must not be overlaid: %+v", *m)
	}
}

func TestSSHMintIncludeCycleTerminates(t *testing.T) {
	home := sshHome(t)
	cfg := filepath.Join(home, ".ssh", "config")
	writeSSHFile(t, cfg, "Include config\nHost self\n") // includes itself
	c, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, m := range c.Mounts {
		if m.Dst == cfg {
			n++
		}
	}
	if n != 1 {
		t.Errorf("self-include must be visited once (cycle guard), got %d mounts for config", n)
	}
}

func TestSSHMintNothingFailsClosed(t *testing.T) {
	home := sshHome(t) // .ssh exists but empty, no agent
	if _, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false); err == nil {
		t.Fatal("Mint with no agent and no config should error")
	}
}

func TestSplitArgsAndKeyword(t *testing.T) {
	kw, rest := splitKeyword("Include  ~/.ssh/conf.d/*")
	if !strings.EqualFold(kw, "include") || rest != "~/.ssh/conf.d/*" {
		t.Errorf("splitKeyword = %q,%q", kw, rest)
	}
	kw, rest = splitKeyword("Include=foo")
	if !strings.EqualFold(kw, "include") || rest != "foo" {
		t.Errorf("splitKeyword with '=' = %q,%q", kw, rest)
	}
	got := splitArgs(`a "b c" d`)
	if len(got) != 3 || got[0] != "a" || got[1] != "b c" || got[2] != "d" {
		t.Errorf("splitArgs = %#v", got)
	}
}

// newUnixSocket creates a listening unix socket in a short-pathed temp dir and
// returns its path. (Deliberately duplicated in the docker package: test-only
// helpers stay out of the production API, and each socket-broker package owns
// its copy.)
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

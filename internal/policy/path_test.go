package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func mustCanon(t *testing.T, p string) string {
	t.Helper()
	c, err := Canonicalize(p, "")
	if err != nil {
		t.Fatalf("canonicalize root %q: %v", p, err)
	}
	return c
}

func TestCanonicalizeRelativeUsesCwd(t *testing.T) {
	dir := t.TempDir()
	got, err := Canonicalize("sub/file.txt", dir)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(mustCanon(t, dir), "sub", "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestCanonicalizeRelativeNoCwdErrors(t *testing.T) {
	if _, err := Canonicalize("foo", ""); err == nil {
		t.Error("expected error for relative path with no cwd")
	}
}

func TestCanonicalizeTraversal(t *testing.T) {
	dir := mustCanon(t, t.TempDir())
	got, err := Canonicalize(filepath.Join(dir, "a", "..", "b"), "")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "b"); got != want {
		t.Errorf("traversal not collapsed: got %q want %q", got, want)
	}
}

func TestCanonicalizeNonexistentLeaf(t *testing.T) {
	dir := mustCanon(t, t.TempDir())
	// Leaf does not exist; parent does. Must still resolve under the parent.
	got, err := Canonicalize(filepath.Join(dir, "newfile"), "")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "newfile"); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestCanonicalizeSymlinkEscape(t *testing.T) {
	home := mustCanon(t, t.TempDir())
	ssh := filepath.Join(home, ".ssh")
	if err := os.Mkdir(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(ssh, "id_rsa")
	if err := os.WriteFile(key, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink with an innocent name pointing at the secret.
	link := filepath.Join(home, "innocent.txt")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	got, err := Canonicalize(link, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != key {
		t.Errorf("symlink not resolved: got %q want %q", got, key)
	}
}

func TestCanonicalizeSymlinkedDirNonexistentLeaf(t *testing.T) {
	// Write through a symlinked directory to a not-yet-existing file: the
	// classic "create ~/.ssh/authorized_keys via a symlink" bypass.
	home := mustCanon(t, t.TempDir())
	ssh := filepath.Join(home, ".ssh")
	if err := os.Mkdir(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(home, "shortcut")
	if err := os.Symlink(ssh, linkDir); err != nil {
		t.Fatal(err)
	}
	got, err := Canonicalize(filepath.Join(linkDir, "authorized_keys"), "")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(ssh, "authorized_keys"); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestCanonicalizeRootToleratesPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses directory permission checks")
	}
	home := mustCanon(t, t.TempDir())
	// A deny root whose parent is unreadable: lstat of the leaf hits EACCES, the
	// same shape a sandbox produces when it masks ~/.ssh.
	locked := filepath.Join(home, "locked")
	if err := os.Mkdir(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) }) // let TempDir cleanup remove it
	root := filepath.Join(locked, ".ssh")

	// Strict Canonicalize fails closed on the permission error...
	if _, err := Canonicalize(root, ""); err == nil {
		t.Fatal("Canonicalize: expected a permission error, got nil")
	}
	// ...but CanonicalizeRoot falls back to the lexically-cleaned absolute path.
	got, err := CanonicalizeRoot(root, "")
	if err != nil {
		t.Fatalf("CanonicalizeRoot: unexpected error: %v", err)
	}
	if got != root {
		t.Errorf("CanonicalizeRoot fallback: got %q want %q", got, root)
	}
}

func TestCanonicalizeRootMatchesCanonicalizeWhenResolvable(t *testing.T) {
	// With no permission barrier, CanonicalizeRoot must behave exactly like
	// Canonicalize (resolve symlinks, collapse traversal) — the relaxation only
	// triggers on a permission error.
	home := mustCanon(t, t.TempDir())
	real := filepath.Join(home, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalizeRoot(link, "")
	if err != nil {
		t.Fatal(err)
	}
	if got != real {
		t.Errorf("CanonicalizeRoot did not resolve symlink: got %q want %q", got, real)
	}
}

func TestLogicalSysPath(t *testing.T) {
	// On darwin the /private firmlink subtrees fold back to the conventional name;
	// everywhere else (and for unrelated paths) the input passes through unchanged.
	cases := []struct{ in, darwin string }{
		{"/etc/shadow", "/etc/shadow"},                     // already conventional
		{"/private/etc/shadow", "/etc/shadow"},             // firmlink-resolved → conventional
		{"/private/etc", "/etc"},                           // bare node (the dir itself)
		{"/private/var/root/.ssh", "/var/root/.ssh"},       // root's home firmlink
		{"/private/tmp/x", "/tmp/x"},                       // /tmp firmlink
		{"/private/var", "/var"},                           // bare node
		{"/Users/u/project/.env", "/Users/u/project/.env"}, // unrelated, unchanged
		{"/private/etcd/data", "/private/etcd/data"},       // prefix-safety: /private/etcd ≠ /private/etc
		{"/etc", "/etc"},                                   // conventional bare node unchanged
	}
	for _, c := range cases {
		want := c.in
		if runtime.GOOS == "darwin" {
			want = c.darwin
		}
		if got := logicalSysPath(c.in); got != want {
			t.Errorf("logicalSysPath(%q) = %q, want %q", c.in, got, want)
		}
	}
}

// An empty path must error in both canonicalizers (the lexicalAbs empty-path branch),
// so a caller can never accidentally treat "" as the filesystem root.
func TestCanonicalizeEmptyPathErrors(t *testing.T) {
	if _, err := Canonicalize("", "/home/u"); err == nil {
		t.Error("Canonicalize(\"\") must error (fail closed)")
	}
	if _, err := CanonicalizeRoot("", "/home/u"); err == nil {
		t.Error("CanonicalizeRoot(\"\") must error (fail closed)")
	}
}

func TestWithin(t *testing.T) {
	cases := []struct {
		p, root string
		want    bool
	}{
		{"/home/u/.ssh", "/home/u/.ssh", true},
		{"/home/u/.ssh/id_rsa", "/home/u/.ssh", true},
		{"/home/u/.ssh/sub/k", "/home/u/.ssh", true},
		{"/home/u/.sshx", "/home/u/.ssh", false}, // prefix-safety
		{"/home/u/.ssh-backup", "/home/u/.ssh", false},
		{"/home/u", "/home/u/.ssh", false},
		{"/anything", "/", true},
		{"/home/other/.ssh", "/home/u/.ssh", false},
	}
	for _, c := range cases {
		if got := Within(c.p, c.root); got != c.want {
			t.Errorf("Within(%q,%q)=%v want %v", c.p, c.root, got, c.want)
		}
	}
}

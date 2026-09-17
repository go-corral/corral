package home

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
	"github.com/go-corral/corral/internal/sandbox"
)

func TestHomeMintCreatesDirAndWritableMount(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".cache", "corral", "home")

	c, err := New(dir).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Same-path rw bind on the private home: Src is the dir, Dst defaults to Src (empty),
	// non-overlay, non-optional (the private home must be present and writable).
	var m *sandbox.Mount
	for i := range c.Mounts {
		if c.Mounts[i].Src == dir {
			m = &c.Mounts[i]
		}
	}
	if m == nil {
		t.Fatalf("private home %s not mounted: %+v", dir, c.Mounts)
	}
	if m.Dst != "" || m.ReadOnly || m.Overlay || m.Optional {
		t.Errorf("home mount must be same-path (empty Dst) rw, non-overlay, non-optional: %+v", *m)
	}

	// HOME is launcher-set (DefaultParams.SandboxHome), never a provider env — emitting
	// it would trip Apply's env-collision guard.
	if _, ok := c.Env["HOME"]; ok {
		t.Error("home provider must NOT emit a HOME env var (the launcher sets it)")
	}
	if c.Cleanup != nil {
		t.Error("home provider registers no cleanup")
	}
	// No Status row: the private home is the same static location every session.
	if len(c.Status) != 0 {
		t.Errorf("home must author no launch status row, got %v", c.Status)
	}
	// The AgentNote corrects the base sandbox note's "most other paths are read-only":
	// $HOME is writable, private, and persistent.
	if len(c.AgentNotes) != 1 || !strings.Contains(c.AgentNotes[0], "$HOME") {
		t.Errorf("home AgentNotes should describe the private writable $HOME, got %v", c.AgentNotes)
	}

	// The dir must be created on the host (else the non-optional bind fails the launch).
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		t.Errorf("private home must be created: %v", err)
	}
}

// TestDefaultPathKeyedToConfigDir pins DefaultPath's keying: every config dir, an agent's
// default or a relocated one, maps to its own stable ~/.cache/corral/home-<8hex> sibling of the
// bare home, which is never returned.
func TestDefaultPathKeyedToConfigDir(t *testing.T) {
	const realHome = "/home/u"
	base := filepath.Join(realHome, ".cache", "corral", "home")

	dirs := []string{
		filepath.Join(realHome, ".claude"),
		filepath.Join(realHome, ".pi"),
		filepath.Join(realHome, ".claude-work"),
		filepath.Join(realHome, ".pi-work"),
	}
	seen := map[string]string{}
	for _, dir := range dirs {
		d := DefaultPath(realHome, dir)
		if d == base || filepath.Dir(d) != filepath.Dir(base) || len(filepath.Base(d)) != len("home-")+8 {
			t.Errorf("%s should yield a sibling home-<8hex>, got %q", dir, d)
		}
		if prev, dup := seen[d]; dup {
			t.Errorf("%s and %s must not share a home, both got %q", prev, dir, d)
		}
		seen[d] = dir
	}

	// Keying is stable across different spellings of the same dir.
	work := DefaultPath(realHome, filepath.Join(realHome, ".claude-work"))
	if again := DefaultPath(realHome, filepath.Join(realHome, ".claude-work", ".")); again != work {
		t.Errorf("same dir (different spelling) must be stable: got %q, want %q", again, work)
	}
}

// TestDefaultPathHashIsPinned pins the digest scheme to literal values. The private home is
// persistent user state, so any change to the cleaning, the digest, or its truncation moves
// every user to an empty home; that must be a deliberate, visible decision.
func TestDefaultPathHashIsPinned(t *testing.T) {
	const realHome = "/home/u"
	for dir, want := range map[string]string{
		filepath.Join(realHome, ".claude"):      "home-99b1807e",
		filepath.Join(realHome, ".claude-work"): "home-9fa37e90",
	} {
		if got := filepath.Base(DefaultPath(realHome, dir)); got != want {
			t.Errorf("DefaultPath(%q): got %q, want %q", dir, got, want)
		}
	}
}

func TestHomeAlwaysAvailable(t *testing.T) {
	if !New(t.TempDir()).Available(context.Background()) {
		t.Error("home provider has no host prerequisite — always available")
	}
}

// TestHomeMintDryRunIsSideEffectFree guards the --dry-run contract: Mint with dryRun=true
// returns the same mount/status as a real Mint but must not create the backing dir (a dry
// run mutates nothing) — this is what lets ResolvePreview fold the private $HOME into the
// printed profile without touching the filesystem.
func TestHomeMintDryRunIsSideEffectFree(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".cache", "corral", "home")

	c, err := New(dir).Mint(context.Background(), spec.Session{}, true)
	if err != nil {
		t.Fatalf("dry-run Mint must not fail: %v", err)
	}
	if c == nil || len(c.Mounts) != 1 || c.Mounts[0].Src != dir {
		t.Fatalf("dry-run Mint must return the same-path home mount: %+v", c)
	}
	if len(c.Status) != 0 {
		t.Errorf("home must author no launch status row on a dry run either, got %v", c.Status)
	}
	// The defining property: no filesystem mutation — the dir is not created.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("dry-run Mint must not create the private home %q (stat err=%v)", dir, err)
	}
}

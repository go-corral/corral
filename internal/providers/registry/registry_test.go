package registry

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/env"
)

// drift guard: the registry order is the canonical provider declaration order
// (apply order, collision attribution, LIFO cleanup), and the config.Providers
// struct-field order documents the same sequence to YAML readers. This pins the
// two to each other — adding or reordering a provider in one place without the
// other fails here instead of silently skewing the contracts.
func TestRegistryMirrorsConfigOrder(t *testing.T) {
	var want []string
	tp := reflect.TypeOf(config.Providers{})
	for i := 0; i < tp.NumField(); i++ {
		tag := strings.Split(tp.Field(i).Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			t.Fatalf("config.Providers field %s has no yaml key", tp.Field(i).Name)
		}
		want = append(want, tag)
	}
	got := Names()
	if len(got) != len(want) {
		t.Fatalf("registry has %d entries, config.Providers has %d fields:\nregistry: %v\nconfig:   %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("order skew at %d: registry %q vs config.Providers %q", i, got[i], want[i])
		}
	}
}

// drift guard: every entry's Name must match what its constructed provider
// reports — the engine attributes collisions, banner status, and cleanup
// failures by Provider.Name(), so a mismatched table entry would mislabel all
// of them.
func TestRegistryEntryNamesMatchProviders(t *testing.T) {
	d := Deps{
		Home:    t.TempDir(),
		Host:    map[string]string{},
		HomeDir: filepath.Join(t.TempDir(), "home"),
	}
	cfg := &config.Config{}
	for _, e := range registry {
		if e.Enabled == nil || e.Build == nil {
			t.Errorf("entry %q must define Enabled and Build", e.Name)
			continue // Build below would panic on a nil func
		}
		if got := e.Build(cfg, d).Name(); got != e.Name {
			t.Errorf("entry %q builds a provider named %q", e.Name, got)
		}
		if e.Probe != nil {
			if got := e.Probe(d).Name(); got != e.Name {
				t.Errorf("entry %q probes a provider named %q", e.Name, got)
			}
		}
	}
}

// Built-ins are phase A by contract: never optional, never host-probed, not part
// of the validate intent view (they surface in the banner instead).
func TestRegistryBuiltinShape(t *testing.T) {
	for _, e := range registry {
		if !e.Builtin {
			continue
		}
		if e.Optional != nil || e.Probe != nil || e.Grants != nil || e.FailurePolicy != nil {
			t.Errorf("built-in %q must not define Optional/Probe/Grants/FailurePolicy", e.Name)
		}
	}
}

// drift guard: the Builtin flag routes a provider's Mint before the confirmation
// gate (phase A), so flipping it silently moves a deny provider across the gate —
// or a side-effecting feature in front of it. Pin the set: exactly the four
// config-owned built-ins, leading the table (deny before grant, before features).
func TestRegistryBuiltinSetPinned(t *testing.T) {
	want := []string{"block", "aiignore", "paths", "env"}
	for i, e := range registry {
		if i < len(want) {
			if !e.Builtin || e.Name != want[i] {
				t.Errorf("registry[%d] must be built-in %q, got %q (builtin=%v)", i, want[i], e.Name, e.Builtin)
			}
			continue
		}
		if e.Builtin {
			t.Errorf("entry %q must not be built-in (phase A is reserved for the pure config-owned providers)", e.Name)
		}
	}
	if len(registry) < len(want) {
		t.Fatalf("registry has %d entries, want at least the %d built-ins", len(registry), len(want))
	}
}

// contract guard: a built-in's Mint must be pure — dryRun-identical and free of
// filesystem side effects — because phase A runs it before the confirmation gate
// (and on --dry-run). Sweep every registered built-in with activating config, so
// a future built-in is covered automatically.
func TestRegistryBuiltinMintPure(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, ".aiignore"), []byte("secrets/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Providers.Block.Directories = []string{"/blocked/dir"}
	cfg.Providers.Block.Files = []string{"/blocked/file.env"}
	cfg.Providers.Paths.RW = []string{"/data/rw"}
	cfg.Providers.Paths.RO = []string{"/data/ro"}
	cfg.Providers.Env.Passthrough = []string{"TERM"}
	cfg.Providers.Env.Set = []env.Var{{Name: "FOO", Value: "bar"}}

	d := Deps{Home: "/home/u"}
	sess := providers.Session{User: "u", ID: "s1", WorkDir: repo}
	before := listTree(t, repo)

	for _, e := range registry {
		if !e.Builtin {
			continue
		}
		if !e.Enabled(cfg) {
			t.Errorf("built-in %q must be enabled by the activating fixture config", e.Name)
			continue
		}
		// Two fresh instances so shared state cannot mask a divergence.
		real, rerr := e.Build(cfg, d).Mint(context.Background(), sess, false)
		dry, derr := e.Build(cfg, d).Mint(context.Background(), sess, true)
		if rerr != nil || derr != nil {
			t.Errorf("built-in %q: Mint errored (real=%v, dry=%v)", e.Name, rerr, derr)
			continue
		}
		// Whole-contribution comparison; DeepEqual also enforces a nil Cleanup
		// (non-nil funcs never compare equal), which phase A requires anyway.
		if !reflect.DeepEqual(real, dry) {
			t.Errorf("built-in %q: Mint must be dryRun-identical\nreal: %+v\ndry:  %+v", e.Name, real, dry)
		}
	}

	if after := listTree(t, repo); !reflect.DeepEqual(before, after) {
		t.Errorf("built-in Mints must not touch the filesystem:\nbefore: %v\nafter:  %v", before, after)
	}
}

// listTree returns every path under root, sorted — a cheap side-effect witness.
func listTree(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}

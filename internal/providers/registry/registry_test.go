package registry

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
)

// drift guard: the config.Providers struct-field order documents the apply order to
// YAML readers: the config sections, then the registry in its canonical order
// (apply order, collision attribution, LIFO cleanup). A new field fails here until it
// is wired as a config section or as a registry entry.
func TestRegistryMirrorsConfigOrder(t *testing.T) {
	var got []string
	tp := reflect.TypeOf(config.Providers{})
	for i := 0; i < tp.NumField(); i++ {
		tag := strings.Split(tp.Field(i).Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			t.Fatalf("config.Providers field %s has no yaml key", tp.Field(i).Name)
		}
		got = append(got, tag)
	}
	want := append([]string{"block", "aiignore", "paths", "env", "notes"}, Names()...)
	if !slices.Equal(got, want) {
		t.Errorf("config.Providers fields must be the config sections, then the registry:\nconfig: %v\nwant:   %v", got, want)
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

// The kubernetes provider is active when at least one effective cluster is enabled, whatever
// the top-level enabled says.
func TestRegistryKubernetesClusterEnabled(t *testing.T) {
	global := `providers:
  kubernetes:
    enabled: false
    clusters:
      prod:
        kubeconfig: {context: prod}
      staging:
        kubeconfig: {context: staging}
profiles:
  staging:
    providers:
      kubernetes:
        clusters:
          staging:
            enabled: true
`
	for _, tc := range []struct {
		profiles []string
		want     bool
	}{
		{[]string{"staging"}, true},
		{nil, false},
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "global.yml")
		if err := os.WriteFile(path, []byte(global), 0o644); err != nil {
			t.Fatal(err)
		}
		cfg, _, err := config.Load(config.LoadOptions{Home: dir, GlobalPath: path, ProjectDir: dir, Profiles: tc.profiles})
		if err != nil {
			t.Fatal(err)
		}
		var active bool
		for _, a := range Features(cfg, Deps{Home: dir}) {
			if a.Provider.Name() == "kubernetes" {
				active = true
				if a.Optional {
					t.Error("a required enabled cluster makes the provider required")
				}
			}
		}
		if active != tc.want {
			t.Errorf("profiles %v: kubernetes active = %v, want %v", tc.profiles, active, tc.want)
		}
	}
}

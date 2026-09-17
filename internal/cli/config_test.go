package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
)

// The in-sandbox hook must read the same global config the launcher loaded, even when it
// lives outside the default ~/.config/corral (e.g. under a host $XDG_CONFIG_HOME the
// sandbox does not forward). The launcher pins the resolved path via sandbox.GlobalConfigEnvVar;
// loadConfig must honor it as the global path rather than re-resolving.
func TestLoadConfigHonorsPinnedGlobalPath(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj) // default global ($XDG/corral/config.yml) is absent

	// A global config at a non-default path, as the launcher would pin it.
	pinned := filepath.Join(t.TempDir(), "pinned.yml")
	if err := os.WriteFile(pinned, []byte("hostname: pinned-host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sandbox.GlobalConfigEnvVar, pinned)

	cfg, srcs, err := loadConfig(nil)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Hostname != "pinned-host" {
		t.Errorf("loadConfig must read the pinned global config, got hostname %q", cfg.Hostname)
	}
	sawGlobal := false
	for _, s := range srcs {
		if s.Kind == "global" && s.Path == pinned {
			sawGlobal = true
		}
	}
	if !sawGlobal {
		t.Errorf("pinned path must appear as the global source: %+v", srcs)
	}
}

// pinGlobalConfig records the resolved global path in the sandbox env and grants the file
// read-only; with no global config there is nothing to pin.
func TestPinGlobalConfig(t *testing.T) {
	gp := "/custom/xdg/corral/config.yml"
	spec := &sandbox.SandboxSpec{SetEnv: map[string]string{}}
	pinGlobalConfig(spec, []config.Source{
		{Kind: "defaults"},
		{Kind: "global", Path: gp},
		{Kind: "project", Path: "/proj/.corral.yml"},
	})
	if spec.SetEnv[sandbox.GlobalConfigEnvVar] != gp {
		t.Errorf("global path must be pinned into the sandbox env, got %q", spec.SetEnv[sandbox.GlobalConfigEnvVar])
	}
	found := false
	for _, m := range spec.Mounts {
		if m.Src == gp && m.ReadOnly && m.Optional {
			found = true
		}
	}
	if !found {
		t.Errorf("global config file must be granted read-only + optional, got %+v", spec.Mounts)
	}

	// No global source (only defaults/project) → pin nothing: the in-sandbox hook's own
	// default resolution also finds no global config, so the two stay consistent.
	bare := &sandbox.SandboxSpec{SetEnv: map[string]string{}}
	pinGlobalConfig(bare, []config.Source{{Kind: "defaults"}, {Kind: "project", Path: "/p/.corral.yml"}})
	if _, ok := bare.SetEnv[sandbox.GlobalConfigEnvVar]; ok {
		t.Error("no global source → must not pin anything")
	}
	if len(bare.Mounts) != 0 {
		t.Errorf("no global source → no mount, got %+v", bare.Mounts)
	}
}

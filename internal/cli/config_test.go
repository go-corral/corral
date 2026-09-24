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

// grantAuditDir adds a custom audit-log directory to the read-write grants and creates it;
// a dry run adds the grant only, and the default path adds nothing.
func TestGrantAuditDir(t *testing.T) {
	home := t.TempDir()
	cfg := &config.Config{}
	if err := grantAuditDir(cfg, home, false); err != nil || len(cfg.Providers.Paths.RW) != 0 {
		t.Fatalf("default path must add no grant, got %v, err %v", cfg.Providers.Paths.RW, err)
	}

	dir := filepath.Join(home, "state")
	cfg.Policy.Audit.Path = filepath.Join(dir, "audit.jsonl")
	if err := grantAuditDir(cfg, home, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("dry run must not create the directory, stat err: %v", err)
	}

	cfg.Providers.Paths.RW = nil
	if err := grantAuditDir(cfg, home, false); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Providers.Paths.RW) != 1 || cfg.Providers.Paths.RW[0] != dir {
		t.Errorf("grant = %v, want [%s]", cfg.Providers.Paths.RW, dir)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory must exist with mode 0700, got %v, err %v", fi, err)
	}
}

// grantAuditDir refuses a directory that would open the home directory read-write, and one
// that resolves into an always-blocked path through a symlinked ancestor, without creating it.
func TestGrantAuditDirRefuses(t *testing.T) {
	home := t.TempDir()
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(home, "logs")); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{
		filepath.Join(home, "audit.jsonl"),
		"/audit.jsonl",
		filepath.Join(home, "logs", "sub", "audit.jsonl"),
	} {
		cfg := &config.Config{}
		cfg.Policy.Audit.Path = p
		if err := grantAuditDir(cfg, home, false); err == nil {
			t.Errorf("%s: want refusal, got grants %v", p, cfg.Providers.Paths.RW)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "sub")); !os.IsNotExist(err) {
		t.Errorf("a refused directory must not be created, stat err: %v", err)
	}
}

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestUpdateCheckOnStartDefaultAndLayering verifies the update.checkOnStart default (true)
// survives strict decode and layering: an empty config inherits true, a project layer can
// override it to false, and a global layer can set it true.
func TestUpdateCheckOnStartDefaultAndLayering(t *testing.T) {
	dir := t.TempDir()
	globalPath := filepath.Join(dir, "global.yml")
	projDir := filepath.Join(dir, "proj")
	if err := os.MkdirAll(projDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	load := func() *Config {
		t.Helper()
		cfg, _, err := Load(LoadOptions{Home: dir, GlobalPath: globalPath, ProjectDir: projDir})
		if err != nil {
			t.Fatalf("load config: %v", err)
		}
		return cfg
	}

	// Empty config: inherits the default true.
	if !load().Update.CheckOnStart {
		t.Error("empty config: CheckOnStart = false, want true (default)")
	}

	// Project layer explicitly disables it.
	projFile := filepath.Join(projDir, ".corral.yml")
	writeFile(projFile, "update:\n  checkOnStart: false\n")
	if load().Update.CheckOnStart {
		t.Error("project checkOnStart:false: CheckOnStart = true, want false")
	}

	// Global layer explicitly enables it, with the project override removed.
	writeFile(globalPath, "update:\n  checkOnStart: true\n")
	if err := os.Remove(projFile); err != nil {
		t.Fatal(err)
	}
	if !load().Update.CheckOnStart {
		t.Error("global checkOnStart:true: CheckOnStart = false, want true")
	}
}

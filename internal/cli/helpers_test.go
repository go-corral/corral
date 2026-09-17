package cli

import (
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/trust"
)

// isolateConfigEnvNoApprove isolates config and trust state without bypassing the trust gate.
func isolateConfigEnvNoApprove(t *testing.T, home, projDir string) {
	t.Helper()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	// Pin the trust state dir under the temp home too, so DefaultDir is deterministic even
	// when the real environment sets XDG_STATE_HOME.
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	// Clear the in-sandbox global-config pin too: when the suite is run inside a corral
	// sandbox (devving corral on corral), the launcher sets this to the real global
	// config, which loadConfig would otherwise read instead of the isolated XDG dir.
	t.Setenv(sandbox.GlobalConfigEnvVar, "")
	// Clear every agent's relocator/reserved env vars (e.g. PI_CODING_AGENT_DIR): a developer's
	// shell may set them, and ConfigDir reads them from the host, so an unset would resolve the
	// agent config dir to the real path instead of the isolated home.
	for _, name := range agents.AllReservedEnv() {
		t.Setenv(name, "")
	}
	t.Chdir(projDir)
}

// isolateConfigEnv isolates config and pre-approves it so non-trust tests can pass the
// non-interactive fail-closed gate.
func isolateConfigEnv(t *testing.T, home, projDir string) {
	t.Helper()
	isolateConfigEnvNoApprove(t, home, projDir)
	approveRepoConfig(t, home, projDir)
}

// approveRepoConfig seeds the trust store with approval for whatever project/local config
// exists under projDir — and for the session-hook executables it names (the gate hashes
// those too; hook tests write their script files before calling isolateConfigEnv, so the
// hashes here match what the gate recomputes). An invalid config is left unapproved (it
// never reaches the gate — loadConfig fails first).
func approveRepoConfig(t *testing.T, home, projDir string) {
	t.Helper()
	cfg, sources, err := config.Load(config.LoadOptions{Home: home, ProjectDir: projDir})
	if err != nil {
		return
	}
	entries := append(trustEntries(sources), collectHookExecs(cfg, projDir).entries...)
	if len(entries) == 0 {
		return
	}
	if err := trust.NewStore(trust.DefaultDir(home)).Approve(entries); err != nil {
		t.Fatalf("pre-approve repo config: %v", err)
	}
}

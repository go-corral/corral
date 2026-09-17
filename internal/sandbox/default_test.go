package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultSpecMasksSecretsAndMountsProject(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := DefaultSpec(DefaultParams{
		Home:           home,
		ProjectDir:     proj,
		BlockedPaths:   []string{filepath.Join(home, ".ssh")},
		EnvPassthrough: []string{"TERM"},
		HostEnv:        map[string]string{"TERM": "xterm", "AWS_SECRET_ACCESS_KEY": "shh"},
	})

	if spec.WorkDir != proj {
		t.Errorf("WorkDir = %q, want %q", spec.WorkDir, proj)
	}
	if spec.Net != NetOpen {
		t.Errorf("Net = %q, want open (0.1 full network)", spec.Net)
	}
	if !contains(spec.BlockedPaths, filepath.Join(home, ".ssh")) {
		t.Errorf("must mask the blocked paths it is given; got %v", spec.BlockedPaths)
	}
	var projRW bool
	for _, m := range spec.Mounts {
		if m.Src == proj && !m.ReadOnly {
			projRW = true
		}
	}
	if !projRW {
		t.Errorf("project dir must be a read-write mount; got %v", spec.Mounts)
	}
	// Allowlisted, host-set var is forwarded.
	if spec.SetEnv["TERM"] != "xterm" {
		t.Errorf("passthrough TERM not forwarded: %v", spec.SetEnv)
	}
	// Sensitive ambient env not in the allowlist is dropped (there is no
	// blocklist — not being allowlisted is what blocks it).
	if _, ok := spec.SetEnv["AWS_SECRET_ACCESS_KEY"]; ok {
		t.Error("must not forward arbitrary ambient env")
	}
}

// TestDefaultSpecIsBackendAgnostic pins the central refactor invariant: DefaultSpec
// builds the same backend-agnostic spec for every backend. It carries only the
// per-launch mounts (the project here) — not the embedded baseline, which each
// backend compiles itself in Prepare/Argv — plus the baseline tokens the backends
// expand. (No `Backend` field, no `if backend == …` gate anywhere in this builder.)
func TestDefaultSpecIsBackendAgnostic(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	agentDir := filepath.Join(home, ".claude")
	spec := DefaultSpec(DefaultParams{Home: home, ProjectDir: proj, AgentConfigDir: agentDir})

	if len(spec.Mounts) != 1 || spec.Mounts[0].Src != proj {
		t.Errorf("DefaultSpec must carry only the per-launch project mount (no baseline binds); got %v", spec.Mounts)
	}
	if len(spec.Symlinks) != 0 {
		t.Errorf("DefaultSpec must carry no baseline symlinks; got %v", spec.Symlinks)
	}
	if spec.Tokens["HOME"] != home {
		t.Errorf("DefaultSpec must carry the HOME baseline token; got %v", spec.Tokens)
	}
	if spec.Tokens["AGENT_CONFIG_DIR"] != agentDir {
		t.Errorf("DefaultSpec must carry the AGENT_CONFIG_DIR baseline token; got %v", spec.Tokens)
	}
}

// TestDefaultSpecEmptyAgentConfigDir locks the fail-safe for a spec with no agent config
// dir: the $AGENT_CONFIG_DIR token stays empty (there is no ~/.claude fallback), so every
// baseline rule referencing it is skipped by the compilers — the launch binds no agent
// state rather than guessing a dir.
func TestDefaultSpecEmptyAgentConfigDir(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := DefaultSpec(DefaultParams{Home: home, ProjectDir: proj})

	if got := spec.Tokens["AGENT_CONFIG_DIR"]; got != "" {
		t.Errorf("unset AgentConfigDir must leave the token empty (no ~/.claude fallback); got %q", got)
	}
	// The empty token must cause a rule referencing it to be skipped.
	if _, ok := ExpandPath("$AGENT_CONFIG_DIR/state", spec.Tokens); ok {
		t.Error("a baseline rule referencing an empty $AGENT_CONFIG_DIR must be skipped")
	}
}

// DefaultSpec merges the agent's launch env (AgentEnv) into the sandbox env after the host
// passthrough, and the corral marker is set last so the agent env cannot clobber it. The
// agent owns what goes in AgentEnv (e.g. claude's connectors kill switch — tested in
// internal/agents); here we pin only the merge mechanism.
func TestDefaultSpecMergesAgentEnv(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := DefaultSpec(DefaultParams{
		Home:       home,
		ProjectDir: proj,
		AgentEnv:   map[string]string{"ENABLE_CLAUDEAI_MCP_SERVERS": "false", SandboxEnvVar: "tampered"},
	})
	if got := spec.SetEnv["ENABLE_CLAUDEAI_MCP_SERVERS"]; got != "false" {
		t.Errorf("AgentEnv var must be merged into the sandbox env; got %q", got)
	}
	if got := spec.SetEnv[SandboxEnvVar]; got != "1" {
		t.Errorf("corral marker must win over AgentEnv (set last); got %q", got)
	}
	// Empty/nil AgentEnv contributes nothing.
	bare := DefaultSpec(DefaultParams{Home: home, ProjectDir: proj})
	if _, ok := bare.SetEnv["ENABLE_CLAUDEAI_MCP_SERVERS"]; ok {
		t.Error("with no AgentEnv the sandbox env must carry no agent vars")
	}
}

// The sandbox PATH must include ~/.local/bin (bound into the sandbox, where the
// user's tools and a native claude install live) so claude doesn't warn it's not
// on PATH and bare-name tool invocation works.
func TestDefaultSpecPathIncludesLocalBin(t *testing.T) {
	home := "/home/u"
	spec := DefaultSpec(DefaultParams{Home: home, ProjectDir: home + "/proj"})
	path := spec.SetEnv["PATH"]
	want := home + "/.local/bin"
	if !strings.HasPrefix(path, want+":") {
		t.Errorf("PATH = %q, want it to start with %q", path, want)
	}
}

// SandboxHome redirects the sandbox's $HOME (and the PATH ~/.local/bin prefix) to the
// private home, while the baseline $HOME token and USER/LOGNAME stay anchored to the
// real home — so baseline rules still allow the real host paths the home symlinks target,
// and a private home like ~/.cache/corral/home does not corrupt the operator identity.
func TestDefaultSpecSandboxHomeRedirect(t *testing.T) {
	realHome := "/home/u"
	fakeHome := "/home/u/.cache/corral/home"
	spec := DefaultSpec(DefaultParams{Home: realHome, SandboxHome: fakeHome, ProjectDir: realHome + "/proj"})

	if spec.SetEnv["HOME"] != fakeHome {
		t.Errorf("HOME = %q, want the sandbox (private) home %q", spec.SetEnv["HOME"], fakeHome)
	}
	if !strings.HasPrefix(spec.SetEnv["PATH"], fakeHome+"/.local/bin:") {
		t.Errorf("PATH = %q, want it to start with the sandbox home's .local/bin", spec.SetEnv["PATH"])
	}
	// Identity and baseline token must not follow the private home.
	if spec.SetEnv["USER"] != "u" || spec.SetEnv["LOGNAME"] != "u" {
		t.Errorf("USER/LOGNAME must stay derived from the real home (u); got %q/%q", spec.SetEnv["USER"], spec.SetEnv["LOGNAME"])
	}
	if spec.Tokens["HOME"] != realHome {
		t.Errorf("baseline HOME token = %q, want the REAL home %q (symlink targets must stay allowed)", spec.Tokens["HOME"], realHome)
	}

	// Default (no SandboxHome) keeps HOME == the real home.
	def := DefaultSpec(DefaultParams{Home: realHome, ProjectDir: realHome + "/proj"})
	if def.SetEnv["HOME"] != realHome {
		t.Errorf("without SandboxHome, HOME must default to the real home; got %q", def.SetEnv["HOME"])
	}
}

// The project (including a launch-from-$HOME scratch dir) is mounted at its own path
// and is the working directory — there is no in-sandbox remap, so the bwrap and macOS
// Seatbelt backends behave identically (Seatbelt has no bind-remap to honor a dst).
func TestDefaultSpecProjectMountedAtOwnPath(t *testing.T) {
	home := t.TempDir()
	scratch := filepath.Join(home, "scratch") // stand-in for a /tmp scratch dir
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	spec := DefaultSpec(DefaultParams{Home: home, ProjectDir: scratch})
	if spec.WorkDir != scratch {
		t.Errorf("WorkDir = %q, want the project's own path %q", spec.WorkDir, scratch)
	}
	var found bool
	for _, m := range spec.Mounts {
		if m.Src == scratch {
			found = true
			if m.Dst != "" && m.Dst != scratch {
				t.Errorf("project mount Dst = %q, want it at its own path (empty, or == src)", m.Dst)
			}
			if m.ReadOnly {
				t.Error("project mount must be read-write")
			}
		}
	}
	if !found {
		t.Errorf("project source %q must be mounted; got %v", scratch, spec.Mounts)
	}
}

func TestPrependBrewPath(t *testing.T) {
	base := "/usr/bin:/bin"
	cases := []struct {
		name     string
		hostPath string
		want     string
	}{
		{"both in host PATH", "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin", "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/bin:/bin"},
		{"neither in host PATH", "/usr/bin:/bin", base},
		{"only bin", "/foo:/opt/homebrew/bin:/usr/bin", "/opt/homebrew/bin:/usr/bin:/bin"},
		{"only sbin", "/opt/homebrew/sbin", "/opt/homebrew/sbin:/usr/bin:/bin"},
		{"empty host PATH", "", base},
		{"no partial match", "/opt/homebrew/binary:/usr/bin", base},
	}
	for _, c := range cases {
		if got := prependBrewPath(base, c.hostPath); got != c.want {
			t.Errorf("%s: prependBrewPath(_, %q) = %q, want %q", c.name, c.hostPath, got, c.want)
		}
	}
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

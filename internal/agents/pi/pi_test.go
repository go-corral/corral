package pi

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPiIdentity(t *testing.T) {
	a := New()
	if a.Name() != "pi" {
		t.Errorf("pi agent Name() = %q, want %q", a.Name(), "pi")
	}
	if !slices.Equal(a.Binaries(), []string{"pi"}) {
		t.Errorf("Binaries() = %v, want [pi] (first entry is also the exec fallback)", a.Binaries())
	}
}

// TestPiConfigDir pins the directory corral binds/write-protects: the ~/.pi umbrella by default
// (so sibling configs outside ~/.pi/agent survive), or the PI_CODING_AGENT_DIR override verbatim
// (trimmed; the user pins the layout). A whitespace-only override falls back to the default.
func TestPiConfigDir(t *testing.T) {
	const home = "/home/u"
	a := New()
	umbrella := filepath.Join(home, ".pi")
	tests := []struct {
		name string
		host map[string]string
		want string
	}{
		{"unset", nil, umbrella},
		{"empty", map[string]string{"PI_CODING_AGENT_DIR": ""}, umbrella},
		{"whitespace", map[string]string{"PI_CODING_AGENT_DIR": "   "}, umbrella},
		{"override", map[string]string{"PI_CODING_AGENT_DIR": "/custom/pi"}, "/custom/pi"},
		{"override trimmed", map[string]string{"PI_CODING_AGENT_DIR": "  /custom/pi  "}, "/custom/pi"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := a.ConfigDir(home, tt.host); got != tt.want {
				t.Errorf("ConfigDir(%q, %v) = %q, want %q", home, tt.host, got, tt.want)
			}
		})
	}
}

// TestPiExtensionsDirDecoupled pins the load-bearing decoupling: corral binds the ~/.pi umbrella
// (ConfigDir) but installs/discovers global extensions under ~/.pi/agent/extensions — where pi's
// loader actually looks. A naive "extensions under ConfigDir" would land at ~/.pi/extensions and
// the presence backstop would silently never load.
func TestPiExtensionsDirDecoupled(t *testing.T) {
	const home = "/home/u"
	p := agent{}
	if got, want := p.extensionsDir(home, nil), filepath.Join(home, ".pi", "agent", "extensions"); got != want {
		t.Errorf("extensionsDir = %q, want %q (under the agent dir, not the ~/.pi umbrella)", got, want)
	}
	// The umbrella bind (ConfigDir) must be a strict parent of the extensions dir.
	if cfg := p.ConfigDir(home, nil); cfg != filepath.Join(home, ".pi") {
		t.Errorf("ConfigDir = %q, want the ~/.pi umbrella", cfg)
	}
	// Override: extensions track the pinned agent dir.
	host := map[string]string{"PI_CODING_AGENT_DIR": "/custom/pi"}
	if got, want := p.extensionsDir(home, host), filepath.Join("/custom/pi", "extensions"); got != want {
		t.Errorf("extensionsDir(override) = %q, want %q", got, want)
	}
}

// TestPiLaunch pins pi's launch contribution: the embedded policy bridge wired for `-e`
// activation. PI_OFFLINE lives on Config.SandboxEnv (TestPiSandboxEnv); the binary-dir token is
// covered by spec.TestBinDir.
func TestPiLaunch(t *testing.T) {
	l := New().Launch()
	if len(l.ExtensionAsset) == 0 {
		t.Error("pi Launch must carry the embedded policy bridge (ExtensionAsset)")
	}
	if l.ExtensionName != "corral-policy.ts" || l.ExtensionFlag != "-e" {
		t.Errorf("pi extension wiring = name %q flag %q, want \"corral-policy.ts\"/\"-e\"", l.ExtensionName, l.ExtensionFlag)
	}
}

// TestPiSandboxEnv pins PI_OFFLINE=1, which silences the startup update checks that cannot work
// behind the masked ~/.ssh.
func TestPiSandboxEnv(t *testing.T) {
	env := Config{}.SandboxEnv()
	if env["PI_OFFLINE"] != "1" || len(env) != 1 {
		t.Errorf("pi SandboxEnv = %v, want only PI_OFFLINE=1", env)
	}
}

func TestPiBannerFields(t *testing.T) {
	if f := (Config{}).BannerFields(); len(f) != 0 {
		t.Errorf("pi BannerFields = %+v, want none", f)
	}
}

// TestPiTempEnvAliases pins that pi declares no private temp var, so a temp-isolating backend no
// longer hardcodes a claude-specific var for every agent.
func TestPiTempEnvAliases(t *testing.T) {
	if got := New().Launch().TempEnvAliases; len(got) != 0 {
		t.Errorf("pi TempEnvAliases = %v, want none", got)
	}
}

// TestPiReservedEnv pins pi's reserved-env contribution: config reserves the config/session
// relocators from env.set so a stray entry can't repoint pi at an unbound dir.
func TestPiReservedEnv(t *testing.T) {
	got := New().ReservedEnv()
	for _, want := range []string{"PI_CODING_AGENT_DIR", "PI_CODING_AGENT_SESSION_DIR"} {
		if !slices.Contains(got, want) {
			t.Errorf("pi.ReservedEnv() = %v, want it to reserve %q", got, want)
		}
	}
}

// TestPiConfigPaths pins that pi keeps everything under ~/.pi and contributes no out-of-config-dir
// grant — the cross-agent invariant that keeps the embedded baseline agent-neutral.
func TestPiConfigPaths(t *testing.T) {
	if got := New().ConfigPaths(); len(got) != 0 {
		t.Errorf("pi ConfigPaths = %v, want none (everything lives under ~/.pi)", got)
	}
}

// TestPiPresenceBackstopExtension pins the presence backstop: pi contributes exactly one global
// extension (corral-presence.ts, non-empty) that `corral sync pi` installs.
func TestPiPresenceBackstopExtension(t *testing.T) {
	exts := agent{}.globalExtensions()
	if len(exts) != 1 || exts[0].Name != "corral-presence.ts" || len(exts[0].Content) == 0 {
		t.Errorf("pi globalExtensions() = %+v, want one non-empty corral-presence.ts", exts)
	}
}

// TestPiFootprint pins pi's static enforcement footprint: the ".pi" marker and the global
// extensions subtree (~/.pi/agent/extensions), whose write/delete the hook gates — a planted global
// extension runs host-side on the next bare `pi`. pi has no protected files (its bridge is bound
// read-only; account/state under ~/.pi stays writable).
func TestPiFootprint(t *testing.T) {
	fp := New().Footprint()
	if fp.Dir != ".pi" || fp.DirReason != "pi's config directory" {
		t.Errorf("Footprint dir = %q/%q, want .pi / pi's config directory", fp.Dir, fp.DirReason)
	}
	if len(fp.ProtectedFiles) != 0 {
		t.Errorf("ProtectedFiles = %v, want none (bridge is read-only; state stays writable)", fp.ProtectedFiles)
	}
	for _, key := range []string{"agent/extensions", "extensions"} { // default umbrella layout + PI_CODING_AGENT_DIR relocation
		if got := fp.ProtectedDirs[key]; got != "pi's global extensions directory" {
			t.Errorf("ProtectedDirs[%s] = %q, want pi's global extensions directory", key, got)
		}
	}
	if len(fp.ProtectedDirs) != 2 {
		t.Errorf("ProtectedDirs = %v, want exactly the two extensions-layout keys", fp.ProtectedDirs)
	}
}

// containsLine reports whether any line contains sub. Shared by this package's report assertions.
func containsLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

package config

import (
	"path/filepath"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// reservedEnvNames is a literal copy of corral's internal env markers because config must
// not import sandbox in non-test code. This drift-guard pins the literals to the real
// sandbox constants so a rename there can't silently let env.set claim a control var.
// (A test file can import sandbox: sandbox does not import config, so there is no cycle.)
func TestReservedEnvNamesMatchSandboxConstants(t *testing.T) {
	for _, name := range []string{sandbox.SandboxEnvVar, sandbox.GlobalConfigEnvVar, sandbox.AgentEnvVar, sandbox.BinEnvVar, sandbox.ProviderNotesEnvVar, sandbox.BackendNotesEnvVar, sandbox.DisableHooksEnvVar} {
		if !reservedEnvNames[name] {
			t.Errorf("reservedEnvNames is missing the sandbox marker %q — env.set could set it", name)
		}
	}
	// The presence acknowledgment is deliberately not reserved: it is user-set, silences a warning, and
	// nothing else, and no corral decision depends on it. Pin that so it is never "tidied" into
	// the reserved set, which would break setting it in a foreign sandbox's own profile.
	if reservedEnvNames[sandbox.PresenceAckEnvVar] {
		t.Errorf("%q must stay UNreserved (user-set, warning-only)", sandbox.PresenceAckEnvVar)
	}
	// The kill switch must never be forwarded into a sandbox by default either: the hook ignores
	// it there, but a passthrough entry would still be a confusing half-signal.
	for _, name := range defaultPassthroughNames(t) {
		if name == sandbox.DisableHooksEnvVar {
			t.Errorf("%q must not be in the default env passthrough", name)
		}
	}
	// The connector kill switch and the phone-home / attribution vars are owned by the
	// agents.claude knobs, not sandbox-exported constants; assert they stay reserved (unioned in
	// from the agent registry via AllReservedEnv) so env.set can't flip connectors on or undo the
	// privacy hardening out of band.
	for _, name := range []string{
		"ENABLE_CLAUDEAI_MCP_SERVERS",
		"DISABLE_TELEMETRY",
		"DISABLE_ERROR_REPORTING",
		"CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY",
		"CLAUDE_CODE_ATTRIBUTION_HEADER",
	} {
		if !reservedEnvNames[name] {
			t.Errorf("reservedEnvNames must keep %q reserved", name)
		}
	}
	// pi's config/session relocators must stay reserved so env.set cannot point pi at a dir
	// corral does not bind/write-protect (agents.pi.ConfigDir reads PI_CODING_AGENT_DIR).
	// CORRAL_BIN is pinned against sandbox.BinEnvVar in the constants loop above.
	for _, name := range []string{"PI_CODING_AGENT_DIR", "PI_CODING_AGENT_SESSION_DIR"} {
		if !reservedEnvNames[name] {
			t.Errorf("reservedEnvNames must keep %q reserved", name)
		}
	}
}

// defaultPassthroughNames returns the env passthrough list from the built-in defaults alone —
// empty temp dirs for home and project so no global/repo layer can contribute.
func defaultPassthroughNames(t *testing.T) []string {
	t.Helper()
	dir := t.TempDir()
	cfg, _, err := Load(LoadOptions{Home: dir, GlobalPath: filepath.Join(dir, "absent.yml"), ProjectDir: dir})
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	return cfg.Providers.Env.Passthrough
}

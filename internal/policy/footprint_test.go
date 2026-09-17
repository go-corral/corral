package policy

import "testing"

// claudeFootprint / piFootprint mirror the production Footprint() of internal/agents/claude and
// internal/agents/pi. policy is a leaf and cannot import the agents tree, so these tests rebuild
// the same data the composition root (cli.agentFootprint) maps in; the reason strings are
// byte-identical to the reasons corral gates for the footprint.
func claudeFootprint() AgentFootprint {
	return AgentFootprint{
		Dir:       ".claude",
		DirReason: "Claude Code's config directory",
		ProtectedFiles: map[string]string{
			"settings.json":         "Claude Code's settings.json",
			"settings.local.json":   "Claude Code's settings.local.json",
			"managed-settings.json": "Claude Code's managed-settings.json",
		},
		ProtectedDirs: map[string]string{"hooks": "Claude Code's hooks directory"},
	}
}

func piFootprint() AgentFootprint {
	return AgentFootprint{
		Dir:       ".pi",
		DirReason: "pi's config directory",
		ProtectedDirs: map[string]string{
			"agent/extensions": "pi's global extensions directory",
			"extensions":       "pi's global extensions directory",
		},
	}
}

// allTestFootprints is every registered agent's footprint — the defense-in-depth static-scan input.
func allTestFootprints() []AgentFootprint { return []AgentFootprint{claudeFootprint(), piFootprint()} }

// TestSelfConfigMatchPiFootprint pins pi's self-protection: the whole ~/.pi dir and its
// global-extensions subtree are write/delete-gated (a planted global extension executes host-side
// on the next bare `pi` run), pi account/state under ~/.pi stays writable, and — cross-agent
// defense-in-depth — a path carrying the ".pi" segment is still gated while Claude is active.
func TestSelfConfigMatchPiFootprint(t *testing.T) {
	piActive := selfProtect{configDir: "/home/u/.pi", footprint: piFootprint(), allFootprints: allTestFootprints()}
	deny := []string{
		"/home/u/.pi",                                     // the config dir itself (rm target)
		"/home/u/.pi/agent",                               // intermediate parent — deleting it takes extensions with it
		"/home/u/.pi/agent/extensions",                    // the global-extensions subtree root
		"/home/u/.pi/agent/extensions/corral-presence.ts", // a planted/edited extension
	}
	for _, p := range deny {
		if _, ok := selfConfigMatch(p, piActive); !ok {
			t.Errorf("selfConfigMatch(%q) with pi active should match", p)
		}
	}
	allow := []string{
		"/home/u/.pi/agent/sessions/x.json", // session state — must remain writable
		"/home/u/.pi/config.toml",           // pi config/account state stays writable
	}
	for _, p := range allow {
		if reason, ok := selfConfigMatch(p, piActive); ok {
			t.Errorf("selfConfigMatch(%q) must NOT match (got %q) — pi state stays writable", p, reason)
		}
	}
	// With Claude active, pi's footprint is still enforced via the static allFootprints scan: one
	// agent's session must not be able to plant an extension that escalates on the next `pi` run.
	claudeActive := selfProtect{configDir: "/home/u/.claude", footprint: claudeFootprint(), allFootprints: allTestFootprints()}
	for _, p := range []string{"/home/u/.pi", "/home/u/.pi/agent", "/home/u/.pi/agent/extensions/evil.ts"} {
		if _, ok := selfConfigMatch(p, claudeActive); !ok {
			t.Errorf("selfConfigMatch(%q) with claude active must match pi's footprint (cross-agent defense-in-depth)", p)
		}
	}

	// A PI_CODING_AGENT_DIR relocation makes the config dir the agent dir itself, so the
	// extensions subtree sits directly beneath it — the "extensions" footprint key gates it
	// there. The static ".pi" segment scan cannot see a custom-named dir, so the anchored
	// check must carry this alone; pi state under the relocated dir stays writable.
	relocated := selfProtect{configDir: "/custom/pidir", footprint: piFootprint(), allFootprints: allTestFootprints()}
	for _, p := range []string{"/custom/pidir", "/custom/pidir/extensions", "/custom/pidir/extensions/evil.ts"} {
		if _, ok := selfConfigMatch(p, relocated); !ok {
			t.Errorf("selfConfigMatch(%q) with relocated pi config dir should match", p)
		}
	}
	if reason, ok := selfConfigMatch("/custom/pidir/sessions/x.json", relocated); ok {
		t.Errorf("relocated pi session state must stay writable (got %q)", reason)
	}
}

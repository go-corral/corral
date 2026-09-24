// Package pi is the adapter for the pi coding agent (github.com/earendil-works/pi). pi ships
// no sandbox of its own, so corral's bwrap/Seatbelt is pi's entire isolation layer; policy
// enforcement rides an in-process extension bridge the launcher activates per session.
package pi

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/agents/spec"
	"github.com/go-corral/corral/internal/health"
)

type agent struct{}

func New() spec.Agent { return agent{} }

var _ spec.Agent = agent{}

func (agent) Name() string       { return "pi" }
func (agent) Binaries() []string { return []string{"pi"} }

func (agent) ConfigDir(home string, host map[string]string) string {
	if d := strings.TrimSpace(host["PI_CODING_AGENT_DIR"]); d != "" {
		return d
	}
	return filepath.Join(home, ".pi")
}

func (agent) agentDir(home string, host map[string]string) string {
	if d := strings.TrimSpace(host["PI_CODING_AGENT_DIR"]); d != "" {
		return d
	}
	return filepath.Join(home, ".pi", "agent")
}

func (p agent) extensionsDir(home string, host map[string]string) string {
	return filepath.Join(p.agentDir(home, host), "extensions")
}

func (agent) Launch() spec.Launch {
	return spec.Launch{
		ExtensionAsset: bridgeSource,
		ExtensionName:  "corral-policy.ts",
		ExtensionFlag:  "-e",
	}
}

type globalExtension struct {
	Name    string
	Content []byte
}

// globalExtensions installs the presence backstop: a global pi extension that warns when pi
// runs outside corral. Inside corral it stays silent while the read-only bridge enforces policy.
func (agent) globalExtensions() []globalExtension {
	return []globalExtension{{Name: "corral-presence.ts", Content: presenceSource}}
}

func (agent) ConfigPaths() []spec.ConfigPath           { return nil }
func (agent) ProtectedPaths(configDir string) []string { return nil }

// Footprint is pi's static enforcement footprint: ~/.pi and the global extensions subtree
// ~/.pi/agent/extensions. The extensions subtree is keyed for both config-dir layouts: under
// the default umbrella ConfigDir (~/.pi) it sits at agent/extensions; under a
// PI_CODING_AGENT_DIR relocation the config dir is the agent dir, putting it at extensions.
func (agent) Footprint() spec.Footprint {
	return spec.Footprint{
		Dir:       ".pi",
		DirReason: "pi's config directory",
		ProtectedDirs: map[string]string{
			"agent/extensions": "pi's global extensions directory",
			"extensions":       "pi's global extensions directory",
		},
	}
}

func (agent) ReservedEnv() []string {
	return []string{"PI_CODING_AGENT_DIR", "PI_CODING_AGENT_SESSION_DIR"}
}

func (p agent) Doctor(in spec.StatusInput) []health.Check {
	bridge := health.Check{Label: "policy bridge", Value: fmt.Sprintf("embedded (%d bytes)", len(p.Launch().ExtensionAsset))}
	if len(p.Launch().ExtensionAsset) == 0 {
		bridge = health.Check{State: health.Fail, Label: "policy bridge", Value: "missing",
			Reason: "the embedded policy bridge is empty (corral build problem)"}
	}
	checks := []health.Check{bridge}

	extDir := p.extensionsDir(in.Home, in.Host)
	staleByPath := map[string]bool{}
	for _, pe := range pendingExtensions(p.globalExtensions(), extDir) {
		staleByPath[pe.path] = pe.stale
	}
	for _, e := range p.globalExtensions() {
		dst := filepath.Join(extDir, e.Name)
		c := health.Check{Label: "presence backstop", Value: "installed"}
		if stale, pending := staleByPath[dst]; pending {
			c.State, c.Fix = health.Warn, "corral sync "+p.Name()
			c.Value, c.Reason = "not installed", fmt.Sprintf("it warns when %s runs without corral", p.Name())
			if stale {
				c.Value, c.Reason = "out of date", dst
			}
		}
		checks = append(checks, c)
	}
	return checks
}

type pendingExtension struct {
	content []byte
	path    string
	stale   bool
}

// pendingExtensions returns the global extensions whose installed copy is missing or
// content-stale. Best-effort: an unreadable file counts as missing.
func pendingExtensions(exts []globalExtension, extDir string) []pendingExtension {
	if len(exts) == 0 {
		return nil
	}
	var pending []pendingExtension
	for _, e := range exts {
		dst := filepath.Join(extDir, e.Name)
		switch cur, err := os.ReadFile(dst); {
		case err != nil:
			pending = append(pending, pendingExtension{content: e.Content, path: dst, stale: false})
		case !bytes.Equal(cur, e.Content):
			pending = append(pending, pendingExtension{content: e.Content, path: dst, stale: true})
		}
	}
	return pending
}

// Sync handles `corral sync pi`: installs the agent's global extensions (the presence
// backstop). When in.DryRun it reports what would change without writing. in.Remove runs the
// inverse.
func (p agent) Sync(in spec.SyncInput) (spec.SyncReport, error) {
	if in.Remove {
		return p.removeSync(in)
	}
	l := p.Launch()
	messages := []string{fmt.Sprintf(
		"%s enforces policy via an in-process bridge activated at `corral run` (%s %s <bridge>) — no settings file to sync.",
		p.Name(), p.Binaries()[0], l.ExtensionFlag)}

	if len(p.globalExtensions()) == 0 {
		return spec.SyncReport{Messages: messages}, nil
	}
	pending := pendingExtensions(p.globalExtensions(), p.extensionsDir(in.Home, in.Host))
	if len(pending) == 0 {
		return spec.SyncReport{Messages: append(messages, "presence backstop already up to date — no changes.")}, nil
	}
	if in.DryRun {
		for _, pe := range pending {
			messages = append(messages, fmt.Sprintf("would %s the presence backstop at %s (dry-run, not written)", verbInstall(pe.stale), pe.path))
		}
		return spec.SyncReport{Messages: messages, Changed: true}, nil
	}
	for _, pe := range pending {
		if err := os.MkdirAll(filepath.Dir(pe.path), 0o755); err != nil {
			return spec.SyncReport{}, fmt.Errorf("create extensions dir: %w", err)
		}
		if err := os.WriteFile(pe.path, pe.content, 0o644); err != nil {
			return spec.SyncReport{}, fmt.Errorf("install presence backstop: %w", err)
		}
		messages = append(messages, fmt.Sprintf("%s the presence backstop at %s", pastInstall(pe.stale), pe.path))
	}
	messages = append(messages, fmt.Sprintf("it warns when %s runs WITHOUT corral; delete that file to remove the warning.", p.Name()))
	return spec.SyncReport{Messages: messages, Changed: true}, nil
}

func (p agent) removeSync(in spec.SyncInput) (spec.SyncReport, error) {
	messages := []string{fmt.Sprintf(
		"%s's policy bridge is activated per session by `corral run` and needs no de-registration — only the global presence backstop persists between sessions.",
		p.Name())}

	extDir := p.extensionsDir(in.Home, in.Host)
	var installed []string
	for _, e := range p.globalExtensions() {
		dst := filepath.Join(extDir, e.Name)
		if _, err := os.Stat(dst); err == nil {
			installed = append(installed, dst)
		}
	}
	if len(installed) == 0 {
		return spec.SyncReport{Messages: append(messages, "presence backstop not installed — nothing to remove.")}, nil
	}
	if in.DryRun {
		for _, dst := range installed {
			messages = append(messages, fmt.Sprintf("would delete the presence backstop at %s (dry-run, not deleted)", dst))
		}
		return spec.SyncReport{Messages: messages, Changed: true}, nil
	}
	for _, dst := range installed {
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return spec.SyncReport{}, fmt.Errorf("remove presence backstop: %w", err)
		}
		messages = append(messages, fmt.Sprintf("deleted the presence backstop at %s", dst))
	}
	return spec.SyncReport{Messages: append(messages, fmt.Sprintf(
		"a bare `%s` outside corral is no longer flagged as unsandboxed; run `corral sync %s` to reinstall.", p.Name(), p.Name())), Changed: true}, nil
}

func (p agent) LaunchWarnings(in spec.StatusInput) []health.Check {
	pending := pendingExtensions(p.globalExtensions(), p.extensionsDir(in.Home, in.Host))
	if len(pending) == 0 {
		return nil
	}
	desc := "presence backstop out of date"
	for _, pe := range pending {
		if !pe.stale {
			desc = "presence backstop not installed"
			break
		}
	}
	return []health.Check{{State: health.Warn, Label: p.Name(), Value: desc,
		Reason: fmt.Sprintf("a bare %s outside corral is not flagged as unsandboxed; this session is protected", p.Name()),
		Fix:    "corral sync " + p.Name()}}
}

func verbInstall(stale bool) string {
	if stale {
		return "update"
	}
	return "install"
}

func pastInstall(stale bool) string {
	if stale {
		return "updated"
	}
	return "installed"
}

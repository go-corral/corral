// Package opencode is the adapter for the opencode coding agent (opencode.ai, 2.x). opencode
// ships no sandbox of its own, so corral's bwrap/Seatbelt is its isolation layer; policy
// enforcement rides a plugin that the launcher activates per session through
// OPENCODE_CONFIG_CONTENT and that talks to the sidecar directly.
package opencode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-corral/corral/internal/agents/spec"
	"github.com/go-corral/corral/internal/health"
)

type agent struct{}

func New() spec.Agent { return agent{} }

var _ spec.Agent = agent{}

const (
	configContentEnv = "OPENCODE_CONFIG_CONTENT"
	configDirEnv     = "OPENCODE_CONFIG_DIR"
	backstopName     = "corral-presence.js"
)

func (agent) Name() string       { return "opencode" }
func (agent) Binaries() []string { return []string{"opencode"} }

func (agent) ConfigDir(home string, host map[string]string) string {
	if d := strings.TrimSpace(host[configDirEnv]); d != "" {
		return d
	}
	return filepath.Join(home, ".config", "opencode")
}

func (agent) Launch() spec.Launch {
	return spec.Launch{
		ExtensionAsset: policySource,
		ExtensionName:  "opencode-policy/index.js",
		ExtensionEnv:   extensionEnv,
		Args:           launchArgs,
	}
}

// extensionEnv activates the policy plugin through an inline config whose plugins list names the
// plugin directory (opencode drops an absolute file path). A host value is merged as strict JSON:
// opencode drops a document it cannot parse, which would leave the session without the plugin.
func extensionEnv(path string, host map[string]string) (map[string]string, error) {
	dir, err := json.Marshal(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	doc := map[string]json.RawMessage{}
	if v := host[configContentEnv]; strings.TrimSpace(v) != "" {
		err := json.Unmarshal([]byte(v), &doc)
		var syntax *json.SyntaxError
		switch {
		case errors.As(err, &syntax):
			return nil, fmt.Errorf("%s is not valid JSON (%w); write strict JSON without comments or move the value to an opencode.json file", configContentEnv, err)
		case err != nil || doc == nil:
			return nil, fmt.Errorf("%s is not a JSON object; write a JSON object or move the value to an opencode.json file", configContentEnv)
		}
	}
	var plugins []json.RawMessage
	if raw, ok := doc["plugins"]; ok {
		if err := json.Unmarshal(raw, &plugins); err != nil {
			return nil, fmt.Errorf("%s: \"plugins\" is not an array; write a JSON array or move the value to an opencode.json file", configContentEnv)
		}
	}
	if doc["plugins"], err = json.Marshal(append(plugins, dir)); err != nil {
		return nil, err
	}
	out, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return map[string]string{configContentEnv: string(out)}, nil
}

// launchArgs adds --standalone so opencode starts its own server inside the sandbox instead of
// sending work to the shared background service, which runs outside it without the plugin.
func launchArgs(config, user []string) ([]string, error) {
	all := slices.Concat(config, user)
	for _, a := range all {
		if a == "--server" || strings.HasPrefix(a, "--server=") {
			return nil, errors.New("--server sends work to a server outside the sandbox; remove it")
		}
	}
	sep := slices.Index(all, "--")
	if sep < 0 {
		sep = len(all)
	}
	for i, a := range all[:sep] {
		off := a == "--no-standalone" || strings.HasPrefix(a, "--standalone=")
		if a == "--standalone" && i+1 < sep {
			switch strings.ToLower(all[i+1]) {
			case "false", "no", "off", "0":
				off, a = true, a+" "+all[i+1]
			}
		}
		if off {
			return nil, errors.New(a + " can start opencode on the shared background service outside the sandbox; remove it")
		}
	}
	if (len(user) > 0 && user[0] == "acp") || slices.Contains(all[:sep], "--standalone") {
		return all, nil
	}
	return slices.Insert(all, sep, "--standalone"), nil
}

func (agent) ConfigPaths() []spec.ConfigPath {
	return []spec.ConfigPath{
		{
			Path:        "$HOME/.local/share/opencode",
			Description: "opencode sessions database, credentials, and logs",
			Writeable:   true,
			Optional:    true,
		},
		{
			Path:        "$HOME/.opencode/bin",
			Description: "opencode installer binary and shim; read-only",
			Optional:    true,
		},
	}
}

func (agent) ProtectedPaths(configDir string) []string { return nil }

func (agent) Footprint() spec.Footprint {
	return spec.Footprint{
		Dir:        ".config/opencode",
		DirReason:  "opencode's config directory",
		ProjectDir: ".opencode",
		ProtectedFiles: map[string]string{
			"opencode.json":  "opencode's config file",
			"opencode.jsonc": "opencode's config file",
			"cli.json":       "opencode's CLI settings",
			"service.json":   "opencode's background service settings",
		},
		ProtectedDirs: map[string]string{
			"plugin":  "opencode's plugins directory",
			"plugins": "opencode's plugins directory",
		},
		ProtectedNames: []string{"opencode.json", "opencode.jsonc"},
	}
}

func (agent) ReservedEnv() []string { return []string{configContentEnv, configDirEnv} }

func (a agent) backstop(in spec.StatusInput) string {
	return filepath.Join(a.ConfigDir(in.Home, in.Host), "plugins", backstopName)
}

// backstopState reports the file at path: "" when current, "missing", or "stale".
func backstopState(path string) string {
	cur, err := os.ReadFile(path)
	switch {
	case err != nil:
		return "missing"
	case !bytes.Equal(cur, presenceSource):
		return "stale"
	}
	return ""
}

func (a agent) Doctor(in spec.StatusInput) []health.Check {
	plugin := health.Check{Label: "policy plugin", Value: fmt.Sprintf("embedded (%d bytes)", len(policySource))}
	if len(policySource) == 0 {
		plugin = health.Check{State: health.Fail, Label: "policy plugin", Value: "missing",
			Reason: "the embedded policy plugin is empty (corral build problem)"}
	}
	path := a.backstop(in)
	c := health.Check{Label: "presence backstop", Value: "installed"}
	switch backstopState(path) {
	case "missing":
		c.State, c.Fix = health.Warn, "corral sync opencode"
		c.Value, c.Reason = "not installed", "it warns when opencode runs without corral"
	case "stale":
		c.State, c.Fix = health.Warn, "corral sync opencode"
		c.Value, c.Reason = "out of date", path
	}
	return []health.Check{plugin, c}
}

// Sync installs the presence backstop. With in.DryRun it reports without writing; in.Remove
// runs the inverse.
func (a agent) Sync(in spec.SyncInput) (spec.SyncReport, error) {
	if in.Remove {
		return a.removeSync(in)
	}
	messages := []string{"opencode enforces policy via a plugin activated at `corral run` (OPENCODE_CONFIG_CONTENT), so sync does not install it."}
	path := a.backstop(spec.StatusInput{Home: in.Home, Host: in.Host})
	state := backstopState(path)
	if state == "" {
		return spec.SyncReport{Messages: append(messages, "presence backstop already up to date — no changes.")}, nil
	}
	verb, past := "install", "installed"
	if state == "stale" {
		verb, past = "update", "updated"
	}
	if in.DryRun {
		return spec.SyncReport{Messages: append(messages, fmt.Sprintf("would %s the presence backstop at %s (dry-run, not written)", verb, path)), Changed: true}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return spec.SyncReport{}, fmt.Errorf("create plugins dir: %w", err)
	}
	if err := os.WriteFile(path, presenceSource, 0o644); err != nil {
		return spec.SyncReport{}, fmt.Errorf("install presence backstop: %w", err)
	}
	return spec.SyncReport{Messages: append(messages,
		fmt.Sprintf("%s the presence backstop at %s", past, path),
		"it warns when opencode runs WITHOUT corral; delete that file to remove the warning."), Changed: true}, nil
}

func (a agent) removeSync(in spec.SyncInput) (spec.SyncReport, error) {
	messages := []string{"opencode's policy plugin is activated per session by `corral run` and needs no de-registration — only the presence backstop persists between sessions."}
	path := a.backstop(spec.StatusInput{Home: in.Home, Host: in.Host})
	if _, err := os.Stat(path); err != nil {
		return spec.SyncReport{Messages: append(messages, "presence backstop not installed — nothing to remove.")}, nil
	}
	if in.DryRun {
		return spec.SyncReport{Messages: append(messages, fmt.Sprintf("would delete the presence backstop at %s (dry-run, not deleted)", path)), Changed: true}, nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return spec.SyncReport{}, fmt.Errorf("remove presence backstop: %w", err)
	}
	return spec.SyncReport{Messages: append(messages,
		fmt.Sprintf("deleted the presence backstop at %s", path),
		"a bare `opencode` outside corral is no longer flagged as unsandboxed; run `corral sync opencode` to reinstall."), Changed: true}, nil
}

func (a agent) LaunchWarnings(in spec.StatusInput) []health.Check {
	desc := "presence backstop out of date"
	switch backstopState(a.backstop(in)) {
	case "":
		return nil
	case "missing":
		desc = "presence backstop not installed"
	}
	return []health.Check{{State: health.Warn, Label: "opencode", Value: desc,
		Reason: "a bare opencode outside corral is not flagged as unsandboxed; this session is protected",
		Fix:    "corral sync opencode"}}
}

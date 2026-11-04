package opencode

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/agents/spec"
	"github.com/go-corral/corral/internal/health"
)

func TestOpencodeIdentity(t *testing.T) {
	a := New()
	if a.Name() != "opencode" || !slices.Equal(a.Binaries(), []string{"opencode"}) {
		t.Errorf("Name/Binaries = %q/%v, want opencode/[opencode]", a.Name(), a.Binaries())
	}
}

func TestOpencodeConfigDir(t *testing.T) {
	const home = "/home/u"
	def := filepath.Join(home, ".config", "opencode")
	for _, tt := range []struct {
		name string
		host map[string]string
		want string
	}{
		{"unset", nil, def},
		{"whitespace", map[string]string{"OPENCODE_CONFIG_DIR": "  "}, def},
		{"override trimmed", map[string]string{"OPENCODE_CONFIG_DIR": " /srv/oc "}, "/srv/oc"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := New().ConfigDir(home, tt.host); got != tt.want {
				t.Errorf("ConfigDir = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOpencodeReservedEnv(t *testing.T) {
	got := New().ReservedEnv()
	if !slices.Contains(got, "OPENCODE_CONFIG_CONTENT") || !slices.Contains(got, "OPENCODE_CONFIG_DIR") || len(got) != 2 {
		t.Errorf("ReservedEnv = %v, want OPENCODE_CONFIG_CONTENT and OPENCODE_CONFIG_DIR", got)
	}
}

func TestOpencodeSandboxEnv(t *testing.T) {
	env := Config{}.SandboxEnv()
	if env["OPENCODE_DISABLE_AUTOUPDATE"] != "1" || len(env) != 1 {
		t.Errorf("SandboxEnv = %v, want only OPENCODE_DISABLE_AUTOUPDATE=1", env)
	}
}

func TestOpencodeFootprint(t *testing.T) {
	fp := New().Footprint()
	if fp.Dir != ".config/opencode" || fp.ProjectDir != ".opencode" {
		t.Errorf("Dir/ProjectDir = %q/%q, want .config/opencode / .opencode", fp.Dir, fp.ProjectDir)
	}
	for _, f := range []string{"opencode.json", "opencode.jsonc", "cli.json", "service.json"} {
		if fp.ProtectedFiles[f] == "" {
			t.Errorf("ProtectedFiles misses %q: %v", f, fp.ProtectedFiles)
		}
	}
	for _, d := range []string{"plugin", "plugins"} {
		if fp.ProtectedDirs[d] == "" {
			t.Errorf("ProtectedDirs misses %q: %v", d, fp.ProtectedDirs)
		}
	}
	if len(fp.ProtectedFiles) != 4 || len(fp.ProtectedDirs) != 2 {
		t.Errorf("footprint maps = %v / %v, want 4 files and 2 dirs", fp.ProtectedFiles, fp.ProtectedDirs)
	}
	if !slices.Equal(fp.ProtectedNames, []string{"opencode.json", "opencode.jsonc"}) {
		t.Errorf("ProtectedNames = %v", fp.ProtectedNames)
	}
}

func TestOpencodeConfigPaths(t *testing.T) {
	got := New().ConfigPaths()
	if len(got) != 2 {
		t.Fatalf("ConfigPaths = %+v, want two grants", got)
	}
	data, bin := got[0], got[1]
	if data.Path != "$HOME/.local/share/opencode" || !data.Writeable || !data.Optional {
		t.Errorf("data grant = %+v, want rw optional", data)
	}
	if bin.Path != "$HOME/.opencode/bin" || bin.Writeable || !bin.Optional {
		t.Errorf("installer grant = %+v, want ro optional", bin)
	}
}

func TestOpencodeLaunch(t *testing.T) {
	l := New().Launch()
	if !bytes.Equal(l.ExtensionAsset, policySource) || len(l.ExtensionAsset) == 0 {
		t.Error("Launch must carry the embedded policy plugin")
	}
	if l.ExtensionName != "opencode-policy/index.js" || l.ExtensionFlag != "" {
		t.Errorf("extension wiring = name %q flag %q, want opencode-policy/index.js and no flag", l.ExtensionName, l.ExtensionFlag)
	}
	if l.ExtensionEnv == nil || l.Args == nil {
		t.Error("Launch must set ExtensionEnv and Args")
	}
}

func TestOpencodeExtensionEnv(t *testing.T) {
	const path = "/h/.cache/corral/opencode-policy/index.js"
	const dir = "/h/.cache/corral/opencode-policy"
	run := func(host string) (map[string]string, error) {
		return extensionEnv(path, map[string]string{"OPENCODE_CONFIG_CONTENT": host})
	}

	t.Run("blank host value", func(t *testing.T) {
		env, err := run("  ")
		want := map[string]string{"OPENCODE_CONFIG_CONTENT": `{"plugins":["` + dir + `"]}`}
		if err != nil || !maps.Equal(env, want) {
			t.Errorf("env = %v, %v; want %v", env, err, want)
		}
	})
	t.Run("merge", func(t *testing.T) {
		env, err := run(`{"model": "a/b", "plugin": ["x"], "plugins": ["/p"], "mcp": {"s": {"n": 1.50}}}`)
		if err != nil || len(env) != 1 {
			t.Fatalf("env = %v, %v; want one variable", env, err)
		}
		var doc map[string]json.RawMessage
		if err := json.Unmarshal([]byte(env["OPENCODE_CONFIG_CONTENT"]), &doc); err != nil {
			t.Fatalf("result is not JSON: %v", err)
		}
		if want := `["/p","` + dir + `"]`; string(doc["plugins"]) != want {
			t.Errorf("plugins = %s, want %s: the host entry then the plugin dir", doc["plugins"], want)
		}
		if string(doc["plugin"]) != `["x"]` || string(doc["model"]) != `"a/b"` || string(doc["mcp"]) != `{"s":{"n":1.50}}` {
			t.Errorf("other keys must keep their values (number text included): %v", doc)
		}
	})

	for _, tt := range []struct{ name, host, want string }{
		{"comment", "{\n// c\n\"model\": \"m\"}", "strict JSON"},
		{"array", `[1]`, "not a JSON object"},
		{"null", `null`, "not a JSON object"},
		{"plugins object", `{"plugins": {}}`, "not an array"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := run(tt.host)
			if err == nil {
				t.Fatal("want an error")
			}
			if !strings.Contains(err.Error(), "OPENCODE_CONFIG_CONTENT") || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "opencode.json") {
				t.Errorf("error = %q, want it to name OPENCODE_CONFIG_CONTENT, %q, and opencode.json", err, tt.want)
			}
		})
	}
}

func TestOpencodeLaunchArgs(t *testing.T) {
	for _, tt := range []struct {
		name         string
		config, user []string
		want         []string
	}{
		{"none", nil, nil, []string{"--standalone"}},
		{"config then user", []string{"--print-logs"}, []string{"run", "hello"}, []string{"--print-logs", "run", "hello", "--standalone"}},
		{"literal double dash", nil, []string{"run", "--", "--text"}, []string{"run", "--standalone", "--", "--text"}},
		{"double dash in config", []string{"--"}, []string{"x"}, []string{"--standalone", "--", "x"}},
		{"standalone after double dash", nil, []string{"run", "--", "--standalone"}, []string{"run", "--standalone", "--", "--standalone"}},
		{"standalone before double dash", nil, []string{"run", "--standalone", "--", "--standalone"}, []string{"run", "--standalone", "--", "--standalone"}},
		{"no-standalone after double dash", nil, []string{"run", "--", "--no-standalone"}, []string{"run", "--standalone", "--", "--no-standalone"}},
		{"standalone in config", []string{"--standalone"}, []string{"run"}, []string{"--standalone", "run"}},
		{"acp with config", []string{"--print-logs"}, []string{"acp", "--port", "1"}, []string{"--print-logs", "acp", "--port", "1"}},
		{"acp not first", nil, []string{"run", "acp"}, []string{"run", "acp", "--standalone"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := launchArgs(tt.config, tt.user)
			if err != nil || !slices.Equal(got, tt.want) {
				t.Errorf("launchArgs(%v, %v) = %v, %v; want %v", tt.config, tt.user, got, err, tt.want)
			}
		})
	}
}

func TestOpencodeLaunchArgsRejects(t *testing.T) {
	const server, standalone = "--server", "shared background service"
	for _, tt := range []struct {
		config, user []string
		want         string
	}{
		{nil, []string{"--server", "x"}, server},
		{nil, []string{"--server=x"}, server},
		{[]string{"--server", "x"}, nil, server},
		{nil, []string{"acp", "--server=x"}, server},
		{[]string{"--standalone"}, []string{"--server", "x"}, server},
		{nil, []string{"--no-standalone"}, standalone},
		{nil, []string{"--standalone=false"}, standalone},
		{[]string{"--no-standalone"}, []string{"run"}, standalone},
		{nil, []string{"--standalone", "--no-standalone"}, standalone},
		{nil, []string{"acp", "--no-standalone"}, standalone},
		{nil, []string{"run", "--standalone", "false", "hi"}, standalone},
		{nil, []string{"--standalone", "0"}, standalone},
		{[]string{"--standalone", "OFF"}, []string{"run"}, standalone},
	} {
		got, err := launchArgs(tt.config, tt.user)
		if err == nil || !strings.Contains(err.Error(), tt.want) || !strings.Contains(err.Error(), "remove it") || got != nil {
			t.Errorf("launchArgs(%v, %v) = %v, %v; want an error naming %q", tt.config, tt.user, got, err, tt.want)
		}
	}
}

func backstopPath(home string) string {
	return filepath.Join(home, ".config", "opencode", "plugins", "corral-presence.js")
}

func writeStaleBackstop(t *testing.T, home string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(backstopPath(home)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backstopPath(home), []byte("// outdated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOpencodeBackstopStatus(t *testing.T) {
	a := New()
	missing, stale, current := t.TempDir(), t.TempDir(), t.TempDir()
	writeStaleBackstop(t, stale)
	if _, err := a.Sync(spec.SyncInput{Home: current, Host: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, home string
		doctor     health.Check
		warning    string
	}{
		{"missing", missing, health.Check{State: health.Warn, Label: "presence backstop", Value: "not installed",
			Reason: "it warns when opencode runs without corral", Fix: "corral sync opencode"}, "presence backstop not installed"},
		{"stale", stale, health.Check{State: health.Warn, Label: "presence backstop", Value: "out of date",
			Reason: backstopPath(stale), Fix: "corral sync opencode"}, "presence backstop out of date"},
		{"current", current, health.Check{Label: "presence backstop", Value: "installed"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			in := spec.StatusInput{Home: tt.home, Host: map[string]string{}}
			got := a.Doctor(in)
			if len(got) != 2 {
				t.Fatalf("Doctor must return the plugin and backstop checks; got %+v", got)
			}
			if p := got[0]; p.State != health.OK || p.Label != "policy plugin" || !strings.HasPrefix(p.Value, "embedded (") || p.Fix != "" {
				t.Errorf("plugin check = %+v, want an embedded policy-plugin check", p)
			}
			if got[1] != tt.doctor {
				t.Errorf("backstop check = %+v, want %+v", got[1], tt.doctor)
			}
			w := a.LaunchWarnings(in)
			if tt.warning == "" {
				if len(w) != 0 {
					t.Errorf("LaunchWarnings = %v, want none", w)
				}
				return
			}
			if len(w) != 1 || w[0].Value != tt.warning || w[0].Fix != "corral sync opencode" || !strings.Contains(w[0].Reason, "this session is protected") {
				t.Errorf("LaunchWarnings = %v, want %q with the fix", w, tt.warning)
			}
		})
	}
}

func TestOpencodeDoctorEmbeddedPluginFails(t *testing.T) {
	orig := policySource
	t.Cleanup(func() { policySource = orig })
	policySource = nil
	got := New().Doctor(spec.StatusInput{Home: t.TempDir(), Host: map[string]string{}})[0]
	if got.State != health.Fail || got.Label != "policy plugin" {
		t.Errorf("empty embedded plugin: got %+v, want a failing policy-plugin check", got)
	}
}

func TestOpencodeSync(t *testing.T) {
	a := New()
	for _, tt := range []struct {
		name      string
		stale     bool
		dry, done string
	}{
		{"install", false, "would install", "installed"},
		{"update", true, "would update", "updated"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			dst := backstopPath(home)
			if tt.stale {
				writeStaleBackstop(t, home)
			}
			old, readErr := os.ReadFile(dst)
			in := spec.SyncInput{Home: home, Host: map[string]string{}}
			dry := in
			dry.DryRun = true

			rep, err := a.Sync(dry)
			if err != nil || !rep.Changed || !containsLine(rep.Messages, tt.dry+" the presence backstop at "+dst) {
				t.Fatalf("dry-run: %+v, %v; want %q and Changed", rep, err, tt.dry)
			}
			if readErr != nil {
				if _, err := os.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("dry-run must not create the backstop, stat err = %v", err)
				}
			} else if got, _ := os.ReadFile(dst); !bytes.Equal(got, old) {
				t.Errorf("dry-run must not write the backstop, got %q", got)
			}

			rep, err = a.Sync(in)
			if err != nil || !rep.Changed || !containsLine(rep.Messages, tt.done+" the presence backstop at "+dst) || !containsLine(rep.Messages, "not install it") {
				t.Fatalf("sync: %+v, %v; want %q with the path and the per-launch note", rep, err, tt.done)
			}
			if got, _ := os.ReadFile(dst); !bytes.Equal(got, presenceSource) {
				t.Errorf("written content differs from the embedded source (%d bytes)", len(got))
			}

			rep, err = a.Sync(in)
			if err != nil || rep.Changed || !containsLine(rep.Messages, "already up to date") {
				t.Errorf("second sync: %+v, %v; want up to date, not Changed", rep, err)
			}
			if rep, err = a.Sync(dry); err != nil || rep.Changed {
				t.Errorf("dry-run over a current file: %+v, %v; want not Changed", rep, err)
			}
		})
	}
}

func TestOpencodeSyncRelocatedConfigDir(t *testing.T) {
	home, dir := t.TempDir(), t.TempDir()
	host := map[string]string{"OPENCODE_CONFIG_DIR": dir}
	if _, err := New().Sync(spec.SyncInput{Home: home, Host: host}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "plugins", "corral-presence.js")); err != nil {
		t.Errorf("backstop must land in the relocated config dir: %v", err)
	}
	if _, err := os.Stat(backstopPath(home)); !os.IsNotExist(err) {
		t.Errorf("nothing may be written under the default dir (stat err = %v)", err)
	}
}

func TestOpencodeSyncRemove(t *testing.T) {
	home := t.TempDir()
	a := New()
	host := map[string]string{}
	dst := backstopPath(home)
	other := filepath.Join(filepath.Dir(dst), "mine.js")
	remove := spec.SyncInput{Home: home, Host: host, Remove: true}

	rep, err := a.Sync(remove)
	if err != nil || rep.Changed || !containsLine(rep.Messages, "not installed — nothing to remove") {
		t.Fatalf("nothing installed: %+v, %v", rep, err)
	}

	if _, err := a.Sync(spec.SyncInput{Home: home, Host: host}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	dry := remove
	dry.DryRun = true
	rep, err = a.Sync(dry)
	if err != nil || !rep.Changed || !containsLine(rep.Messages, "would delete the presence backstop") {
		t.Fatalf("dry-run removal: %+v, %v", rep, err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Errorf("dry-run removal must keep the file: %v", err)
	}

	rep, err = a.Sync(remove)
	if err != nil || !rep.Changed || !containsLine(rep.Messages, "deleted the presence backstop at "+dst) || !containsLine(rep.Messages, "no longer flagged") {
		t.Fatalf("removal: %+v, %v", rep, err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Errorf("backstop should be gone (stat err = %v)", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("removal must keep other files in the plugins dir: %v", err)
	}
	if rep, err = a.Sync(remove); err != nil || rep.Changed {
		t.Errorf("second removal: %+v, %v; want a no-op", rep, err)
	}
}

func containsLine(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

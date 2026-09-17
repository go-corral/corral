package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// stubAgentBinaries puts fake `claude` and `pi` executables on PATH so doctor reports both agents
// as available and calls their Doctor functions — independent of what is really installed (pi is
// absent in CI). Each stub answers --version so the version probe has something to print.
func stubAgentBinaries(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		script := "#!/bin/sh\necho \"" + name + " stub 9.9.9\"\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestDoctorEnumeratesAllAgents verifies `corral doctor` (no positional) reports every supported
// agent in one view: each available agent's binary plus its own enforcement-readiness — claude's
// settings.json status and pi's policy bridge + presence backstop.
func TestDoctorEnumeratesAllAgents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub uses /bin/sh")
	}
	home := t.TempDir()
	isolateConfigEnv(t, home, home)
	stubAgentBinaries(t, "claude", "pi")

	out := captureStdout(t, func() { cmdDoctor(nil, "test") })

	if !strings.Contains(out, "Agents:") {
		t.Errorf("doctor should have an Agents section:\n%s", out)
	}
	// Both agents present and resolved to the stubs (so available).
	for _, name := range []string{"claude:", "pi:"} {
		if !strings.Contains(out, name) {
			t.Errorf("doctor should list %s:\n%s", name, out)
		}
	}
	if !strings.Contains(out, "available") {
		t.Errorf("stubbed agents should report as available:\n%s", out)
	}
	// claude's enforcement detail: its settings.json hook status.
	if !strings.Contains(out, "settings") || !strings.Contains(out, "corral sync") {
		t.Errorf("doctor should report claude's settings.json status:\n%s", out)
	}
	// pi's enforcement detail: the policy bridge and the presence backstop.
	if !strings.Contains(out, "policy bridge") || !strings.Contains(out, "pi -e <bridge>") {
		t.Errorf("doctor should report pi's policy bridge:\n%s", out)
	}
	if !strings.Contains(out, "presence backstop") {
		t.Errorf("doctor should report pi's presence backstop:\n%s", out)
	}
}

// TestDoctorReportsUnavailableAgent verifies an agent whose binary is absent is reported as not
// installed, with no enforcement detail (corral can't gate tool calls for an agent that isn't
// there). PATH is set to an empty dir so neither agent resolves.
func TestDoctorReportsUnavailableAgent(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home)
	t.Setenv("PATH", t.TempDir())

	out := captureStdout(t, func() { cmdDoctor(nil, "test") })

	if !strings.Contains(out, "not installed") {
		t.Errorf("doctor should report an absent agent as not installed:\n%s", out)
	}
	// No enforcement detail for an absent agent.
	if strings.Contains(out, "policy bridge") {
		t.Errorf("doctor should not report enforcement detail for an absent agent:\n%s", out)
	}
}

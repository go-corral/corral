//go:build darwin

package seatbelt

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-corral/corral/internal/sandbox"
)

// TestGeneratedProfileBlocksOpenEscape is the end-to-end tripwire for the macOS sandbox-escape
// hardening: it asserts that a real `open` launched under the profile this backend generates does
// not reach launchd (the LaunchServices/launchd hand-off that otherwise spawns the target outside
// the sandbox — see profile). It is the only check that exercises the live Mach-service names, so if
// a future macOS moves them and the mach-lookup deny stops matching, this fails instead of silently
// re-opening the hole.
//
// darwin-only. It applies a nested Seatbelt profile, which macOS forbids
// from inside an existing sandbox, so it skips when run under corral itself or wherever sandbox-exec
// can't nest. A positive control (plain `(allow default)`) must launch, else the harness — not the
// deny — is broken and the test skips rather than false-passing.
func TestGeneratedProfileBlocksOpenEscape(t *testing.T) {
	if os.Getenv("CORRAL_SANDBOX") != "" {
		t.Skip("running inside corral: nested sandbox-exec is denied, cannot apply a test profile")
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not found")
	}

	dir := t.TempDir()
	proof := filepath.Join(dir, "launched")
	app := buildProbeApp(t, dir, proof)

	// Positive control: a bare allow-all profile must let `open` launch, proving the probe works.
	control := "(version 1)\n(allow default)\n"
	if !ranUnderProfile(t, control, app, proof) {
		t.Skip("control launch did not fire (LaunchServices/env issue, not the deny) — skipping")
	}

	// The real profile the backend generates carries the mach-lookup deny; `open` must be blocked.
	prof, err := New("", Config{}).profile(sandbox.SandboxSpec{})
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	if ranUnderProfile(t, prof, app, proof) {
		t.Fatal("`open` escaped: the generated profile did not block the LaunchServices/launchd hand-off " +
			"(a macOS version likely moved the coreservices Mach service names — update the mach-lookup deny in profile)")
	}
}

// Apple Events cross-app RCE (osascript telling an already-running app to run code) is deliberately
// not covered by a tripwire: it is not mach-lookup-blockable (the event travels peer-to-peer to the
// target's port, using no deniable global-name — confirmed on macOS 26 that neither the scoped deny
// nor strict deny-default stops it), so it is an accepted OS-layer residual documented in the threat
// model, not something the profile can assert against.

// buildProbeApp writes a minimal .app whose executable records that it launched into proof, and
// returns the bundle path. The app is unconfined only if launchd spawns it outside the profile.
func buildProbeApp(t *testing.T, dir, proof string) string {
	t.Helper()
	app := filepath.Join(dir, "Probe.app")
	macos := filepath.Join(app, "Contents", "MacOS")
	if err := os.MkdirAll(macos, 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Probe</string>
<key>CFBundleIdentifier</key><string>corral.seatbelt.escape.probe</string>
<key>CFBundlePackageType</key><string>APPL</string>
</dict></plist>
`
	if err := os.WriteFile(filepath.Join(app, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	exe := "#!/bin/sh\necho launched > " + proof + "\n"
	if err := os.WriteFile(filepath.Join(macos, "Probe"), []byte(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	return app
}

// ranUnderProfile runs `open app` under the given SBPL profile and reports whether the app launched
// (its proof file appeared within a short window). `open` detaches, so the proof file is the signal.
func ranUnderProfile(t *testing.T, profile, app, proof string) bool {
	t.Helper()
	_ = os.Remove(proof)
	f := filepath.Join(t.TempDir(), "profile.sb")
	if err := os.WriteFile(f, []byte(profile), 0o600); err != nil {
		t.Fatal(err)
	}
	// open exits immediately; ignore its status and poll for the app's proof.
	_ = exec.Command("sandbox-exec", "-f", f, "/usr/bin/open", app).Run()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(proof); err == nil {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

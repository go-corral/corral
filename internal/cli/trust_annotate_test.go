package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validate is not gated; it annotates each repo-config source with its approval state so
// the operator can inspect before approving.
func TestValidateAnnotatesUnapprovedConfig(t *testing.T) {
	trustRepo(t, "hostname: ok\n") // chdir into an unapproved repo

	var code int
	out := captureStdout(t, func() { code = cmdValidate(nil) })
	if code != 0 {
		t.Fatalf("validate must stay usable on unapproved config, got code %d", code)
	}
	if !strings.Contains(out, "not approved") {
		t.Errorf("validate should annotate the unapproved project source:\n%s", out)
	}
}

// Successful approvals stay quiet; changed bytes must still prompt a visible notice.
func TestValidateHidesApprovedConfig(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte("hostname: ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj) // pre-approves the written config

	out := captureStdout(t, func() { cmdValidate(nil) })
	if strings.Contains(out, "approved") {
		t.Errorf("an approved source should have no approval annotation:\n%s", out)
	}
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte("hostname: changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() { cmdValidate(nil) })
	if !strings.Contains(out, "changed since approval") {
		t.Errorf("changed source needs a re-approval notice:\n%s", out)
	}
}

// validate lists the session-hook executables with their trust state — attributed to the
// config path that names each, unreadable files called out instead of annotated.
func TestValidateAnnotatesHookExecs(t *testing.T) {
	home, proj := trustRepo(t, "providers:\n  hooks:\n    preStart:\n      10-up:\n        exec: ./up.sh\n      20-gone:\n        exec: ./gone.sh\n        optional: true\n")
	if err := os.WriteFile(filepath.Join(proj, "up.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = home

	out := captureStdout(t, func() { cmdValidate(nil) })
	if !strings.Contains(out, "Session-hook executables") {
		t.Fatalf("validate should list the hook executables:\n%s", out)
	}
	if !strings.Contains(out, "      providers.hooks.preStart.10-up\n") || !strings.Contains(out, "not approved") {
		t.Errorf("the readable executable should carry attribution and trust state:\n%s", out)
	}
	if !strings.Contains(out, "unreadable") {
		t.Errorf("the missing executable should be called out as unreadable:\n%s", out)
	}
}

// doctor annotates the detected config layers with their approval state too.
func TestDoctorAnnotatesTrustState(t *testing.T) {
	trustRepo(t, "hostname: ok\n") // chdir into an unapproved repo
	t.Setenv("SSH_AUTH_SOCK", "")  // deterministic provider availability

	out := captureStdout(t, func() { cmdDoctor(nil, "test") })
	if !strings.Contains(out, "not approved") {
		t.Errorf("doctor should annotate the unapproved config layer:\n%s", out)
	}
}

// run --dry-run is not gated, but it prints a note that a real run would prompt for
// approval of not-yet-approved repo config.
func TestRunDryRunAnnotatesUnapprovedConfig(t *testing.T) {
	home, proj := trustRepo(t, "hostname: ok\n")
	failIfMint(t)

	var code int
	stderr := captureStderr(t, func() {
		_ = captureStdout(t, func() {
			withStdin(t, "", func() {
				code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
			})
		})
	})
	if code != 0 {
		t.Fatalf("run --dry-run must not be gated, got code %d\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "not yet approved") {
		t.Errorf("run --dry-run should note the unapproved repo config:\n%s", stderr)
	}
}

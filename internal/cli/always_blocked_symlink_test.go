package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests for the two halves of the symlinked-always-blocked-path bypass. Both go
// through the real commands, because both fixes are launcher wiring: the resolving check
// is deliberately absent from config.Validate (the hook re-runs that on every tool call),
// so a unit test on the config alone would pass even if the launcher never called it.

// A grant that only reaches an always-blocked path through a symlink must be refused. The
// lexical check in config.Validate passes because /home/u/sshlink is not under /home/u/.ssh,
// but bwrap realpath()s bind sources before it pivots, so the resolved ~/.ssh would be
// mounted at the link's name, which the always-blocked tmpfs mask does not cover.
func TestRunRefusesSymlinkedGrantIntoAlwaysBlocked(t *testing.T) {
	home, proj := symlinkedGrantRepo(t)

	code, stderr := runCmd(t, "--dry-run", "--home", home, "--project", proj)
	if code == 0 {
		t.Fatalf("run accepted a grant that resolves into an always-blocked path (exit 0)\n%s", stderr)
	}
	if !strings.Contains(stderr, "always-blocked path") {
		t.Errorf("refusal did not name the always-blocked path:\n%s", stderr)
	}
	// The message must name the resolved path — the operator cannot see the problem from
	// the config alone, which only mentions the link.
	if !strings.Contains(stderr, filepath.Join(home, ".ssh")) {
		t.Errorf("refusal did not name the resolved always-blocked path it hit:\n%s", stderr)
	}
}

// `validate` must refuse exactly what `run` refuses; a green validate on a config that
// cannot launch is the failure mode this guards.
func TestValidateRefusesSymlinkedGrantIntoAlwaysBlocked(t *testing.T) {
	symlinkedGrantRepo(t)

	var code int
	stderr := captureStderr(t, func() {
		captureStdout(t, func() { code = cmdValidate(nil, "test") })
	})
	if code == 0 {
		t.Fatalf("validate green-lit a grant that resolves into an always-blocked path\n%s", stderr)
	}
	if !strings.Contains(stderr, "always-blocked path") {
		t.Errorf("validate refusal did not name the always-blocked path:\n%s", stderr)
	}
}

// symlinkedGrantRepo builds a home whose ~/sshlink points at a real ~/.ssh and grants the
// link via providers.paths.rw, then isolates the environment (chdir'ing into the project
// so `validate` discovers the same config `run` loads).
func symlinkedGrantRepo(t *testing.T) (home, proj string) {
	t.Helper()
	home = t.TempDir()
	proj = filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(home, "sshlink")); err != nil {
		t.Fatal(err)
	}
	writeCorralYML(t, proj, "providers:\n  paths:\n    rw: ["+filepath.Join(home, "sshlink")+"]\n")
	isolateConfigEnv(t, home, proj)
	return home, proj
}

// The other half: when an always-blocked dir is itself a host symlink (dotfiles-managed
// ~/.gnupg), the FS mask must also cover its real path. Otherwise an unrelated grant that
// contains the target (here ~/dotfiles) re-exposes the secrets under their real
// name, on both backends, and the in-sandbox hook cannot see it (there the always-blocked
// path is an empty tmpfs / denied, so no symlink is left to follow). The grant itself stays
// legal: masking the resolved path inside it is what makes an ancestor grant safe.
func TestRunMasksResolvedPathWhenAlwaysBlockedDirIsSymlink(t *testing.T) {
	// On macOS t.TempDir() sits under /var, a firmlink to /private/var; resolve the base so the
	// ancestor grant is not itself seen as a symlink into the always-blocked path. Linux: no-op.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(home, "proj")
	realGnupg := filepath.Join(home, "dotfiles", "gnupg")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(realGnupg, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realGnupg, filepath.Join(home, ".gnupg")); err != nil {
		t.Fatal(err)
	}
	writeCorralYML(t, proj, "providers:\n  paths:\n    rw: ["+filepath.Join(home, "dotfiles")+"]\n")
	isolateConfigEnv(t, home, proj)

	// t.TempDir can itself sit under a symlink (macOS /var/folders), and the emitted mask
	// carries the fully resolved path, so compare against the resolved form.
	wantMasked, err := filepath.EvalSymlinks(realGnupg)
	if err != nil {
		t.Fatal(err)
	}

	var code int
	out := captureStdout(t, func() {
		code = cmdRun([]string{"--dry-run", "--home", home, "--project", proj}, "dev")
	})
	if code != 0 {
		t.Fatalf("dry-run exit=%d (the ancestor grant must stay legal, only the always-blocked path is masked)\n%s", code, out)
	}
	if !strings.Contains(out, wantMasked) {
		t.Errorf("the symlinked always-blocked dir's real path %q is not masked; a grant covering it would re-expose the secrets:\n%s", wantMasked, out)
	}
	// No regression: the lexical always-blocked path stays masked too.
	if !strings.Contains(out, filepath.Join(home, ".gnupg")) {
		t.Errorf("the lexical always-blocked path is no longer masked:\n%s", out)
	}

	// The resolved mask is invisible to the hook's blocked-path view, so `validate` must
	// name it explicitly — otherwise a path carved out of the operator's own grant appears
	// in no diagnostic at all.
	vOut := captureStdout(t, func() {
		if c := cmdValidate(nil, "test"); c != 0 {
			t.Fatalf("validate exit=%d", c)
		}
	})
	if !strings.Contains(vOut, "    also masked     "+abbrevHome(wantMasked, home)+"\n") {
		t.Errorf("validate did not surface the resolved always-blocked mask %q:\n%s", wantMasked, vOut)
	}
}

func writeCorralYML(t *testing.T, proj, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

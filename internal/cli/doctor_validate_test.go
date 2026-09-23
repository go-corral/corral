package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// doctor = host/integration readiness. It must show the host availability of the enabled
// providers and must not re-print the effective policy (net / blocked paths / mounts) — that
// belongs to validate. This pins the separation so the overlap can't creep back.
func TestDoctorShowsAvailabilityNotPolicy(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// A config with policy details doctor must not echo, and two enabled providers.
	cfg := "providers:\n  block: {directories: [/data/vault]}\n  paths:\n    rw: [/srv/work]\n" +
		"  docker: {enabled: true, optional: true}\n  ssh: {enabled: true}\n"
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)
	t.Setenv("SSH_AUTH_SOCK", "") // deterministic: agent unavailable

	out := captureStdout(t, func() { cmdDoctor(nil, "test") })

	// ssh is required and unavailable, so it is the providers area's worst check.
	for _, want := range []string{
		"providers   ✗ ssh unavailable",
		"  ✗ ssh             unavailable\n",
		"required in config, so the launch stops here\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor must show provider host availability %q:\n%s", want, out)
		}
	}
	// Only enabled providers are checked.
	for _, name := range []string{"kubernetes", "gitlab"} {
		if strings.Contains(out, name) {
			t.Errorf("doctor checked the provider %q, which the config does not enable:\n%s", name, out)
		}
	}
	// Policy details are validate's job — doctor must not re-print them.
	for _, leak := range []string{"net:", "blocked paths:", "/data/vault", "/srv/work", "extra paths"} {
		if strings.Contains(out, leak) {
			t.Errorf("doctor leaked policy detail %q (belongs to validate):\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "corral validate") {
		t.Errorf("doctor should point to validate for policy:\n%s", out)
	}
}

// validate = config validity + effective policy, including which providers are
// *enabled* (intent). Host availability is doctor's job and must not appear here.
func TestValidateShowsEnabledProviders(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "providers:\n  docker: {enabled: true}\n  ssh: {enabled: true, optional: true}\n"
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	out := captureStdout(t, func() { cmdValidate(nil, "test") })

	for _, want := range []string{
		"  ● docker          docker daemon socket + ~/.docker\n                    setup error: abort launch\n",
		"  ● ssh ", "                    setup error: skip provider\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate providers section missing %q:\n%s", want, out)
		}
	}
}

// The home provider is default-on, so the bare default config already lists it.
func TestValidateShowsDefaultHomeProvider(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	out := captureStdout(t, func() { cmdValidate(nil, "test") })
	if !strings.Contains(out, "  ● home            private $HOME") {
		t.Errorf("default config should show the default-on home provider:\n%s", out)
	}
}

// validate prints the resolved private home: the default is keyed by hash, so this row is how
// a user finds the directory without starting a session.
func TestValidateShowsPrivateHomePath(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	out := captureStdout(t, func() { cmdValidate(nil, "test") })
	if !strings.Contains(out, "    home            ~/.cache/corral/home-") {
		t.Errorf("validate should print the resolved private home under %s:\n%s", home, out)
	}
}

// Disabled providers must not appear as configured grants, and the Home row says the private
// home is disabled instead of naming a directory.
func TestValidateNoProvidersEnabled(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte("providers:\n  home: {enabled: false}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	out := captureStdout(t, func() { cmdValidate(nil, "test") })
	if !strings.Contains(out, "    providers       none\n") || strings.Contains(out, "●") {
		t.Errorf("all providers off should show none:\n%s", out)
	}
	if !strings.Contains(out, "    home            host home (private home disabled)\n") {
		t.Errorf("home off should render the home row as disabled:\n%s", out)
	}
}

func TestCmdValidateDefaults(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() { code = cmdValidate(nil, "test") })
	if code != 0 {
		t.Fatalf("validate exit=%d", code)
	}
	if !strings.Contains(out, "✓ config valid") {
		t.Errorf("validate output: %s", out)
	}
}

func TestCmdValidateInvalid(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	// A project config with an unknown key must fail validation (fail-closed).
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte("nonsense_key: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	if code := cmdValidate(nil, "test"); code != 1 {
		t.Errorf("invalid config should exit 1, got %d", code)
	}
}

func TestCmdValidateListsPaths(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "providers:\n  block: {directories: [/data/vault]}\n  paths:\n    rw: [/srv/work]\n"
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() { code = cmdValidate([]string{"--list"}, "test") })
	if code != 0 {
		t.Fatalf("validate --list exit=%d", code)
	}
	for _, want := range []string{
		"    /data/vault     configured\n", "    ~/.ssh          always blocked\n",
		"    /srv/work                 rw   providers.paths.rw\n", "blocked     7 paths: 6 always blocked + 1 configured\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate --list missing %q in:\n%s", want, out)
		}
	}
}

// --profile is repeatable and -p is its shorthand, so both spellings stack in one command
// line: the sources roll-up gains a profile layer per selection and the title joins them in
// application order.
func TestCmdValidateStacksProfiles(t *testing.T) {
	home := t.TempDir()
	proj := filepath.Join(home, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "profiles:\n" +
		"  a:\n    providers:\n      paths:\n        ro: [/from-a]\n" +
		"  b:\n    hostname: b-host\n"
	if err := os.WriteFile(filepath.Join(proj, ".corral.yml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, proj)

	var code int
	out := captureStdout(t, func() { code = cmdValidate([]string{"--profile", "a", "-p", "b"}, "test") })
	if code != 0 {
		t.Fatalf("validate with stacked profiles exit=%d:\n%s", code, out)
	}
	for _, want := range []string{
		"sources     project approved, profile a, profile b\n",
		"   profile a, b   agent claude\n",
		"list with corral validate --list --profile a --profile b\n",
		"    /from-a                   ro   providers.paths.ro\n", "    hostname        b-host\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate missing %q in:\n%s", want, out)
		}
	}
}

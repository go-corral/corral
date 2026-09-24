package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestValidateReport(t *testing.T) {
	home, _ := trustRepo(t, "agents:\n  claude:\n    telemetry: true\nproviders:\n  paths:\n    ro: [~/reference/wiki, ~/reference/code, ~/reference/code/example]\n")
	failIfMint(t)
	t.Setenv("NO_COLOR", "1")
	out := captureStdout(t, func() {
		if code := cmdValidate(nil); code != 0 {
			t.Fatalf("validate exit=%d", code)
		}
	})
	// The default private home ends in a hash of the agent config dir; pin the row's shape only.
	got := regexp.MustCompile(`(?m)^(  Home       ~/\.cache/corral/home-)[0-9a-f]{8}$`).ReplaceAllString(out, "${1}<hash>")
	want := `corral validate
Configuration valid

Configuration
  Sources
    defaults
    project    ~/proj/.corral.yml
               not approved — will prompt on next run/sync

  Profiles   none

Sandbox
  Network    open
  Hostname   corral
  Home       ~/.cache/corral/home-<hash>

Agent · claude
  Connectors       off
  Telemetry        on
  Error reporting  off
  Feedback survey  off
  Agent view       off

Filesystem
  Blocked   6 paths: 6 always blocked + 0 configured
            List with corral validate --list

  Extra read-write   none

  Extra read-only · 3 grants · [grant] marks configured paths
    ~/reference/
    ├── code  [grant]
    │   └── example  [grant]
    └── wiki  [grant]

Environment
  Host passthrough allowlist
    TERM  COLORTERM  NO_COLOR  EDITOR  VISUAL  PAGER  TMPDIR  LANG
    CLAUDE_CONFIG_DIR  PI_CODING_AGENT_DIR  PI_CODING_AGENT_SESSION_DIR
  Other host variables are dropped.

Providers
  home
    Grants          private $HOME (allowed paths symlinked in; tool caches & state isolated)
    On setup error  abort launch
`
	if got != want {
		t.Errorf("report mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if created, _ := filepath.Glob(filepath.Join(home, ".cache", "corral", "home*")); len(created) > 0 {
		t.Errorf("validation must not create the private home: %v", created)
	}
}

func TestValidateWarningsPrecedeConfiguration(t *testing.T) {
	trustRepo(t, "providers:\n  docker: {enabled: true}\n")
	failIfMint(t)
	out := captureStdout(t, func() {
		if code := cmdValidate(nil); code != 0 {
			t.Fatalf("advisories must not invalidate config, exit=%d", code)
		}
	})
	warning := strings.Index(out, "\nWarnings\n")
	configuration := strings.Index(out, "\nConfiguration\n")
	if warning < 0 || configuration < warning || !strings.Contains(out[:configuration], "docker") {
		t.Fatalf("warnings must precede config and path inventories:\n%s", out)
	}
}

func TestValidateHookFailurePolicy(t *testing.T) {
	trustRepo(t, `providers:
  hooks:
    preStart:
      required: {exec: /bin/true}
      optional: {exec: /bin/true, optional: true}
    postEnd:
      report: {exec: /bin/true}
`)
	out := captureStdout(t, func() { cmdValidate(nil) })
	start := strings.Index(out, "  hooks\n")
	if start < 0 {
		t.Fatalf("missing hooks provider section:\n%s", out)
	}
	end := strings.Index(out[start:], "\n  home\n")
	if end < 0 {
		t.Fatalf("missing provider after hooks section:\n%s", out)
	}
	section := out[start : start+end]
	want := "Failure policy  required pre-start failures abort launch; optional pre-start failures continue; post-end failures warn"
	if !strings.Contains(section, want) || strings.Contains(section, "On setup error") {
		t.Errorf("hooks provider has the wrong failure policy:\n%s", section)
	}
}

func TestValidateQuotesAmbiguousProfileNames(t *testing.T) {
	const cfg = `profiles:
  "": {hostname: empty}
  none: {hostname: sentinel}
  "a, b": {hostname: comma}
`
	for _, tc := range []struct{ name, rendered string }{
		{"", `""`},
		{"none", `"none"`},
		{"a, b", `"a, b"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trustRepo(t, cfg)
			out := captureStdout(t, func() { cmdValidate([]string{"--profile", tc.name}) })
			if !strings.Contains(out, "    profile    "+tc.rendered+"\n") ||
				!strings.Contains(out, "  Profiles   "+tc.rendered+"\n") {
				t.Errorf("ambiguous profile name is not quoted as %q:\n%s", tc.rendered, out)
			}
		})
	}
}

func TestValidatePiReport(t *testing.T) {
	trustRepo(t, "agent: pi\nproviders:\n  home: {enabled: false}\n")
	out := captureStdout(t, func() { cmdValidate(nil) })
	for _, want := range []string{"Agent · pi\n  No agent-specific config toggles", "Home       host home (private home disabled)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"Connectors", "Telemetry", "Error reporting", "Feedback survey", "Agent view", "~/.cache/corral/home"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("unexpected %q:\n%s", unwanted, out)
		}
	}
}

func TestValidatePrivateHome(t *testing.T) {
	for _, tt := range []struct{ name, config, relocator, want string }{
		{"custom", "providers:\n  home: {path: ~/custom-home}\n", "", "~/custom-home"},
		{"relocated", "{}\n", "/accounts/claude", "~/.cache/corral/home-"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			trustRepo(t, tt.config)
			t.Setenv("CLAUDE_CONFIG_DIR", tt.relocator)
			out := captureStdout(t, func() { cmdValidate(nil) })
			if !strings.Contains(out, "Home       "+tt.want) {
				t.Errorf("missing resolved private home %q:\n%s", tt.want, out)
			}
		})
	}
}

func TestValidateListOnlyExpandsBlockedPaths(t *testing.T) {
	trustRepo(t, "providers:\n  block: {files: [~/private-file]}\n  paths:\n    rw: [~/code/work]\n    ro: [~/code/docs]\n")
	plain := captureStdout(t, func() { cmdValidate(nil) })
	listed := captureStdout(t, func() { cmdValidate([]string{"--list"}) })
	start, end := "  Blocked   ", "\n  Extra read-write"
	section := func(s string) string {
		t.Helper()
		i, j := strings.Index(s, start), strings.Index(s, end)
		if i < 0 || j < i {
			t.Fatalf("missing filesystem section:\n%s", s)
		}
		return s[:i] + s[j:]
	}
	if section(plain) != section(listed) {
		t.Errorf("--list changed more than the blocked-path inventory:\n%s\n%s", plain, listed)
	}
	if strings.Contains(plain, "~/.ssh") || strings.Contains(plain, "~/private-file") {
		t.Errorf("blocked inventory must require --list:\n%s", plain)
	}
	if !strings.Contains(listed, "~/private-file  [configured]") || !strings.Contains(listed, "~/.ssh  [always blocked]") {
		t.Errorf("missing blocked path attribution:\n%s", listed)
	}
	for _, want := range []string{"Extra read-write · 1 grant · [grant] marks configured paths\n    ~/code/work  [grant]", "Extra read-only · 1 grant · [grant] marks configured paths\n    ~/code/docs  [grant]"} {
		if !strings.Contains(plain, want) {
			t.Errorf("missing separate grant tree %q:\n%s", want, plain)
		}
	}
}

package cli

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/trust"
)

// validateFixture is a config with extra grants, docker, a profile, a changed repo layer, a
// session hook, and a resolved always-blocked mask.
func validateFixture() validateInput {
	cfg := &config.Config{Net: "open", Hostname: "corral"}
	cfg.Providers.Paths.RW = []string{"/home/u/work/cache"}
	cfg.Providers.Paths.RO = []string{"/usr/share/doc", "/etc/ssl", "/home/u/p/.git"}
	cfg.Providers.Docker.Enabled = true
	cfg.Providers.Env.Passthrough = []string{"TERM", "COLORTERM", "NO_COLOR", "EDITOR", "VISUAL", "PAGER", "TMPDIR",
		"LANG", "CLAUDE_CONFIG_DIR", "PI_CODING_AGENT_DIR", "PI_CODING_AGENT_SESSION_DIR"}
	return validateInput{
		version:  "0.21.0",
		profiles: []string{"k8s"},
		cfg:      cfg,
		sources: []config.Source{
			{Kind: "defaults"}, {Kind: "global", Path: "/home/u/.config/corral/config.yml"},
			{Kind: "project", Path: "/home/u/p/.corral.yml"}, {Kind: "profile", Path: "k8s"},
		},
		states:   map[string]trust.State{"/home/u/p/.corral.yml": trust.StateChanged},
		home:     "/home/u",
		wd:       "/home/u/p",
		privHome: "/home/u/.cache/corral/home-1a2b3c4d",
		extras:   []string{"/home/u/dotfiles/ssh"},
		execs:    hookExecs{attr: map[string]string{"/home/u/bin/up": "providers.hooks.preStart.10-up"}},
		warnings: []health.Check{
			{State: health.Warn, Label: "docker", Value: "grants root-equivalent host access",
				Reason: "a sandboxed process can mount the host filesystem"},
			{State: health.Warn, Label: "project", Value: "changed since approval",
				Reason: "/home/u/p/.corral.yml; corral asks again on the next run or sync", Fix: "corral run"},
		},
	}
}

func renderValidate(c report.Style, v validateInput) string {
	var b strings.Builder
	writeValidate(&b, c, v)
	return b.String()
}

// The approved layout: the verdict and roll-up beside the mark, then the warnings, the
// settings, and the path grants.
func TestWriteValidateLayout(t *testing.T) {
	want := `
  ████████████  corral v0.21.0   profile k8s   agent claude
  █          █  ✓ config valid  ·  3 sources  ·  2 warnings
  █  ████  █
  █  ████  █    sources     global, project changed, profile k8s
  █          █  writable    ~/work/cache
  ████████████  read-only   /usr/share/doc /etc/ssl ~/p/.git
                blocked     6 paths: 6 always blocked + 0 configured
                            list with corral validate --list --profile k8s

warnings ─────────────────────────────────────────────────────────
  ! docker          grants root-equivalent host access
                    a sandboxed process can mount the host filesystem
  ! project         changed since approval
                    ~/p/.corral.yml; corral asks again on the next run or sync
                    → corral run
settings ─────────────────────────────────────────────────────────
    global          ~/.config/corral/config.yml
    project         ~/p/.corral.yml
                    changed since approval
    home            ~/.cache/corral/home-1a2b3c4d
    network         open
    hostname        corral
    connectors      off
    telemetry       off
    error reporting off
    feedback survey off
    attribution header off
    also masked     ~/dotfiles/ssh
                    real paths of symlinked always-blocked directories
    env             TERM COLORTERM NO_COLOR EDITOR VISUAL PAGER TMPDIR LANG
                    CLAUDE_CONFIG_DIR PI_CODING_AGENT_DIR
                    PI_CODING_AGENT_SESSION_DIR
                    other host variables are dropped
    hook exec       ~/bin/up
                    providers.hooks.preStart.10-up
  ● docker          docker daemon socket + ~/.docker
                    setup error: abort launch
path grants ──────────────────────────────────────────────────────
    /
    ├── etc/ssl               ro   providers.paths.ro
    └── usr/share/doc         ro   providers.paths.ro
    ~
    ├── p                     rw   project
    │   └── .git              rw   providers.paths.ro (no effect)
    └── work/cache            rw   providers.paths.rw

Config only. Run corral doctor to check this host.
`
	if got := renderValidate(report.NewStyle(false, false), validateFixture()); got != want {
		t.Errorf("report =\n%s\nwant\n%s", got, want)
	}
}

// With ASCII-only data, the ASCII form is ASCII only, and the layout lines fit LineMax.
func TestWriteValidateASCII(t *testing.T) {
	v := validateFixture()
	v.list = true
	for _, c := range []report.Style{report.NewStyle(false, false), report.NewStyle(false, true)} {
		out := renderValidate(c, v)
		for _, ln := range strings.Split(out, "\n") {
			if n := utf8.RuneCountInString(ln); n > report.LineMax {
				t.Errorf("ascii=%t: line is %d columns, want at most %d: %q", c.ASCII, n, report.LineMax, ln)
			}
		}
		if !c.ASCII {
			continue
		}
		for i := range len(out) {
			if out[i] > 0x7f {
				t.Fatalf("ASCII report contains a non-ASCII byte at %d:\n%s", i, out)
			}
		}
		for _, want := range []string{"[ok] config valid  |  3 sources", "[!]  docker", "[on] docker", "    |-- p "} {
			if !strings.Contains(out, want) {
				t.Errorf("ASCII report missing %q:\n%s", want, out)
			}
		}
	}
}

// The singular forms, the defaults layer as the only source, and no warnings section.
func TestWriteValidateMinimal(t *testing.T) {
	v := validateInput{version: "dev", cfg: &config.Config{}, sources: []config.Source{{Kind: "defaults"}}, home: "/home/u", wd: "/w"}
	out := renderValidate(report.NewStyle(false, false), v)
	for _, want := range []string{"config valid  ·  0 sources  ·  0 warnings\n", "sources     defaults\n",
		"    home            host home (private home disabled)\n", "    env             none\n", "    providers       none\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("minimal report missing %q:\n%s", want, out)
		}
	}
	for _, absent := range []string{"warnings ─", "writable", "read-only", "profile", "blocked paths"} {
		if strings.Contains(out, absent) {
			t.Errorf("minimal report must not show %q:\n%s", absent, out)
		}
	}
	v.sources = append(v.sources, config.Source{Kind: "global"})
	v.warnings = []health.Check{{State: health.Warn, Label: "docker", Value: "x"}}
	if out := renderValidate(report.NewStyle(false, false), v); !strings.Contains(out, "config valid  ·  1 source  ·  1 warning\n") {
		t.Errorf("singular verdict missing:\n%s", out)
	}
}

// Run from home, run mounts a scratch dir as the project, so home stays read-only.
func TestWriteValidateFromHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("TMPDIR", "/tmp")
	cfg := &config.Config{}
	cfg.Providers.Paths.RO = []string{filepath.Join(home, "docs")}
	v := validateInput{version: "dev", cfg: cfg, sources: []config.Source{{Kind: "defaults"}}, home: home, wd: home}
	out := renderValidate(report.NewStyle(false, false), v)
	for _, want := range []string{
		"/tmp/corral-work-XXXXXX   rw   project (scratch dir, run from home)\n",
		"~/docs                    ro   providers.paths.ro\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report from home missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "   rw   project\n") {
		t.Errorf("home must not be the read-write project:\n%s", out)
	}
}

func TestValidateReport(t *testing.T) {
	home, _ := trustRepo(t, "agents:\n  claude:\n    telemetry: true\nproviders:\n  paths:\n    ro: [~/reference/wiki, ~/reference/code, ~/reference/code/example]\n")
	failIfMint(t)
	t.Setenv("NO_COLOR", "1")
	out := captureStdout(t, func() {
		if code := cmdValidate(nil, "test"); code != 0 {
			t.Fatalf("validate exit=%d", code)
		}
	})
	// The default private home ends in a hash of the agent config dir; pin the row's shape only.
	got := regexp.MustCompile(`(?m)^(    home            ~/\.cache/corral/home-)[0-9a-f]{8}$`).ReplaceAllString(out, "${1}<hash>")
	want := `
  ████████████  corral test   agent claude
  █          █  ✓ config valid  ·  1 source  ·  1 warning
  █  ████  █
  █  ████  █    sources     project not approved
  █          █  read-only   ~/reference/wiki ~/reference/code +1
  ████████████  blocked     6 paths: 6 always blocked + 0 configured
                            list with corral validate --list

warnings ─────────────────────────────────────────────────────────
  ! project         not approved
                    ~/proj/.corral.yml; corral asks on the next run or sync
settings ─────────────────────────────────────────────────────────
    project         ~/proj/.corral.yml
                    not approved
    home            ~/.cache/corral/home-<hash>
    network         open
    hostname        corral
    connectors      off
    telemetry       on
    error reporting off
    feedback survey off
    env             TERM COLORTERM NO_COLOR EDITOR VISUAL PAGER TMPDIR LANG
                    CLAUDE_CONFIG_DIR PI_CODING_AGENT_DIR
                    PI_CODING_AGENT_SESSION_DIR
                    other host variables are dropped
  ● home            private $HOME (allowed paths symlinked in; tool caches & state isolated)
                    setup error: abort launch
path grants ──────────────────────────────────────────────────────
    ~
    ├── proj                  rw   project
    └── reference
        ├── code              ro   providers.paths.ro
        │   └── example       ro   providers.paths.ro
        └── wiki              ro   providers.paths.ro

Config only. Run corral doctor to check this host.
`
	if got != want {
		t.Errorf("report mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
	if created, _ := filepath.Glob(filepath.Join(home, ".cache", "corral", "home*")); len(created) > 0 {
		t.Errorf("validation must not create the private home: %v", created)
	}
}

func TestValidateWarningsPrecedeSettings(t *testing.T) {
	trustRepo(t, "providers:\n  docker: {enabled: true}\n")
	failIfMint(t)
	out := captureStdout(t, func() {
		if code := cmdValidate(nil, "test"); code != 0 {
			t.Fatalf("advisories must not invalidate config, exit=%d", code)
		}
	})
	warning := strings.Index(out, "\nwarnings ")
	settings := strings.Index(out, "\nsettings ")
	if warning < 0 || settings < warning || !strings.Contains(out[warning:settings], "docker") {
		t.Fatalf("warnings must precede settings and path grants:\n%s", out)
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
	out := captureStdout(t, func() { cmdValidate(nil, "test") })
	start := strings.Index(out, "  ● hooks ")
	if start < 0 {
		t.Fatalf("missing hooks provider row:\n%s", out)
	}
	end := strings.Index(out[start:], "  ● home ")
	if end < 0 {
		t.Fatalf("missing provider after hooks row:\n%s", out)
	}
	section := out[start : start+end]
	want := "failure policy: required pre-start failures abort launch; optional pre-start failures continue; post-end failures warn"
	if !strings.Contains(section, want) || strings.Contains(section, "setup error") {
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
			t.Setenv("NO_COLOR", "1")
			out := captureStdout(t, func() { cmdValidate([]string{"--profile", tc.name}, "test") })
			if !strings.Contains(out, ", profile "+tc.rendered+"\n") ||
				!strings.Contains(out, "   profile "+tc.rendered+"   agent claude\n") {
				t.Errorf("ambiguous profile name is not quoted as %q:\n%s", tc.rendered, out)
			}
		})
	}
}

func TestValidatePiReport(t *testing.T) {
	trustRepo(t, "agent: pi\nproviders:\n  home: {enabled: false}\n")
	out := captureStdout(t, func() { cmdValidate(nil, "test") })
	for _, want := range []string{"agent pi\n", "    hostname        corral\n    agent           no agent-specific toggles\n    env ", "    home            host home (private home disabled)\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	for _, unwanted := range []string{"connectors", "telemetry", "error reporting", "feedback survey", "~/.cache/corral/home"} {
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
			out := captureStdout(t, func() { cmdValidate(nil, "test") })
			if !strings.Contains(out, "    home            "+tt.want) {
				t.Errorf("missing resolved private home %q:\n%s", tt.want, out)
			}
		})
	}
}

func TestValidateListOnlyExpandsBlockedPaths(t *testing.T) {
	trustRepo(t, "providers:\n  block: {files: [~/private-file]}\n  paths:\n    rw: [~/code/work]\n    ro: [~/code/docs]\n")
	t.Setenv("NO_COLOR", "1")
	plain := captureStdout(t, func() { cmdValidate(nil, "test") })
	listed := captureStdout(t, func() { cmdValidate([]string{"--list"}, "test") })
	const hint = "                            list with corral validate --list\n"
	start, end := "\nblocked paths ", "\nsettings "
	i, j := strings.Index(listed, start), strings.Index(listed, end)
	if i < 0 || j < i {
		t.Fatalf("missing blocked paths section:\n%s", listed)
	}
	if strings.Replace(plain, hint, "", 1) != listed[:i]+listed[j:] {
		t.Errorf("--list changed more than the blocked-path inventory:\n%s\n%s", plain, listed)
	}
	if strings.Contains(plain, "~/.ssh") || strings.Contains(plain, "blocked paths") {
		t.Errorf("blocked inventory must require --list:\n%s", plain)
	}
	section := listed[i : j+1]
	if !strings.Contains(section, "    ~/private-file  configured\n") || !strings.Contains(section, "    ~/.ssh          always blocked\n") {
		t.Errorf("missing blocked path attribution:\n%s", section)
	}
	for _, want := range []string{"├── docs              ro   providers.paths.ro\n", "└── work              rw   providers.paths.rw\n"} {
		if !strings.Contains(plain, want) {
			t.Errorf("missing grant %q:\n%s", want, plain)
		}
	}
}

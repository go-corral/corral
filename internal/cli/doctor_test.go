package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/selfupdate"
)

// doctorFixture is a host with one failed and three warning checks across the areas.
func doctorFixture() []doctorArea {
	ok := func(label, value string) health.Check { return health.Check{Label: label, Value: value} }
	return []doctorArea{
		{name: "sandbox", summary: "bwrap", checks: []health.Check{
			ok("bwrap", "/usr/bin/bwrap"), ok("pid namespace", "pid:[1]"), ok("legacy tiocsti", "disabled"),
		}},
		{name: "config", summary: "global + project valid", checks: []health.Check{ok("config", "valid")}},
		{name: "agents", summary: "claude, pi ready", checks: []health.Check{
			ok("claude", "/usr/bin/claude"), ok("claude", "hooks registered for this binary"),
			ok("pi", "/usr/bin/pi"), ok("pi", "policy bridge embedded (10 bytes)"),
			{State: health.Warn, Label: "pi", Value: "presence backstop out of date",
				Reason: "~/.pi/agent/extensions/corral-presence.ts", Fix: "corral sync pi"},
		}},
		{name: "providers", summary: "docker, ssh available", checks: []health.Check{
			{State: health.Fail, Label: "docker", Value: "unavailable", Reason: "required in config, so the launch stops here"},
			{State: health.Warn, Label: "ssh", Value: "unavailable", Reason: "optional; the session warns and continues"},
		}},
		{name: "environment", summary: "no overrides", checks: []health.Check{
			{State: health.Warn, Label: "hooks", Value: "CORRAL_DISABLE_HOOKS=0 not recognized",
				Reason: "hooks stay active; use 1 to disable them or unset it", Fix: "unset CORRAL_DISABLE_HOOKS"},
		}},
		{name: "update", summary: "up to date", checks: []health.Check{ok("update", "up to date")}},
	}
}

// cleanFixture is a host where every check passes and no provider is enabled.
func cleanFixture() []doctorArea {
	var areas []doctorArea
	for _, a := range doctorFixture() {
		var checks []health.Check
		for _, ch := range a.checks {
			if ch.State == health.OK {
				checks = append(checks, ch)
			}
		}
		a.checks = checks
		if a.name == "environment" {
			a.checks = []health.Check{{Label: "hooks", Value: "CORRAL_DISABLE_HOOKS not set"}}
		}
		if a.name == "providers" {
			a.summary = "none to check"
		}
		areas = append(areas, a)
	}
	return areas
}

func renderDoctor(c report.Style, areas []doctorArea) string {
	var b strings.Builder
	writeDoctor(&b, c, "corral v0.21.0", areas)
	return b.String()
}

// The approved layout: the verdict and roll-up beside the mark, then one attention row per
// failed or warning check with its reason and fix.
func TestWriteDoctorLayout(t *testing.T) {
	want := `
  ████████████  corral v0.21.0
  █          █  1 failed  ·  3 warnings  ·  9 passed
  █  ████  █
  █  ████  █    sandbox     ✓ bwrap
  █          █  config      ✓ global + project valid
  ████████████  agents      ! pi presence backstop out of date
                providers   ✗ docker unavailable +1
                environment ! hooks CORRAL_DISABLE_HOOKS=0 not recognized
                update      ✓ up to date

needs attention ──────────────────────────────────────────────────
  ! pi              presence backstop out of date
                    ~/.pi/agent/extensions/corral-presence.ts
                    → corral sync pi
  ✗ docker          unavailable
                    required in config, so the launch stops here
  ! ssh             unavailable
                    optional; the session warns and continues
  ! hooks           CORRAL_DISABLE_HOOKS=0 not recognized
                    hooks stay active; use 1 to disable them or unset it
                    → unset CORRAL_DISABLE_HOOKS

Host only. Run corral validate for the effective policy.
`
	if got := renderDoctor(report.NewStyle(false, false), doctorFixture()); got != want {
		t.Errorf("doctor =\n%s\nwant\n%s", got, want)
	}
}

// Each roll-up row carries the glyph of its area's first worst attention row, and the
// verdict counts every check once.
func TestWriteDoctorRollupMatchesAttention(t *testing.T) {
	areas := doctorFixture()
	out := renderDoctor(report.NewStyle(false, false), areas)
	lines := strings.Split(out, "\n")

	if want := "1 failed  ·  3 warnings  ·  9 passed"; !strings.Contains(out, want) {
		t.Errorf("verdict must read %q:\n%s", want, out)
	}

	// Attention rows in output order: glyph and label.
	type row struct{ glyph, label string }
	var attention []row
	for _, l := range lines[slicesIndexPrefix(lines, "needs attention")+1:] {
		r := []rune(l)
		if len(r) > 4 && r[0] == ' ' && r[2] != ' ' {
			attention = append(attention, row{string(r[2]), strings.TrimSpace(string(r[4:20]))})
		}
	}

	severity := map[string]int{"!": 1, "✗": 2}
	for _, a := range areas {
		rollup := ""
		for _, l := range lines {
			if r := []rune(l); len(r) > 16 && strings.TrimSpace(string(r[16:28])) == a.name {
				rollup = strings.Fields(string(r[28:]))[0]
			}
		}
		labels := map[string]bool{}
		for _, ch := range a.checks {
			labels[ch.Label] = true
		}
		want := "✓"
		for _, r := range attention {
			if labels[r.label] && severity[r.glyph] > severity[want] {
				want = r.glyph
			}
		}
		if rollup != want {
			t.Errorf("roll-up %s glyph = %q, want %q (its worst attention row):\n%s", a.name, rollup, want, out)
		}
	}
}

func slicesIndexPrefix(lines []string, prefix string) int {
	for i, l := range lines {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

// A clean host prints the roll-up without an attention section; an area without checks
// shows its summary dimmed behind the off glyph.
func TestWriteDoctorClean(t *testing.T) {
	out := renderDoctor(report.NewStyle(false, false), cleanFixture())
	if strings.Contains(out, "needs attention") {
		t.Errorf("a clean host must not print the attention section:\n%s", out)
	}
	for _, want := range []string{
		"0 failed  ·  0 warnings  ·  10 passed",
		"agents      ✓ claude, pi ready\n",
		"providers   ○ none to check\n",
		"environment ✓ no overrides\n",
		"Host only. Run corral validate for the effective policy.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("clean doctor missing %q:\n%s", want, out)
		}
	}
}

// Reasons and fixes sit on their own lines at the value column, and every line fits
// LineMax with this short data.
func TestWriteDoctorAttentionRows(t *testing.T) {
	out := renderDoctor(report.NewStyle(false, false), doctorFixture())
	indent := strings.Repeat(" ", report.ValueColumn-1)
	for _, want := range []string{
		"\n" + indent + "required in config, so the launch stops here\n",
		"\n" + indent + "→ corral sync pi\n",
		"\n" + indent + "→ unset CORRAL_DISABLE_HOOKS\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("attention section missing %q:\n%s", want, out)
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if n := utf8.RuneCountInString(l); n > report.LineMax {
			t.Errorf("line is %d columns, over %d: %q", n, report.LineMax, l)
		}
	}
}

// A single warning is singular, and a long roll-up text is clipped so the line fits.
func TestWriteDoctorOneWarningClipped(t *testing.T) {
	areas := []doctorArea{{name: "agents", checks: []health.Check{{State: health.Warn, Label: "claude",
		Value: "hooks stale for PreToolUse, PostToolUse, SessionStart, UserPromptSubmit"}}}}
	out := renderDoctor(report.NewStyle(false, false), areas)
	if !strings.Contains(out, "0 failed  ·  1 warning  ·  0 passed") {
		t.Errorf("one warning must be singular:\n%s", out)
	}
	if !strings.Contains(out, "agents      ! claude hooks stale for PreToolUse, PostToolUse, S…\n") {
		t.Errorf("a long roll-up text must be clipped at the line end:\n%s", out)
	}
}

// The ASCII form keeps the grid with ASCII glyphs, separator, rule, and fix arrow.
func TestWriteDoctorASCII(t *testing.T) {
	out := renderDoctor(report.NewStyle(false, true), doctorFixture())
	for _, want := range []string{
		"1 failed  |  3 warnings  |  9 passed",
		"providers   [x] docker unavailable +1\n",
		"agents      [!] pi presence backstop out of date\n",
		"needs attention ---",
		"[x]  docker         unavailable\n",
		"[!]  pi             presence backstop out of date\n",
		"\n" + strings.Repeat(" ", report.ValueColumn-1) + "-> corral sync pi\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ASCII doctor missing %q:\n%s", want, out)
		}
	}
	for i, r := range out {
		if r >= utf8.RuneSelf {
			t.Fatalf("ASCII doctor has non-ASCII %q at byte %d:\n%s", r, i, out)
		}
	}
}

// stubAgentBinaries puts fake agent executables on PATH so doctor reports those agents as
// installed and calls their Doctor functions, independent of what is really installed (pi is
// absent in CI).
func stubAgentBinaries(t *testing.T, names ...string) {
	t.Helper()
	dir := t.TempDir()
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write stub %s: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// TestDoctorEnumeratesAllAgents verifies `corral doctor` reports every installed agent in one
// view, with each agent's own readiness checks: claude's hook registration and pi's presence
// backstop, each with its sync command.
func TestDoctorEnumeratesAllAgents(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub uses /bin/sh")
	}
	home := t.TempDir()
	isolateConfigEnv(t, home, home)
	t.Setenv("CORRAL_DISABLE_HOOKS", "")
	stubAgentBinaries(t, "claude", "pi")

	out := captureStdout(t, func() { cmdDoctor(nil, "test") })

	if !strings.Contains(out, "agents      ! claude hooks not registered +1\n") {
		t.Errorf("the agents roll-up should name claude's missing hooks and count pi's warning:\n%s", out)
	}
	for _, want := range []string{
		"  ! claude          hooks not registered\n",
		"→ corral sync claude\n",
		"  ! pi              presence backstop not installed\n",
		"→ corral sync pi\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor should report %q:\n%s", want, out)
		}
	}
}

// TestDoctorReportsUnavailableAgent verifies only the configured agent is reported when it is
// absent: the other agents are optional. PATH is set to an empty dir so no agent resolves.
func TestDoctorReportsUnavailableAgent(t *testing.T) {
	for _, tt := range []struct{ config, missing, silent string }{
		{"", "claude", "pi"},
		{"agent: pi\n", "pi", "claude"},
	} {
		home := t.TempDir()
		if err := os.WriteFile(filepath.Join(home, ".corral.yml"), []byte(tt.config), 0o644); err != nil {
			t.Fatal(err)
		}
		isolateConfigEnv(t, home, home)
		t.Setenv("PATH", t.TempDir())

		out := captureStdout(t, func() { cmdDoctor(nil, "test") })

		for _, want := range []string{
			"agents      ! " + tt.missing + " not installed\n",
			"  ! " + tt.missing + strings.Repeat(" ", 16-len(tt.missing)) + "not installed\n",
			"no " + tt.missing + " on PATH\n",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("doctor should report the missing configured agent with %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, tt.silent) {
			t.Errorf("doctor should not report the absent, unconfigured %s:\n%s", tt.silent, out)
		}
	}
}

// An invalid config names no agent, so absent agents stay silent, and providers are not checked.
func TestDoctorInvalidConfig(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".corral.yml"), []byte("providers: [broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	isolateConfigEnv(t, home, home)
	t.Setenv("PATH", t.TempDir())

	out := captureStdout(t, func() { cmdDoctor(nil, "test") })
	for _, want := range []string{"agents      ○ none installed\n", "providers   ○ not checked (config invalid)\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor with an invalid config should report %q:\n%s", want, out)
		}
	}
}

// The update area dates the cached check, and warns when the launch check is disabled.
func TestDoctorUpdateArea(t *testing.T) {
	when := time.Date(2026, 9, 1, 12, 0, 0, 0, time.Local)
	for _, tt := range []struct {
		name, config, cached string
		want                 []string
	}{
		{"up to date", "", "0.3.0", []string{"update      ✓ up to date as of 2026-09-01\n"}},
		{"disabled", "update:\n  checkOnStart: false\n", "0.3.0", []string{
			"update      ! update launch check disabled\n",
			"  ! update          launch check disabled\n",
			"                    last check 2026-09-01\n",
			"                    → corral update --check\n",
		}},
		{"disabled, never checked", "update:\n  checkOnStart: false\n", "", []string{
			"  ! update          launch check disabled\n",
			"                    never checked\n",
		}},
		{"newer", "update:\n  checkOnStart: false\n", "0.4.0", []string{
			"  ! corral          0.3.0 → 0.4.0 available\n",
			"                    → corral update\n",
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(home, ".corral.yml"), []byte(tt.config), 0o644); err != nil {
				t.Fatal(err)
			}
			isolateConfigEnv(t, home, home)
			if tt.cached != "" {
				selfupdate.RecordCheck(selfupdate.StatePath(home), tt.cached, when)
			}
			out := captureStdout(t, func() { cmdDoctor(nil, "0.3.0") })
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("doctor update area missing %q:\n%s", want, out)
				}
			}
		})
	}
}

// Hook-exec trust warnings name the config key, and an unreadable executable its read error.
func TestDoctorHookExecReasons(t *testing.T) {
	_, proj := trustRepo(t, "providers:\n  hooks:\n    preStart:\n      10-up:\n        exec: ./up.sh\n      20-gone:\n        exec: ./gone.sh\n        optional: true\n")
	if err := os.WriteFile(filepath.Join(proj, "up.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", "")

	out := captureStdout(t, func() { cmdDoctor(nil, "test") })
	for _, want := range []string{
		"~/proj/up.sh (providers.hooks.preStart.10-up); corral asks on the next run\n",
		"  ! hook exec       ~/proj/gone.sh\n",
		"providers.hooks.preStart.20-gone; open ~/proj/gone.sh: no such file or directory; the launch fails or skips this hook\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor hook-exec warning missing %q:\n%s", want, out)
		}
	}
}

// The kill switch lives in the launching shell, so doctor warns about it with the command
// that clears it; an unrecognized value leaves hooks active and says so.
func TestDoctorReportsHookKillSwitch(t *testing.T) {
	home := t.TempDir()
	isolateConfigEnv(t, home, home)
	for raw, want := range map[string]string{
		"1":   "CORRAL_DISABLE_HOOKS=1 disables hooks",
		"yes": "CORRAL_DISABLE_HOOKS=yes not recognized",
		"":    "",
	} {
		t.Setenv("CORRAL_DISABLE_HOOKS", raw)
		out := captureStdout(t, func() { cmdDoctor(nil, "test") })
		if want == "" {
			if !strings.Contains(out, "environment ✓ no overrides\n") {
				t.Errorf("unset kill switch should report no overrides:\n%s", out)
			}
			continue
		}
		if !strings.Contains(out, "  ! hooks           "+want+"\n") || !strings.Contains(out, "→ unset CORRAL_DISABLE_HOOKS\n") {
			t.Errorf("CORRAL_DISABLE_HOOKS=%s should warn %q with its fix:\n%s", raw, want, out)
		}
	}
}

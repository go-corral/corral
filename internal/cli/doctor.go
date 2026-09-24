package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/selfupdate"
)

// doctorArea is one roll-up row. summary is shown when every check passes, or dimmed when
// the area has no checks.
type doctorArea struct {
	name    string
	summary string
	checks  []health.Check
}

// cmdDoctor reports host readiness: the sandbox backend, config, agents, enabled
// providers, environment overrides, and update state.
func cmdDoctor(args []string, version string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	backendFlag := fs.String("backend", "", "sandbox backend to check: bwrap or seatbelt (default: this OS's backend)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: corral doctor [flags]")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	c := report.StyleFor(os.Stdout)
	home, homeErr := os.UserHomeDir()
	cfg, sources, cfgErr := loadConfig(nil)
	areas := []doctorArea{
		sandboxArea(*backendFlag),
		configArea(cfg, sources, cfgErr),
		agentsArea(cfg, cfgErr, home, homeErr),
		providersArea(cfg, cfgErr, home),
		environmentArea(),
		updateArea(c, cfg, cfgErr, version, home, homeErr),
	}
	for _, a := range areas {
		for i := range a.checks {
			a.checks[i].Value = abbrevText(a.checks[i].Value, home)
			a.checks[i].Reason = abbrevText(a.checks[i].Reason, home)
		}
	}
	title := fmt.Sprintf("%scorral %s%s   %s%s/%s   %s%s",
		c.Bold, bannerVersion(version), c.Reset, c.Dim, runtime.GOOS, runtime.GOARCH, runtime.Version(), c.Reset)
	writeDoctor(os.Stdout, c, title, areas)
	return 0
}

func sandboxArea(override string) doctorArea {
	kind, err := sandbox.ResolveKind(override)
	if err != nil {
		return doctorArea{name: "sandbox", checks: []health.Check{{State: health.Fail, Label: "sandbox", Value: err.Error()}}}
	}
	backend := newBackend(kind, "", config.Sandbox{})
	return doctorArea{name: "sandbox", summary: backend.Name(), checks: backend.Doctor()}
}

// configArea reports config validity and the approval state of repo layers and
// session-hook executables.
func configArea(cfg *config.Config, sources []config.Source, err error) doctorArea {
	a := doctorArea{name: "config", summary: "valid"}
	if err != nil {
		a.checks = []health.Check{{State: health.Fail, Label: "config", Value: "invalid", Reason: err.Error(), Fix: "corral validate"}}
		return a
	}
	a.checks = []health.Check{{Label: "config", Value: "valid"}}
	var kinds []string
	for _, s := range sources {
		if s.Kind != "defaults" {
			kinds = append(kinds, s.Kind)
		}
	}
	if len(kinds) > 0 {
		a.summary = strings.Join(kinds, " + ") + " valid"
	}
	a.checks = append(a.checks, trustWarnings(cfg, sources)...)
	return a
}

// agentsArea reports each installed agent and its enforcement readiness. With a valid
// config, the configured agent is reported when it is not installed.
func agentsArea(cfg *config.Config, cfgErr error, home string, homeErr error) doctorArea {
	a := doctorArea{name: "agents", summary: "none installed"}
	host := envMap()
	// This executable is the binary an agent's registration must name.
	self, _ := os.Executable()
	configured := ""
	if cfgErr == nil {
		configured = cfg.EffectiveAgent()
		if _, ok := agents.Lookup(configured); !ok {
			configured = agents.Default
		}
	}
	var installed []string
	for _, name := range agents.Known() {
		ag, _ := agents.Lookup(name)
		path, found := agentBinary(ag)
		if !found {
			if name == configured {
				a.checks = append(a.checks, health.Check{State: health.Warn, Label: name,
					Value: "not installed", Reason: "no " + strings.Join(ag.Binaries(), "/") + " on PATH"})
			}
			continue
		}
		installed = append(installed, name)
		a.checks = append(a.checks, health.Check{Label: name, Value: path})
		if homeErr != nil {
			a.checks = append(a.checks, health.Check{State: health.Warn, Label: name,
				Value: "cannot resolve home", Reason: homeErr.Error()})
			continue
		}
		// The agent's own checks are listed under the agent's name.
		for _, ch := range ag.Doctor(agents.StatusInput{Home: home, Host: host, Self: self}) {
			ch.Label, ch.Value = name, ch.Label+" "+ch.Value
			a.checks = append(a.checks, ch)
		}
	}
	if len(installed) > 0 {
		a.summary = strings.Join(installed, ", ") + " ready"
	}
	return a
}

// agentBinary resolves an agent's program on PATH, trying Binaries names in order.
func agentBinary(a agents.Agent) (string, bool) {
	for _, name := range a.Binaries() {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	return "", false
}

// doctorAgent resolves the agent a `[agent]` positional names: the positional if given,
// else the configured agent, else the default.
func doctorAgent(name string) agents.Agent {
	if name == "" {
		if cfg, _, err := loadConfig(nil); err == nil {
			name = cfg.EffectiveAgent()
		}
	}
	if a, ok := agents.Lookup(name); ok {
		return a
	}
	a, _ := agents.Lookup(agents.Default)
	return a
}

// providersArea probes the host prerequisite of each enabled provider that has one.
func providersArea(cfg *config.Config, cfgErr error, home string) doctorArea {
	if cfgErr != nil {
		return doctorArea{name: "providers", summary: "not checked (config invalid)"}
	}
	a := doctorArea{name: "providers", summary: "none to check"}
	optional := map[string]bool{}
	for _, v := range enabledProviders(cfg) {
		optional[v.Name] = v.Optional
	}
	var names []string
	for _, p := range knownProviders(home, envMap()) {
		opt, enabled := optional[p.Name()]
		if !enabled {
			continue
		}
		names = append(names, p.Name())
		ch := health.Check{Label: p.Name(), Value: "available"}
		switch {
		case p.Available(context.Background()):
		case opt:
			ch = health.Check{State: health.Warn, Label: p.Name(), Value: "unavailable", Reason: "optional; the session warns and continues"}
		default:
			ch = health.Check{State: health.Fail, Label: p.Name(), Value: "unavailable", Reason: "required in config, so the launch stops here"}
		}
		a.checks = append(a.checks, ch)
	}
	if len(names) > 0 {
		a.summary = strings.Join(names, ", ") + " available"
	}
	return a
}

// environmentArea reports CORRAL_DISABLE_HOOKS as seen in this shell: it lives in the
// launching shell, not a corral file.
func environmentArea() doctorArea {
	ch := health.Check{Label: "hooks", Value: sandbox.DisableHooksEnvVar + " not set"}
	raw := os.Getenv(sandbox.DisableHooksEnvVar)
	switch {
	case strings.TrimSpace(raw) == "":
	case sandbox.EnvEnabled(sandbox.DisableHooksEnvVar):
		ch = health.Check{State: health.Warn, Label: "hooks", Value: sandbox.DisableHooksEnvVar + "=" + raw + " disables hooks",
			Reason: "agents started from this shell run unhooked; a corral run session is unaffected",
			Fix:    "unset " + sandbox.DisableHooksEnvVar}
	default:
		ch = health.Check{State: health.Warn, Label: "hooks", Value: sandbox.DisableHooksEnvVar + "=" + raw + " not recognized",
			Reason: "hooks stay active; use 1 to disable them or unset it",
			Fix:    "unset " + sandbox.DisableHooksEnvVar}
	}
	return doctorArea{name: "environment", summary: "no overrides", checks: []health.Check{ch}}
}

// updateArea reports the cached result of the last version check, with no network call.
func updateArea(c report.Style, cfg *config.Config, cfgErr error, version, home string, homeErr error) doctorArea {
	ch := health.Check{Label: "update"}
	if homeErr != nil {
		ch.State, ch.Value, ch.Reason = health.Warn, "unknown", "cannot resolve home"
		return doctorArea{name: "update", summary: ch.Value, checks: []health.Check{ch}}
	}
	latest, when, ok := selfupdate.CachedCheck(selfupdate.StatePath(home))
	switch {
	case ok && selfupdate.IsNewer(latest, version):
		ch = health.Check{State: health.Warn, Label: "corral",
			Value: fmt.Sprintf("%s %s %s available", version, c.Glyph(report.Fix), latest), Fix: "corral update"}
	case cfgErr == nil && !cfg.Update.CheckOnStart:
		ch.State, ch.Value, ch.Reason, ch.Fix = health.Warn, "launch check disabled", "never checked", "corral update --check"
		if ok {
			ch.Reason = "last check " + when.Format("2006-01-02")
		}
	case !ok:
		ch.Value = "not checked yet"
	case latest != "":
		ch.Value = "up to date as of " + when.Format("2006-01-02")
	default:
		ch.State, ch.Value = health.Warn, "release server unreachable at last check"
		ch.Reason, ch.Fix = "checked "+when.Format("2006-01-02 15:04"), "corral update --check"
	}
	return doctorArea{name: "update", summary: ch.Value, checks: []health.Check{ch}}
}

// stateGlyph is the status glyph of a check state.
func stateGlyph(s health.State) report.Glyph {
	switch s {
	case health.Fail:
		return report.Blocked
	case health.Warn:
		return report.Attention
	}
	return report.Ready
}

// writeDoctor prints the header with the verdict and one roll-up row per area, then every
// failed or warning check with its reason and fix, then a pointer to validate.
func writeDoctor(w io.Writer, c report.Style, title string, areas []doctorArea) {
	var failed, warned, passed int
	var rollup []report.Row
	for _, a := range areas {
		var worst *health.Check
		bad := 0
		for i, ch := range a.checks {
			switch ch.State {
			case health.Fail:
				failed++
			case health.Warn:
				warned++
			default:
				passed++
				continue
			}
			bad++
			if worst == nil || ch.State > worst.State {
				worst = &a.checks[i]
			}
		}
		rollup = append(rollup, report.Row{Label: a.name, Value: rollupValue(c, a, worst, bad)})
	}

	sep := "  " + c.Sep() + "  "
	failedText := fmt.Sprintf("%d failed", failed)
	if failed > 0 {
		failedText = c.Red + failedText + c.Reset
	}
	warnText := fmt.Sprintf("%d warnings", warned)
	if warned == 1 {
		warnText = "1 warning"
	}
	if warned > 0 {
		warnText = c.Yellow + warnText + c.Reset
	}
	verdict := failedText + sep + warnText + sep + fmt.Sprintf("%d passed", passed)
	c.Header(w, title, []string{verdict}, rollup)

	if failed+warned > 0 {
		fmt.Fprintln(w)
		c.Rule(w, "needs attention")
		for _, a := range areas {
			for _, ch := range a.checks {
				if ch.State == health.OK {
					continue
				}
				c.Row(w, report.Row{Glyph: stateGlyph(ch.State), Label: ch.Label, Value: ch.Value, Reason: ch.Reason})
				if ch.Fix != "" {
					c.Cont(w, c.Glyph(report.Fix)+" "+ch.Fix)
				}
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.Dim+"Host only. Run corral validate for the effective policy."+c.Reset)
}

// rollupValue is an area's roll-up value: its worst check, clipped to the line, and a dim
// count of the other failed or warning checks; else its summary.
func rollupValue(c report.Style, a doctorArea, worst *health.Check, bad int) string {
	switch {
	case len(a.checks) == 0:
		return c.Dim + c.Glyph(report.Off) + " " + a.summary + c.Reset
	case worst == nil:
		return c.Status(report.Ready) + " " + a.summary
	}
	g := stateGlyph(worst.State)
	more := ""
	if bad > 1 {
		more = fmt.Sprintf(" +%d", bad-1)
	}
	room := rollupWidth - utf8.RuneCountInString(c.Glyph(g)+" "+more)
	return c.Status(g) + " " + clip(c, worst.Label+" "+worst.Value, room) + c.Dim + more + c.Reset
}

// clip shortens s to n columns, marking the cut with an ellipsis.
func clip(c report.Style, s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	dots := "…"
	if c.ASCII {
		dots = "..."
	}
	return string([]rune(s)[:max(n-utf8.RuneCountInString(dots), 0)]) + dots
}

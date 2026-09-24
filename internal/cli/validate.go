package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/trust"
)

// validateInput is what the validate report shows beyond the config itself: the host facts
// cmdValidate reads.
type validateInput struct {
	version  string
	profiles []string
	list     bool
	cfg      *config.Config
	sources  []config.Source
	states   map[string]trust.State
	home, wd string
	// privHome is the resolved private home, "" when the home provider is disabled.
	privHome string
	extras   []string
	execs    hookExecs
	warnings []health.Check
}

// cmdValidate reports config validity and the effective policy without launching providers.
func cmdValidate(args []string, version string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	profiles := addProfileFlags(fs)
	list := fs.Bool("list", false, "list every effective blocked path (not just the count)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	cfg, sources, err := loadConfig([]string(*profiles))
	if err != nil {
		return fatalf(os.Stderr, "config invalid: %v", err)
	}

	// An empty home would misrepresent the always-blocked paths.
	home, err := os.UserHomeDir()
	if err != nil {
		return fatalf(os.Stderr, "cannot resolve home: %v", err)
	}
	if err := grantAuditDir(cfg, home, true); err != nil {
		return fatalf(os.Stderr, "config invalid: %v", err)
	}
	// Apply the launcher's resolved-path guard; lexical validation alone cannot detect a grant
	// that exposes an always-blocked directory through a symlink.
	if err := checkResolvedPathGrants(cfg, home); err != nil {
		return fatalf(os.Stderr, "config invalid: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		return fatalf(os.Stderr, "cannot resolve the working directory: %v", err)
	}
	env := envMap()
	v := validateInput{
		version:  version,
		profiles: *profiles,
		list:     *list,
		cfg:      cfg,
		sources:  sources,
		states:   trustStates(trustEntries(sources)),
		home:     home,
		wd:       wd,
		extras:   resolvedFloorExtras(home),
		// Hook executables are hashed for their approval state, never executed.
		execs:    collectHookExecs(cfg, wd),
		warnings: append(validateWarnings(cfg, home, env), trustWarnings(cfg, sources)...),
	}
	v.privHome, _ = homeDir(cfg, home, env)
	writeValidate(os.Stdout, report.StyleFor(os.Stdout), v)
	return 0
}

// writeValidate prints the header with the verdict and the roll-up, then the warnings, the
// blocked paths with --list, the settings, the path grants, and a pointer to doctor.
func writeValidate(w io.Writer, c report.Style, v validateInput) {
	cfg := v.cfg
	pathText := func(p string) string { return reportText(abbrevHome(p, v.home)) }

	title := c.Bold + "corral " + bannerVersion(v.version) + c.Reset
	if len(v.profiles) > 0 {
		names := make([]string, len(v.profiles))
		for i, p := range v.profiles {
			names[i] = reportProfileName(p)
		}
		title += "   " + c.Dim + "profile " + strings.Join(names, ", ") + c.Reset
	}
	title += "   " + c.Dim + "agent " + cfg.EffectiveAgent() + c.Reset

	var layers []string
	for _, s := range v.sources {
		switch s.Kind {
		case "defaults":
		case "profile":
			layers = append(layers, "profile "+reportProfileName(s.Path))
		default:
			layer := s.Kind
			if st, ok := v.states[s.Path]; ok {
				layer += " " + trustStateText(st)
			}
			layers = append(layers, layer)
		}
	}
	nSources := len(layers)
	if nSources == 0 {
		layers = []string{"defaults"}
	}
	warnText := fmt.Sprintf("%d %s", len(v.warnings), plural(len(v.warnings), "warning", "warnings"))
	if len(v.warnings) > 0 {
		warnText = c.Yellow + warnText + c.Reset
	}
	sep := "  ·  "
	verdict := c.Status(report.Ready) + " config valid" + sep +
		fmt.Sprintf("%d %s", nSources, plural(nSources, "source", "sources")) + sep + warnText

	rollup := []report.Row{{Label: "sources", Value: clip(c, strings.Join(layers, ", "), rollupWidth)}}
	if rw := cfg.Providers.Paths.RW; len(rw) > 0 {
		rollup = append(rollup, report.Row{Label: "writable", Value: pathsValue(c, rw, v.home)})
	}
	if ro := cfg.Providers.Paths.RO; len(ro) > 0 {
		rollup = append(rollup, report.Row{Label: "read-only", Value: pathsValue(c, ro, v.home)})
	}
	floor := map[string]bool{}
	for _, p := range config.AlwaysBlockedExpanded(v.home) {
		floor[p] = true
	}
	blocked := cfg.EffectiveBlockedPaths(v.home)
	nFloor := 0
	for _, p := range blocked {
		if floor[p] {
			nFloor++
		}
	}
	blockedRow := report.Row{Label: "blocked", Value: fmt.Sprintf("%d %s: %d always blocked + %d configured",
		len(blocked), plural(len(blocked), "path", "paths"), nFloor, len(blocked)-nFloor)}
	if !v.list {
		command := []string{"corral", "validate", "--list"}
		for _, p := range v.profiles {
			command = append(command, "--profile", p)
		}
		blockedRow.Reason = "list with " + shellQuote(command)
	}
	rollup = append(rollup, blockedRow)
	c.Header(w, title, []string{verdict}, rollup)
	fmt.Fprintln(w)

	if len(v.warnings) > 0 {
		c.Rule(w, "warnings")
		writeChecks(w, c, v.warnings, v.home)
	}

	if v.list {
		c.Rule(w, "blocked paths")
		for _, p := range blocked {
			tag := "configured"
			if floor[p] {
				tag = "always blocked"
			}
			c.Row(w, report.Row{Label: pathText(p), Value: tag})
		}
	}

	c.Rule(w, "settings")
	for _, s := range v.sources {
		if s.Kind == "defaults" || s.Kind == "profile" || s.Path == "" {
			continue
		}
		row := report.Row{Label: s.Kind, Value: pathText(s.Path)}
		if st, ok := v.states[s.Path]; ok {
			row.Reason = trustStateText(st)
			if st == trust.StateChanged {
				row.Reason = "changed since approval"
			}
		}
		c.Row(w, row)
	}
	home := "host home (private home disabled)"
	if v.privHome != "" {
		home = pathText(v.privHome)
	}
	c.Row(w, report.Row{Label: "home", Value: home})
	c.Row(w, report.Row{Label: "network", Value: string(cfg.Net)})
	c.Row(w, report.Row{Label: "hostname", Value: reportText(cfg.Hostname)})
	fields := cfg.AgentValidationFields()
	if len(fields) == 0 {
		c.Row(w, report.Row{Label: "agent", Value: "no agent-specific toggles"})
	}
	for _, f := range fields {
		c.Row(w, report.Row{Label: strings.ToLower(f.Label), Value: reportText(f.Value)})
	}
	if len(v.extras) > 0 {
		var masked []string
		for _, p := range v.extras {
			masked = append(masked, pathText(p))
		}
		writeWrapped(w, c, "also masked", masked, "real paths of symlinked always-blocked directories")
	}
	var names []string
	for _, n := range cfg.Providers.Env.Passthrough {
		names = append(names, reportText(n))
	}
	writeWrapped(w, c, "env", names, "other host variables are dropped")
	for _, p := range v.execs.sortedAttrPaths() {
		c.Row(w, report.Row{Label: "hook exec", Value: pathText(p), Reason: reportText(v.execs.attr[p])})
	}
	if notes := cfg.Providers.Notes.Lines(); len(notes) == 0 {
		c.Row(w, report.Row{Label: "agent notes", Value: "none"})
	} else {
		c.Row(w, report.Row{Label: "agent notes", Value: reportText(notes[0])})
		for _, n := range notes[1:] {
			c.Cont(w, reportText(n))
		}
	}
	// These are configured providers, not availability probes or minted contributions.
	provs := enabledProviders(cfg)
	if len(provs) == 0 {
		c.Row(w, report.Row{Label: "providers", Value: "none"})
	}
	for _, p := range provs {
		reason := "setup error: abort launch"
		if p.Optional {
			reason = "setup error: skip provider"
		}
		if p.FailurePolicy != "" {
			reason = "failure policy: " + reportText(p.FailurePolicy)
		}
		c.Row(w, report.Row{Glyph: report.On, Label: p.Name, Value: reportText(p.Grants), Reason: reason})
	}

	c.Rule(w, "path grants")
	// run mounts a scratch dir instead of home; the dry-run form only names it.
	project, scratch, _ := resolveWorkdir(v.home, v.wd, true)
	grants := []grant{{project, "rw", "project"}}
	if scratch {
		grants[0].source = "project (scratch dir, run from home)"
	}
	writable := append([]string{project}, cfg.Providers.Paths.RW...)
	for _, p := range cfg.Providers.Paths.RW {
		grants = append(grants, grant{p, "rw", "providers.paths.rw"})
	}
	// Both backends let read-write win, so a read-only grant under a writable path is writable.
	for _, p := range cfg.Providers.Paths.RO {
		g := grant{p, "ro", "providers.paths.ro"}
		if slices.ContainsFunc(writable, func(rw string) bool { return policy.Within(p, rw) }) {
			g.access, g.source = "rw", "providers.paths.ro (no effect)"
		}
		grants = append(grants, g)
	}
	for _, root := range grantTrees(c, grants, v.home) {
		c.Tree(w, grantIndent, root)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, c.Dim+"Config only. Run corral doctor to check this host."+c.Reset)
}

// trustStateText is the short approval state of a repo config layer.
func trustStateText(st trust.State) string {
	switch st {
	case trust.StateApproved:
		return "approved"
	case trust.StateChanged:
		return "changed"
	}
	return "not approved"
}

// writeWrapped writes words as one detail row, wrapped at the value column so each line ends
// by LineMax, then reason dimmed below. No words print as "none".
func writeWrapped(w io.Writer, c report.Style, label string, words []string, reason string) {
	lines := []string{""}
	for _, word := range words {
		last := &lines[len(lines)-1]
		switch {
		case *last == "":
			*last = word
		case utf8.RuneCountInString(*last)+1+utf8.RuneCountInString(word) > report.LineMax-report.ValueColumn+1:
			lines = append(lines, word)
		default:
			*last += " " + word
		}
	}
	if lines[0] == "" {
		lines[0] = "none"
	}
	c.Row(w, report.Row{Label: label, Value: lines[0]})
	for _, l := range lines[1:] {
		c.Cont(w, l)
	}
	c.Cont(w, c.Dim+reason+c.Reset)
}

// validateWarnings inspects the current backend's read-only targets without preparing a sandbox.
func validateWarnings(cfg *config.Config, home string, env map[string]string) []health.Check {
	var roTargets []string
	if kind, err := sandbox.DefaultKind(); err == nil {
		spec := sandbox.SandboxSpec{Tokens: map[string]string{
			"HOME":             home,
			"AGENT_CONFIG_DIR": cfg.AgentConfigDir(home, env),
			"XDG_RUNTIME_DIR":  env["XDG_RUNTIME_DIR"],
		}}
		roTargets = newBackend(kind, "", cfg.Sandbox).ReadOnlyTargets(spec)
	}
	return sessionWarnings(cfg, roTargets)
}

// resolvedFloorExtras returns filesystem masks absent from the lexical always-blocked set.
func resolvedFloorExtras(home string) []string {
	lexical := make(map[string]bool)
	for _, p := range config.AlwaysBlockedExpanded(home) {
		lexical[p] = true
	}
	var out []string
	for _, p := range config.AlwaysBlockedMaskPaths(home) {
		if !lexical[p] {
			out = append(out, p)
		}
	}
	return out
}

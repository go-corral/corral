package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/trust"
)

// cmdValidate reports config validity and selected effective settings without launching providers.
func cmdValidate(args []string) int {
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
	out := os.Stdout
	c := report.StyleFor(out)
	env := envMap()
	pathText := func(p string) string { return reportText(abbrevHome(p, home)) }
	fmt.Fprintf(out, "%scorral validate%s\nConfiguration valid\n", c.Bold, c.Reset)
	if warnings := validateWarnings(cfg, home, env); len(warnings) > 0 {
		writeReportHeading(out, c, "Warnings")
		writeWarnings(out, c, warnings)
	}

	writeReportHeading(out, c, "Configuration")
	fmt.Fprintln(out, "  Sources")
	trustAnn := trustAnnotations(trustEntries(sources))
	for _, s := range sources {
		if s.Kind == "profile" {
			fmt.Fprintf(out, "    %-10s %s\n", s.Kind, reportProfileName(s.Path))
			continue
		}
		if s.Path == "" {
			fmt.Fprintf(out, "    %s\n", s.Kind)
			continue
		}
		fmt.Fprintf(out, "    %-10s %s\n", s.Kind, pathText(s.Path))
		if a, ok := trustAnn[s.Path]; ok && a.state != trust.StateApproved {
			fmt.Fprintf(out, "               %s%s%s\n", c.Yellow, reportText(a.label), c.Reset)
		}
	}
	active := make([]string, 0, len(*profiles))
	for _, p := range *profiles {
		active = append(active, reportProfileName(p))
	}
	fmt.Fprintf(out, "\n  Profiles   %s\n", joinOrNone(active))

	// Hook executables have their own approval state; inspection must not execute any of them.
	if wd, werr := os.Getwd(); werr == nil {
		if execs := collectHookExecs(cfg, wd); len(execs.attr) > 0 {
			fmt.Fprintln(out, "\n  Session-hook executables")
			hookAnn := trustAnnotations(execs.entries)
			for _, p := range execs.sortedAttrPaths() {
				fmt.Fprintf(out, "    %s\n      %s\n", pathText(p), reportText(execs.attr[p]))
				a, annotated := hookAnn[p]
				switch {
				case execs.unreadable[p] != "":
					fmt.Fprintf(out, "      %sunreadable — launch will fail or skip this hook: %s%s\n", c.Yellow, reportText(execs.unreadable[p]), c.Reset)
				case annotated && a.state != trust.StateApproved:
					fmt.Fprintf(out, "      %s%s%s\n", c.Yellow, reportText(a.label), c.Reset)
				}
			}
		}
	}

	writeReportHeading(out, c, "Sandbox")
	fmt.Fprintf(out, "  Network    %s\n  Hostname   %s\n", cfg.Net, reportText(cfg.Hostname))
	if dir, enabled := homeDir(cfg, home, env); enabled {
		fmt.Fprintf(out, "  Home       %s\n", pathText(dir))
	} else {
		fmt.Fprintln(out, "  Home       host home (private home disabled)")
	}

	writeReportHeading(out, c, "Agent · "+cfg.EffectiveAgent())
	fields := cfg.AgentValidationFields()
	if len(fields) == 0 {
		fmt.Fprintln(out, "  No agent-specific config toggles")
	}
	width := 0
	for _, f := range fields {
		width = max(width, len(f.Label))
	}
	for _, f := range fields {
		fmt.Fprintf(out, "  %-*s  %s\n", width, f.Label, reportText(f.Value))
	}

	floor := map[string]bool{}
	for _, p := range config.AlwaysBlockedExpanded(home) {
		floor[p] = true
	}
	eff := cfg.EffectiveBlockedPaths(home)
	nFloor := 0
	for _, p := range eff {
		if floor[p] {
			nFloor++
		}
	}
	writeReportHeading(out, c, "Filesystem")
	fmt.Fprintf(out, "  Blocked   %d paths: %d always blocked + %d configured\n", len(eff), nFloor, len(eff)-nFloor)
	if *list {
		for _, p := range eff {
			tag := "configured"
			if floor[p] {
				tag = "always blocked"
			}
			fmt.Fprintf(out, "    %s  [%s]\n", pathText(p), tag)
		}
	} else if len(eff) > 0 {
		command := []string{"corral", "validate", "--list"}
		for _, p := range *profiles {
			command = append(command, "--profile", p)
		}
		fmt.Fprintf(out, "            %sList with %s%s\n", c.Dim, shellQuote(command), c.Reset)
	}

	// Resolved masks are invisible to the hook inside the sandbox.
	if extra := resolvedFloorExtras(home); len(extra) > 0 {
		fmt.Fprintln(out, "\n  Also masked · real paths of symlinked always-blocked directories")
		for _, p := range extra {
			fmt.Fprintf(out, "    %s  [always blocked → resolved]\n", pathText(p))
		}
	}

	writeGrantSection(out, c, "Extra read-write", cfg.Providers.Paths.RW, home)
	writeGrantSection(out, c, "Extra read-only", cfg.Providers.Paths.RO, home)

	writeReportHeading(out, c, "Environment")
	fmt.Fprintln(out, "  Host passthrough allowlist")
	writeReportNames(out, cfg.Providers.Env.Passthrough)
	fmt.Fprintf(out, "  %sOther host variables are dropped.%s\n", c.Dim, c.Reset)

	// These are configured providers, not availability probes or minted contributions.
	writeReportHeading(out, c, "Providers")
	provs := enabledProviders(cfg)
	if len(provs) == 0 {
		fmt.Fprintln(out, "  none")
	}
	for i, p := range provs {
		if i > 0 {
			fmt.Fprintln(out)
		}
		mode := "abort launch"
		if p.Optional {
			mode = "skip provider"
		}
		label := "On setup error"
		if p.FailurePolicy != "" {
			label, mode = "Failure policy", p.FailurePolicy
		}
		fmt.Fprintf(out, "  %s\n    %-14s  %s\n    %-14s  %s\n", p.Name, "Grants", reportText(p.Grants), label, reportText(mode))
	}
	return 0
}

// validateWarnings inspects the current backend's read-only targets without preparing a sandbox.
func validateWarnings(cfg *config.Config, home string, env map[string]string) []string {
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

func writeReportHeading(w io.Writer, c report.Style, title string) {
	fmt.Fprintf(w, "\n%s%s%s\n", c.Bold, title, c.Reset)
}

func writeGrantSection(w io.Writer, c report.Style, label string, paths []string, home string) {
	if len(paths) == 0 {
		fmt.Fprintf(w, "\n  %s   none\n", label)
		return
	}
	var tree strings.Builder
	count := writePathTree(&tree, c, paths, home, "    ")
	noun := "grants"
	if count == 1 {
		noun = "grant"
	}
	const hint = "[grant] marks configured paths"
	fmt.Fprintf(w, "\n  %s · %d %s · %s%s%s\n%s", label, count, noun, c.Dim, hint, c.Reset, tree.String())
}

func writeReportNames(w io.Writer, names []string) {
	line := "    "
	for _, name := range names {
		name = reportText(name)
		if line != "    " {
			if len(line)+2+len(name) > 78 {
				fmt.Fprintln(w, line)
				line = "    "
			} else {
				line += "  "
			}
		}
		line += name
	}
	if len(names) == 0 {
		line += "none"
	}
	fmt.Fprintln(w, line)
}

func joinOrNone(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	return strings.Join(ss, ", ")
}

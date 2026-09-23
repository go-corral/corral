package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/registry"
	"github.com/go-corral/corral/internal/sandbox/seatbelt"
)

// sessionWarnings returns advisory notices about the effective config, shared by the `run`
// banner and `corral validate`. roTargets is the resolved backend's read-only baseline targets,
// supplied by the caller so the warning matches the backend that compiles the spec.
func sessionWarnings(cfg *config.Config, roTargets []string) []health.Check {
	var w []health.Check

	// Provider-owned lints: each provider Config authors its own advisories; the registry
	// sweeps them in canonical order. Only the paths.rw overlap check stays here — it needs
	// the resolved backend's read-only targets, which only this layer has.
	w = append(w, registry.ConfigWarnings(cfg)...)

	// A paths.rw grant that covers a baseline read-only system path re-exposes it as
	// writable, overriding corral's default protection. The always-blocked paths cannot be
	// granted (Validate rejects that) — this catches the system-path footgun.
	for _, g := range cfg.Providers.Paths.RW {
		// A seatbelt backend reports /private-folded read-only targets (macOS, or -backend
		// seatbelt on Linux), so compare each grant on both its raw and /private-folded form.
		// NormalizeMacPath is a no-op outside /var|/tmp|/etc, so other roots compare unchanged.
		cands := []string{g}
		if n := seatbelt.NormalizeMacPath(g); n != g {
			cands = append(cands, n)
		}
		if ro, ok := firstOverlap(cands, roTargets); ok {
			// Overlap in either direction re-exposes the read-only path as writable. The
			// message shows the grant as the user wrote it, not the /private-folded form.
			w = append(w, health.Check{State: health.Warn, Label: "paths.rw", Value: fmt.Sprintf("%q re-exposes %q as writable", g, ro),
				Reason: "it overlaps a baseline read-only system path and overrides corral's default protection"})
		}
	}

	return w
}

// firstOverlap returns the first read-only target that overlaps any of the grant's
// candidate forms (in either containment direction), and whether one was found.
func firstOverlap(grantCands, roTargets []string) (string, bool) {
	for _, ro := range roTargets {
		for _, c := range grantCands {
			if policy.Within(ro, c) || policy.Within(c, ro) {
				return ro, true
			}
		}
	}
	return "", false
}

// rollupWidth is the room a roll-up value has before LineMax.
const rollupWidth = report.LineMax - report.RollupValueColumn + 1

// fitPaths joins paths, home-abbreviated, so that the line and a " +N" count of the paths
// left out fit in width columns. The first path is always shown. A path with a space is
// quoted, because the paths are joined with spaces.
func fitPaths(paths []string, home string, width int) (line string, hidden int) {
	for i, p := range paths {
		text := abbrevHome(p, home)
		if strings.Contains(text, " ") {
			text = strconv.Quote(text)
		} else {
			text = reportText(text)
		}
		next := strings.TrimPrefix(line+" "+text, " ")
		more := ""
		if rest := len(paths) - i - 1; rest > 0 {
			more = fmt.Sprintf(" +%d", rest)
		}
		if i > 0 && utf8.RuneCountInString(next+more) > width {
			return line, len(paths) - i
		}
		line = next
	}
	return line, 0
}

// pathsValue renders paths as a roll-up value: the paths that fit, then a dim "+N".
func pathsValue(c report.Style, paths []string, home string) string {
	line, hidden := fitPaths(paths, home, rollupWidth)
	v := c.Blue + line + c.Reset
	if hidden > 0 {
		v += fmt.Sprintf(" %s+%d%s", c.Dim, hidden, c.Reset)
	}
	return v
}

// pathRun matches a run of characters that can form a path in free text.
var pathRun = regexp.MustCompile(`(?:[A-Za-z0-9/._~+@%-]|[^\x00-\x7F])+`)

// abbrevText applies abbrevHome to each path in a free-text status line.
func abbrevText(s, home string) string {
	return pathRun.ReplaceAllStringFunc(s, func(p string) string { return abbrevHome(p, home) })
}

// bannerVersion renders the build version: prefix "v" only for digit-leading stamps.
func bannerVersion(version string) string {
	if version != "" && version[0] >= '0' && version[0] <= '9' {
		return "v" + version
	}
	return version
}

// bannerInfo is the session state the run header shows.
type bannerInfo struct {
	version       string
	home, workdir string
	auditLog      string
	// latest is set when it is newer than version.
	latest string
	// profiles are in application order (rightmost wins).
	profiles []string
}

// writeStartupBanner prints the launch banner to w. Split into header and body so the
// real launch can slot its confirmation gate between them.
func writeStartupBanner(w io.Writer, c report.Style, cfg *config.Config, b bannerInfo, cfgWarnings []health.Check, warnings []string, notices []providers.Notice, launchOnly []string) {
	writeBannerHeader(w, c, cfg, b, cfgWarnings, warnings)
	writeBannerBody(w, c, b.home, notices, launchOnly)
}

// writeBannerHeader prints the mark with the version line and the roll-up of what the
// session can reach, then the config warnings and the other warnings. Everything here is
// known before providers mint.
func writeBannerHeader(w io.Writer, c report.Style, cfg *config.Config, b bannerInfo, cfgWarnings []health.Check, warnings []string) {
	title := fmt.Sprintf("%scorral %s%s", c.Bold, bannerVersion(b.version), c.Reset)
	if len(b.profiles) > 0 {
		title += fmt.Sprintf("   %sprofile %s%s", c.Dim, strings.Join(b.profiles, ", "), c.Reset)
	}
	var verdict []string
	if b.latest != "" {
		glyph := c.Glyph(report.Attention)
		verdict = append(verdict,
			fmt.Sprintf("%s%s%s %s %s %s available", c.Yellow, glyph, c.Reset, b.version, c.Glyph(report.Fix), b.latest),
			fmt.Sprintf("%s%s corral update", strings.Repeat(" ", utf8.RuneCountInString(glyph)+1), c.Glyph(report.Fix)))
	}
	blue := func(s string) string { return c.Blue + s + c.Reset }

	rollup := []report.Row{{Label: "project", Value: blue(abbrevHome(b.workdir, b.home)) + "   " + c.Green + "rw" + c.Reset}}
	if rw := cfg.Providers.Paths.RW; len(rw) > 0 {
		rollup = append(rollup, report.Row{Label: "writable", Value: pathsValue(c, rw, b.home)})
	}
	if ro := cfg.Providers.Paths.RO; len(ro) > 0 {
		rollup = append(rollup, report.Row{Label: "read-only", Value: pathsValue(c, ro, b.home)})
	}
	home := blue("host $HOME")
	if cfg.Providers.Home.Enabled {
		home = blue("private $HOME") + "   " + c.Dim + "kept between sessions" + c.Reset
	}
	rollup = append(rollup,
		report.Row{Label: "home", Value: home},
		report.Row{Label: "policy", Value: "audit events in " + blue(abbrevHome(b.auditLog, b.home))},
		// "!" bash-mode runs outside every hook, so neither its command nor its output is seen.
		report.Row{Value: c.Dim + "! bash-mode is not checked or secret-scanned" + c.Reset},
	)
	c.Header(w, title, verdict, rollup)

	if len(cfgWarnings)+len(warnings) > 0 {
		fmt.Fprintln(w)
		writeChecks(w, c, cfgWarnings, b.home)
		writeWarnings(w, c, warnings)
	}
}

// writeBannerBody prints the providers section: one row per provider status line
// (secret-free), recording what happened at launch. The provider name prints once per
// consecutive run. launchOnly names the dry-run providers that act only at launch.
func writeBannerBody(w io.Writer, c report.Style, home string, notices []providers.Notice, launchOnly []string) {
	fmt.Fprintln(w)
	c.Rule(w, "providers")
	if len(notices)+len(launchOnly) == 0 {
		c.Message(w, report.None, "(none)")
	}
	prev := ""
	for _, n := range notices {
		text := abbrevText(n.Text, home)
		if n.Provider == prev {
			c.Cont(w, text)
			continue
		}
		prev = n.Provider
		c.Row(w, report.Row{Glyph: report.On, Label: n.Provider, Value: text})
	}
	for _, name := range launchOnly {
		c.Row(w, report.Row{Glyph: report.Off, Label: name, Value: "acts only at launch (not expanded in this dry-run)"})
	}
}

// writeChecks renders warning checks as detail rows, home-abbreviated, each with its fix.
func writeChecks(w io.Writer, c report.Style, checks []health.Check, home string) {
	for _, ch := range checks {
		c.Row(w, report.Row{Glyph: report.Attention, Label: ch.Label, Value: abbrevText(ch.Value, home), Reason: abbrevText(ch.Reason, home)})
		if ch.Fix != "" {
			c.Cont(w, c.Glyph(report.Fix)+" "+ch.Fix)
		}
	}
}

// writeWarnings renders advisory warning lines.
func writeWarnings(w io.Writer, c report.Style, warnings []string) {
	for _, msg := range warnings {
		c.Message(w, report.Attention, msg)
	}
}

// abbrevHome replaces a leading home component with ~ for display.
func abbrevHome(p, home string) string {
	if home == "" {
		return p
	}
	home = filepath.Clean(home)
	if home == "/" {
		return p
	}
	if p == home {
		return "~"
	}
	if strings.HasPrefix(p, home+"/") {
		return "~" + p[len(home):]
	}
	return p
}

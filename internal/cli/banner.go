package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/registry"
	"github.com/go-corral/corral/internal/sandbox/seatbelt"
)

// sessionWarnings returns advisory notices about the effective config, shared by the `run`
// banner and `corral validate`. roTargets is the resolved backend's read-only baseline targets,
// supplied by the caller so the warning matches the backend that compiles the spec.
func sessionWarnings(cfg *config.Config, roTargets []string) []string {
	var w []string

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
			w = append(w, fmt.Sprintf("providers.paths.rw %q overlaps the baseline read-only system path %q and re-exposes it as writable, "+
				"overriding corral's default protection", g, ro))
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

// writePathRows prints one row per path under a single label, home-abbreviated. No paths
// renders "(none)".
func writePathRows(w io.Writer, c report.Style, label string, paths []string, home string) {
	if len(paths) == 0 {
		c.Row(w, report.Row{Label: label, Value: "(none)"})
		return
	}
	c.Row(w, report.Row{Label: label, Value: abbrevHome(paths[0], home)})
	for _, p := range paths[1:] {
		c.Cont(w, abbrevHome(p, home))
	}
}

// abbrevText replaces the home prefix with ~ anywhere in a free-text status line (the
// per-path form is abbrevHome). home == "" is a no-op.
func abbrevText(s, home string) string {
	if home == "" {
		return s
	}
	return strings.ReplaceAll(s, home, "~")
}

// blockedSummary builds the one-line "blocked" value: the always-blocked paths (tagged),
// then config-added paths after a "+" — home-abbreviated and deduped. aiignore masks are
// not part of it: they surface as the aiignore provider's status line in the providers tree.
func blockedSummary(c report.Style, cfg *config.Config, home string) string {
	floor := config.AlwaysBlockedExpanded(home)
	shown := make(map[string]bool, len(floor))
	abbrevFloor := make([]string, len(floor))
	for i, p := range floor {
		shown[p] = true
		abbrevFloor[i] = abbrevHome(p, home)
	}
	var added []string
	for _, p := range cfg.EffectiveBlockedPaths(home) {
		if !shown[p] {
			shown[p] = true
			added = append(added, abbrevHome(p, home))
		}
	}
	s := fmt.Sprintf("%s %s(always blocked)%s", strings.Join(abbrevFloor, " "), c.Dim, c.Reset)
	if len(added) > 0 {
		s += " + " + strings.Join(added, " ")
	}
	return s
}

// bannerVersion renders the build version: prefix "v" only for digit-leading stamps.
func bannerVersion(version string) string {
	if version != "" && version[0] >= '0' && version[0] <= '9' {
		return "v" + version
	}
	return version
}

// writeStartupBanner prints the launch banner to w. Split into header and body so the
// real launch can slot its confirmation gate between them.
func writeStartupBanner(w io.Writer, c report.Style, cfg *config.Config, version, versionWarn, home string, profiles []string, workdir string, warnings []string, notices []providers.Notice) {
	writeBannerHeader(w, c, version, versionWarn, warnings)
	writeBannerBody(w, c, cfg, home, profiles, workdir, notices)
}

// writeBannerHeader prints the top of the banner: the logo with title+version and warnings.
func writeBannerHeader(w io.Writer, c report.Style, version, versionWarn string, warnings []string) {
	verdict := ""
	if versionWarn != "" {
		verdict = fmt.Sprintf("%s%s%s %s", c.Yellow, c.Glyph(report.Attention), c.Reset, versionWarn)
	}
	c.Header(w, fmt.Sprintf("%s%scorral%s %s%s %s sandbox active%s", c.Bold, c.Green, c.Reset, c.Dim, bannerVersion(version), c.Sep(), c.Reset), verdict, nil)

	// Warnings sit on top of the config info.
	if len(warnings) > 0 {
		writeWarnings(w, c, warnings)
		fmt.Fprintln(w)
	}
}

// writeBannerBody prints the config summary: session, workdir, access block, and providers.
func writeBannerBody(w io.Writer, c report.Style, cfg *config.Config, home string, profiles []string, workdir string, notices []providers.Notice) {
	// Stacked profiles render in application order (rightmost wins).
	prof := strings.Join(profiles, ", ")
	if prof == "" {
		prof = "(none)"
	}
	// session: low-cardinality knobs on one line.
	field := func(k, v string) string { return fmt.Sprintf("%s%s%s %s", c.Dim, k, c.Reset, v) }
	sep := fmt.Sprintf(" %s%s%s ", c.Dim, c.Sep(), c.Reset)
	sessionFields := []string{
		field("profile", prof),
		field("network", fmt.Sprint(cfg.Net)),
	}
	// Agent-specific knobs come from the config bridge.
	for _, f := range cfg.AgentBannerFields() {
		sessionFields = append(sessionFields, field(f.Label, f.Value))
	}
	c.Row(w, report.Row{Label: "session", Value: strings.Join(sessionFields, sep)})
	c.Row(w, report.Row{Label: "workdir", Value: abbrevHome(workdir, home)})

	fmt.Fprintln(w)

	writePathRows(w, c, "read-only", cfg.Providers.Paths.RO, home)
	writePathRows(w, c, "read-write", cfg.Providers.Paths.RW, home)
	c.Row(w, report.Row{Label: "blocked", Value: blockedSummary(c, cfg, home)})
	// "!" bash-mode runs outside every hook, so its output is unscanned.
	c.Row(w, report.Row{Label: "note", Value: "! bash-mode output is not secret-scanned; don't use ! to read secrets in"})

	fmt.Fprintln(w)

	// Per-provider status rows (secret-free). Dynamic-only: a row records what happened at
	// launch, never static config the rows above show. The provider name prints once per
	// consecutive run.
	if len(notices) == 0 {
		c.Row(w, report.Row{Label: "providers", Value: "(none)"})
	}
	prev := ""
	for i, n := range notices {
		name := ""
		if n.Provider != prev {
			name, prev = n.Provider, n.Provider
		}
		v := fmt.Sprintf("%s%-*s%s%s%s%s", c.Dim, provNameW, name, c.Reset, c.Green, abbrevText(n.Text, home), c.Reset)
		if i == 0 {
			c.Row(w, report.Row{Label: "providers", Value: v})
		} else {
			c.Cont(w, v)
		}
	}
}

// provNameW is the width of the provider-name column inside the providers value.
const provNameW = 11

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

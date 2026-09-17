package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/registry"
	"github.com/go-corral/corral/internal/sandbox/seatbelt"
)

// ansi holds optional terminal color codes. When color is disabled every field is
// the empty string, so call sites can wrap text unconditionally (`c.warn + s + c.reset`)
// and get plain output.
type ansi struct {
	reset, bold, dim, green, yellow, red, brand string
}

// colors returns populated codes when enabled, else all-empty (no-op) codes.
func colors(enabled bool) ansi {
	if !enabled {
		return ansi{}
	}
	return ansi{
		reset:  "\x1b[0m",
		bold:   "\x1b[1m",
		dim:    "\x1b[2m",
		green:  "\x1b[32m",
		yellow: "\x1b[33m",
		red:    "\x1b[31m",
		// brand is corral's mark color #E2552B as a 24-bit truecolor SGR, used only by the
		// decorative startup logo.
		brand: "\x1b[38;2;226;85;43m",
	}
}

// colorTo reports whether ANSI color should be emitted to f: it must be a terminal and the
// environment must not disable styling. A pipe/file (as in tests, or when output is
// redirected) gets plain text.
func colorTo(f *os.File) bool {
	return !styleDisabledByEnv() && isTerminal(f)
}

// styleDisabledByEnv reports whether NO_COLOR (https://no-color.org) is set or TERM is "dumb".
func styleDisabledByEnv() bool {
	return os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"
}

// isTerminal reports whether f is an interactive terminal (false for a pipe, file, or closed
// handle, as in tests/CI/`claude -p`). Asks the tty driver via term.IsTerminal, not a
// char-device mode bit: /dev/null is a char device too, so a mode check would misread
// `corral run < /dev/null` as interactive.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

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

// bannerIndent / bannerLabelW define the banner's aligned grid: a 2-space indent, then a
// left-justified label column, then the value column. Continuation lines (extra paths, the
// provider tree) align under the value column. bannerCont is that value-column indent.
const (
	bannerIndent = "  "
	bannerLabelW = 11
)

func bannerCont() string { return strings.Repeat(" ", len(bannerIndent)+bannerLabelW) }

// bannerLine prints one labeled row (`  <label>   <values[0]>`) with further values
// aligned under the value column. An empty values renders "(none)". The label is dim; values
// (which may carry their own color) are printed as-is.
func bannerLine(w io.Writer, c ansi, label string, values []string) {
	first := "(none)"
	if len(values) > 0 {
		first = values[0]
	}
	fmt.Fprintf(w, "%s%s%-*s%s%s\n", bannerIndent, c.dim, bannerLabelW, label, c.reset, first)
	if len(values) > 1 {
		cont := bannerCont()
		for _, v := range values[1:] {
			fmt.Fprintf(w, "%s%s\n", cont, v)
		}
	}
}

// abbrevAll abbreviates each path against home (~) for display; nil/empty in → empty out
// (so bannerLine renders "(none)").
func abbrevAll(paths []string, home string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = abbrevHome(p, home)
	}
	return out
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
func blockedSummary(c ansi, cfg *config.Config, home string) string {
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
	s := fmt.Sprintf("%s %s(always blocked)%s", strings.Join(abbrevFloor, " "), c.dim, c.reset)
	if len(added) > 0 {
		s += " + " + strings.Join(added, " ")
	}
	return s
}

// corralLogo is the ASCII corral mark (assets/logo.svg): a full-block pen with an open gate
// on the right. Purely decorative — it degrades to uncolored blocks when color is off.
var corralLogo = []string{
	"████████████",
	"█          █",
	"█  ████  █",
	"█  ████  █",
	"█          █",
	"████████████",
}

// logoWidth is the logo's column width; ragged open-gate rows are padded to it before the
// text column. logoGap is the gutter between logo and text.
const (
	logoWidth = 12
	logoGap   = "  "
)

// writeLogoBeside prints the brand-colored logo with header lines beside each row.
func writeLogoBeside(w io.Writer, c ansi, lines []string) {
	for i, art := range corralLogo {
		text := ""
		if i < len(lines) {
			text = lines[i]
		}
		// Logo-only rows skip the pad+gutter.
		row := bannerIndent + c.brand + art + c.reset
		if text != "" {
			pad := strings.Repeat(" ", logoWidth-utf8.RuneCountInString(art))
			row += pad + logoGap + text
		}
		fmt.Fprintln(w, row)
	}
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
func writeStartupBanner(w io.Writer, c ansi, cfg *config.Config, version, versionWarn, home string, profiles []string, workdir string, warnings []string, notices []providers.Notice) {
	writeBannerHeader(w, c, version, versionWarn, warnings)
	writeBannerBody(w, c, cfg, home, profiles, workdir, notices)
}

// writeBannerHeader prints the top of the banner: the logo with title+version and warnings.
func writeBannerHeader(w io.Writer, c ansi, version, versionWarn string, warnings []string) {
	fmt.Fprintln(w)
	header := make([]string, len(corralLogo))
	header[2] = fmt.Sprintf("%s%scorral%s %s%s · sandbox active%s", c.bold, c.green, c.reset, c.dim, bannerVersion(version), c.reset)
	if versionWarn != "" {
		header[3] = fmt.Sprintf("%s⚠ %s%s", c.yellow, versionWarn, c.reset)
	}
	writeLogoBeside(w, c, header)
	fmt.Fprintln(w)

	// Warnings sit on top of the config info.
	if len(warnings) > 0 {
		writeWarnings(w, c, warnings)
		fmt.Fprintln(w)
	}
}

// writeBannerBody prints the config summary: session, workdir, access block, and providers.
func writeBannerBody(w io.Writer, c ansi, cfg *config.Config, home string, profiles []string, workdir string, notices []providers.Notice) {
	// Stacked profiles render in application order (rightmost wins).
	prof := strings.Join(profiles, ", ")
	if prof == "" {
		prof = "(none)"
	}
	// session: low-cardinality knobs on one line.
	field := func(k, v string) string { return fmt.Sprintf("%s%s%s %s", c.dim, k, c.reset, v) }
	sep := fmt.Sprintf(" %s·%s ", c.dim, c.reset)
	sessionFields := []string{
		field("profile", prof),
		field("network", fmt.Sprint(cfg.Net)),
	}
	// Agent-specific knobs come from the config bridge.
	for _, f := range cfg.AgentBannerFields() {
		sessionFields = append(sessionFields, field(f.Label, f.Value))
	}
	bannerLine(w, c, "session", []string{strings.Join(sessionFields, sep)})
	bannerLine(w, c, "workdir", []string{abbrevHome(workdir, home)})

	fmt.Fprintln(w)

	bannerLine(w, c, "read-only", abbrevAll(cfg.Providers.Paths.RO, home))
	bannerLine(w, c, "read-write", abbrevAll(cfg.Providers.Paths.RW, home))
	bannerLine(w, c, "blocked", []string{blockedSummary(c, cfg, home)})
	// "!" bash-mode runs outside every hook, so its output is unscanned.
	bannerLine(w, c, "note", []string{"! bash-mode output is not secret-scanned — don't use ! to read secrets in"})

	fmt.Fprintln(w)

	// Per-provider status rows (secret-free). Dynamic-only: a row records what happened at
	// launch, never static config the rows above show.
	if len(notices) == 0 {
		bannerLine(w, c, "providers", nil)
	} else {
		writeNotices(w, c, home, notices)
	}
}

// writeWarnings renders advisory warning lines in the banner's yellow style.
func writeWarnings(w io.Writer, c ansi, warnings []string) {
	for _, msg := range warnings {
		fmt.Fprintf(w, "  %s⚠ %s%s\n", c.yellow, msg, c.reset)
	}
}

// provNameW is the width of the provider-name column.
const provNameW = 11

// writeNotices renders the per-provider status rows of the "providers" section.
func writeNotices(w io.Writer, c ansi, home string, notices []providers.Notice) {
	prev := ""
	for i, n := range notices {
		lead := bannerCont()
		if i == 0 {
			lead = fmt.Sprintf("%s%s%-*s%s", bannerIndent, c.dim, bannerLabelW, "providers", c.reset)
		}
		name := ""
		if n.Provider != prev {
			name, prev = n.Provider, n.Provider
		}
		fmt.Fprintf(w, "%s%s%-*s%s%s%s%s\n", lead, c.dim, provNameW, name, c.reset, c.green, abbrevText(n.Text, home), c.reset)
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

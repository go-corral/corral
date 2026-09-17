package cli

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/audit"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/trust"
)

// cmdUninstall reports corral's system footprint and removes it with --apply.
// A bare `corral uninstall` is read-only: it prints and deletes nothing.
func cmdUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	var (
		apply = fs.Bool("apply", false, "perform the removal (default: report the footprint and delete nothing)")
		yes   = fs.Bool("yes", false, "skip every confirmation prompt (requires --apply)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: corral uninstall [--apply] [--yes]")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	// --yes is meaningless without --apply.
	if *yes && !*apply {
		return fatalf(os.Stderr, "--yes only applies with --apply; a bare `corral uninstall` deletes nothing.")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fatalf(os.Stderr, "cannot resolve home: %v", err)
	}
	return runUninstall(uninstallOptions{
		Home:   home,
		Host:   envMap(),
		Apply:  *apply,
		Yes:    *yes,
		Colors: colors(colorTo(os.Stdout)),
	}, os.Stdin, os.Stdout)
}

// uninstallOptions is the flag-free input to runUninstall for tests.
type uninstallOptions struct {
	Home   string
	Host   map[string]string
	Apply  bool
	Yes    bool
	Colors ansi
}

// runUninstall is the testable core: collect the footprint, then either print it or run removal.
func runUninstall(opts uninstallOptions, in io.Reader, out io.Writer) int {
	// Warn-and-allow: inside the sandbox every path resolves against the sandbox-private $HOME.
	if sandbox.InsideCorral() {
		writeWarnings(out, opts.Colors, []string{
			"running inside a corral sandbox — the paths below resolve to the sandbox-private $HOME, not the host's. Run `corral uninstall` on the host to see (or remove) the real installation.",
		})
	}

	fp := collectUninstallFootprint(opts)
	if !opts.Apply {
		printUninstallFootprint(out, opts.Colors, fp)
		fmt.Fprintln(out, "\nnothing was deleted. `corral uninstall --apply` removes the enforcement, cache, state and audit entries above.")
		return 0
	}
	// One buffered reader serves all phase prompts.
	return applyUninstall(opts, fp, bufio.NewReader(in), out)
}

// --- footprint collection (read-only) ---

// uninstallFootprint is everything `corral uninstall` reports on, collected once.
type uninstallFootprint struct {
	Home   string
	Agents []agentEnforcement
	Cache  cacheFootprint
	State  stateFootprint
	Audit  []auditFootprint

	// Binary / BinaryErr locate the running corral executable (print-only).
	Binary    string
	BinaryErr error
	// GlobalConfig is the user's own global config (print-only).
	GlobalConfig       string
	GlobalConfigExists bool

	// Cfg is the loaded config; nil when it failed to load.
	Cfg       *config.Config
	ConfigErr error
}

// agentEnforcement is one known agent's enforcement-registration state.
type agentEnforcement struct {
	Name       string
	ConfigDir  string
	Registered bool
	Messages   []string
	Err        error
}

// cacheFootprint is corral's host cache dir and its top-level entries.
type cacheFootprint struct {
	Dir     string
	Exists  bool
	Entries []cacheEntry
}

// cacheEntry is one top-level entry under the cache dir.
type cacheEntry struct {
	Name string
	Path string
	Size int64
}

// stateFootprint is corral's state dir: the trust store's approval records.
type stateFootprint struct {
	Dir      string // ~/.local/state/corral (or $XDG_STATE_HOME/corral) — what gets removed
	TrustDir string // <Dir>/trust — where the approval records live
	Exists   bool
	Records  int
}

// auditFootprint is one audit log candidate and its siblings.
type auditFootprint struct {
	Path       string
	Source     string // why this path: the config key, or the agent whose config dir it defaults under
	Exists     bool
	Size       int64
	Backups    []string
	Lock       string
	LockExists bool
}

// collectUninstallFootprint gathers the whole report without touching anything.
func collectUninstallFootprint(opts uninstallOptions) uninstallFootprint {
	fp := uninstallFootprint{Home: opts.Home}
	fp.Cfg, fp.GlobalConfig, fp.GlobalConfigExists, fp.ConfigErr = loadHostConfig(opts.Home)
	fp.Agents = collectAgentEnforcement(opts.Home, opts.Host)
	fp.Cache = collectCacheFootprint(opts.Home)
	fp.State = collectStateFootprint(opts.Home)
	fp.Audit = collectAuditFootprint(fp.Cfg, opts.Home, opts.Host)
	fp.Binary, fp.BinaryErr = updateTarget()
	return fp
}

// loadHostConfig loads the layered config ungated. Returns the config, the resolved global
// config path, whether it exists, and any load error. An invalid config degrades the report.
func loadHostConfig(home string) (cfg *config.Config, globalPath string, exists bool, err error) {
	cfg, sources, err := loadConfig(nil)
	// Name the global config even when it does not exist.
	globalPath = os.Getenv(sandbox.GlobalConfigEnvVar)
	if globalPath == "" {
		globalPath = defaultGlobalConfigPath(home)
	}
	for _, s := range sources {
		if s.Kind == "global" && s.Path != "" {
			globalPath = s.Path
		}
	}
	_, statErr := os.Stat(globalPath)
	return cfg, globalPath, statErr == nil, err
}

// defaultGlobalConfigPath mirrors config's own default resolution for the global config file.
func defaultGlobalConfigPath(home string) string {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "corral", "config.yml")
	}
	return filepath.Join(home, ".config", "corral", "config.yml")
}

// corralCacheDir is corral's host cache dir. Hardcoded under ~/.cache (every writer does the same).
func corralCacheDir(home string) string { return filepath.Join(home, ".cache", "corral") }

// collectAgentEnforcement asks every known agent whether corral's enforcement is registered
// via a DryRun+Remove Sync (writes nothing).
func collectAgentEnforcement(home string, host map[string]string) []agentEnforcement {
	var out []agentEnforcement
	for _, name := range agents.Known() {
		a, ok := agents.Lookup(name)
		if !ok {
			continue
		}
		e := agentEnforcement{Name: name, ConfigDir: a.ConfigDir(home, host)}
		report, err := a.Sync(agents.SyncInput{Home: home, Host: host, Remove: true, DryRun: true})
		if err != nil {
			e.Err = err
		} else {
			e.Registered, e.Messages = report.Changed, report.Messages
		}
		out = append(out, e)
	}
	return out
}

// collectCacheFootprint lists the top-level entries under corral's cache dir.
func collectCacheFootprint(home string) cacheFootprint {
	out := cacheFootprint{Dir: corralCacheDir(home)}
	entries, err := os.ReadDir(out.Dir)
	if err != nil {
		return out
	}
	out.Exists = true
	for _, e := range entries {
		path := filepath.Join(out.Dir, e.Name())
		out.Entries = append(out.Entries, cacheEntry{Name: e.Name(), Path: path, Size: treeSize(path)})
	}
	return out
}

// treeSize is the recursive size of a file or directory, best-effort.
func treeSize(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// collectStateFootprint reports corral's state dir — only the record count is collected.
func collectStateFootprint(home string) stateFootprint {
	trustDir := trust.DefaultDir(home)
	out := stateFootprint{Dir: filepath.Dir(trustDir), TrustDir: trustDir}
	if _, err := os.Stat(out.Dir); err == nil {
		out.Exists = true
	}
	entries, err := os.ReadDir(trustDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			out.Records++
		}
	}
	return out
}

// collectAuditFootprint resolves the audit logs uninstall would delete. effectiveAuditPath is
// the same resolver the hook's auditor uses.
func collectAuditFootprint(cfg *config.Config, home string, host map[string]string) []auditFootprint {
	if cfg == nil {
		cfg = &config.Config{} // unloadable config: fall back to the per-agent defaults
	}
	seen := map[string]bool{}
	var out []auditFootprint
	for _, name := range agents.Known() {
		a, ok := agents.Lookup(name)
		if !ok {
			continue
		}
		path := effectiveAuditPath(cfg, a.ConfigDir(home, host))
		if seen[path] {
			continue
		}
		seen[path] = true
		source := name + " default"
		if cfg.Policy.Audit.Path != "" {
			source = "policy.audit.path"
		}
		af := auditFootprint{Path: path, Source: source, Lock: path + ".lock"}
		if info, err := os.Stat(path); err == nil {
			af.Exists, af.Size = true, info.Size()
			af.Backups = audit.Backups(path)
			if _, lerr := os.Stat(af.Lock); lerr == nil {
				af.LockExists = true
			}
		}
		out = append(out, af)
	}
	return out
}

// --- manifest rendering ---

// uninstallIndent / uninstallLabelW define the manifest's aligned grid.
const (
	uninstallIndent = "  "
	uninstallLabelW = 10
)

// uninstallRow prints one labeled manifest row.
func uninstallRow(w io.Writer, c ansi, label, text string) {
	fmt.Fprintf(w, "%s%s%-*s%s%s\n", uninstallIndent, c.dim, uninstallLabelW, label+":", c.reset, text)
}

// uninstallCont prints a continuation line aligned under a row's text column.
func uninstallCont(w io.Writer, text string) {
	fmt.Fprintf(w, "%s%s%s\n", uninstallIndent, strings.Repeat(" ", uninstallLabelW), text)
}

// printUninstallFootprint renders the read-only manifest.
func printUninstallFootprint(out io.Writer, c ansi, fp uninstallFootprint) {
	fmt.Fprintf(out, "%scorral's footprint on this system%s\n", c.bold, c.reset)
	if fp.ConfigErr != nil {
		writeWarnings(out, c, []string{fmt.Sprintf("global config is invalid (%v) — reporting corral's default locations instead", fp.ConfigErr)})
	}
	reportUninstallEnforcement(out, c, fp)
	reportUninstallState(out, c, fp)
	reportUninstallKept(out, c, fp)
}

// reportUninstallEnforcement lists, per known agent, whether corral's enforcement is registered.
func reportUninstallEnforcement(out io.Writer, c ansi, fp uninstallFootprint) {
	fmt.Fprintln(out, "\nEnforcement (corral's registration in each agent's own config):")
	for _, a := range fp.Agents {
		switch {
		case a.Err != nil:
			uninstallRow(out, c, a.Name, fmt.Sprintf("cannot determine (%v)", a.Err))
		case a.Registered:
			uninstallRow(out, c, a.Name, fmt.Sprintf("%sREGISTERED%s — config dir %s", c.yellow, c.reset, abbrevHome(a.ConfigDir, fp.Home)))
		default:
			uninstallRow(out, c, a.Name, "not registered — config dir "+abbrevHome(a.ConfigDir, fp.Home))
		}
		for _, m := range a.Messages {
			// abbrevText, not abbrevHome: an agent's message embeds paths mid-sentence.
			uninstallCont(out, strings.TrimSuffix(abbrevText(m, fp.Home), ":"))
		}
	}
}

// reportUninstallState lists corral's own state: cache, trust/state dir, and audit logs.
func reportUninstallState(out io.Writer, c ansi, fp uninstallFootprint) {
	fmt.Fprintln(out, "\nState (removed by `--apply`):")

	if !fp.Cache.Exists {
		uninstallRow(out, c, "cache", abbrevHome(fp.Cache.Dir, fp.Home)+" — not present")
	} else {
		uninstallRow(out, c, "cache", abbrevHome(fp.Cache.Dir, fp.Home))
		if len(fp.Cache.Entries) == 0 {
			uninstallCont(out, "(empty)")
		}
		for _, e := range fp.Cache.Entries {
			uninstallCont(out, fmt.Sprintf("%-24s %9s", e.Name, humanSize(e.Size)))
		}
	}

	stateText := abbrevHome(fp.State.Dir, fp.Home)
	if !fp.State.Exists {
		stateText += " — not present"
	} else {
		stateText += fmt.Sprintf(" — %d approval record(s)", fp.State.Records)
	}
	uninstallRow(out, c, "state", stateText)

	for _, af := range fp.Audit {
		text := fmt.Sprintf("%s (%s)", abbrevHome(af.Path, fp.Home), af.Source)
		if !af.Exists {
			uninstallRow(out, c, "audit", text+" — not present")
			continue
		}
		text += fmt.Sprintf(" — %s, %d rotated backup(s)", humanSize(af.Size), len(af.Backups))
		if af.LockExists {
			text += ", + " + filepath.Base(af.Lock)
		}
		uninstallRow(out, c, "audit", text)
	}
}

// reportUninstallKept prints the print-only section: things uninstall never deletes.
func reportUninstallKept(out io.Writer, c ansi, fp uninstallFootprint) {
	fmt.Fprintln(out, "\nKept — uninstall never deletes these (remove them yourself if you want them gone):")

	if fp.BinaryErr != nil {
		uninstallRow(out, c, "binary", fmt.Sprintf("cannot resolve this executable (%v)", fp.BinaryErr))
	} else {
		uninstallRow(out, c, "binary", abbrevHome(fp.Binary, fp.Home))
		uninstallCont(out, "rm "+fp.Binary)
	}
	uninstallCont(out, "and drop any `alias claude='corral run --'` from your shell rc (~/.bashrc, ~/.zshrc, …)")

	if fp.GlobalConfigExists {
		uninstallRow(out, c, "config", abbrevHome(fp.GlobalConfig, fp.Home))
		uninstallCont(out, "rm "+fp.GlobalConfig)
	} else {
		uninstallRow(out, c, "config", abbrevHome(fp.GlobalConfig, fp.Home)+" — not present")
	}

	uninstallRow(out, c, "plugin", "the corral-helper Claude Code plugin, if you installed it")
	uninstallCont(out, "claude plugin uninstall corral-helper@corral")
	uninstallCont(out, "claude plugin marketplace remove corral")
}

// humanSize formats a byte count for the manifest (SI units).
func humanSize(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	v := float64(n)
	for _, suffix := range []string{"kB", "MB", "GB", "TB"} {
		v /= unit
		if v < unit {
			return fmt.Sprintf("%.1f %s", v, suffix)
		}
	}
	return fmt.Sprintf("%.1f PB", v/unit)
}

// --- removal ---

// applyUninstall runs the removal phases in order, each behind its own confirmation.
func applyUninstall(opts uninstallOptions, fp uninstallFootprint, in io.Reader, out io.Writer) int {
	failed := uninstallGCPhase(opts, fp, in, out)
	failed = deregisterPhase(opts, fp, in, out) || failed
	failed = cachePhase(opts, fp, in, out) || failed
	failed = statePhase(opts, fp, in, out) || failed
	failed = auditPhase(opts, fp, in, out) || failed

	reportUninstallKept(out, opts.Colors, fp)
	if failed {
		fmt.Fprintln(out, "\ncorral uninstall: finished with errors (see above).")
		return 1
	}
	fmt.Fprintln(out, "\ncorral uninstall: done.")
	return 0
}

// confirmPhase gates one destructive phase. Default-no: --yes pre-approves, EOF declines.
func confirmPhase(opts uninstallOptions, in io.Reader, out io.Writer, prompt string) bool {
	if opts.Yes {
		return true
	}
	return promptYesNo(in, out, prompt)
}

// skipped prints the visible "declined" marker.
func skipped(out io.Writer) { fmt.Fprintln(out, uninstallIndent+"skipped.") }

// uninstallGCPhase reaps orphaned provider resources before the rest of the removal, while
// the config is still readable. Delegates to runGC (its own preview and confirmation). A failure
// is a warning, not a stop.
func uninstallGCPhase(opts uninstallOptions, fp uninstallFootprint, in io.Reader, out io.Writer) bool {
	fmt.Fprintln(out, "\nOrphaned provider resources:")
	if fp.Cfg == nil {
		fmt.Fprintf(out, "%scannot check: %v — reap them with `corral gc` once the config is fixed.\n", uninstallIndent, fp.ConfigErr)
		return true
	}
	reapers := providers.Reapers(gcCandidates(fp.Cfg, opts.Home, opts.Host))
	if code := runGC(context.Background(), reapers, gcOptions{Yes: opts.Yes}, in, out); code != 0 {
		fmt.Fprintln(out, uninstallIndent+"warning: orphaned resources may remain — continuing with the local footprint.")
		return true
	}
	return false
}

// deregisterPhase removes corral's enforcement registration from every known agent.
func deregisterPhase(opts uninstallOptions, fp uninstallFootprint, in io.Reader, out io.Writer) bool {
	fmt.Fprintln(out, "\nDe-register enforcement:")
	if !confirmPhase(opts, in, out, fmt.Sprintf("%sDe-register corral's enforcement for %s? [y/N] ",
		uninstallIndent, strings.Join(agents.Known(), ", "))) {
		skipped(out)
		return false
	}
	failed := false
	for _, name := range agents.Known() {
		a, ok := agents.Lookup(name)
		if !ok {
			continue
		}
		report, err := a.Sync(agents.SyncInput{Home: opts.Home, Host: opts.Host, Remove: true})
		if err != nil {
			fmt.Fprintf(out, "%s%s: %v\n", uninstallIndent, name, err)
			failed = true
			continue
		}
		for _, m := range report.Messages {
			fmt.Fprintf(out, "%s%s: %s\n", uninstallIndent, name, m)
		}
		if report.Diff != nil {
			fmt.Fprint(out, unifiedDiff(report.Diff.Before, report.Diff.After, report.Diff.FromLabel, report.Diff.ToLabel, opts.Colors))
		}
	}
	return failed
}

// cachePhase deletes corral's cache dir wholesale.
func cachePhase(opts uninstallOptions, fp uninstallFootprint, in io.Reader, out io.Writer) bool {
	fmt.Fprintln(out, "\nCache:")
	if !fp.Cache.Exists {
		fmt.Fprintf(out, "%s%s — not present, nothing to remove.\n", uninstallIndent, abbrevHome(fp.Cache.Dir, opts.Home))
		return false
	}
	if !confirmPhase(opts, in, out, fmt.Sprintf("%sDelete %s (%d entr%s)? [y/N] ",
		uninstallIndent, abbrevHome(fp.Cache.Dir, opts.Home), len(fp.Cache.Entries), plural(len(fp.Cache.Entries), "y", "ies"))) {
		skipped(out)
		return false
	}
	if err := os.RemoveAll(fp.Cache.Dir); err != nil {
		fmt.Fprintf(out, "%scannot delete %s: %v\n", uninstallIndent, abbrevHome(fp.Cache.Dir, opts.Home), err)
		return true
	}
	fmt.Fprintf(out, "%sdeleted %s\n", uninstallIndent, abbrevHome(fp.Cache.Dir, opts.Home))
	return false
}

// statePhase deletes corral's state dir — the trust store's approval records.
func statePhase(opts uninstallOptions, fp uninstallFootprint, in io.Reader, out io.Writer) bool {
	fmt.Fprintln(out, "\nState directory:")
	if !fp.State.Exists {
		fmt.Fprintf(out, "%s%s — not present, nothing to remove.\n", uninstallIndent, abbrevHome(fp.State.Dir, opts.Home))
		return false
	}
	if !confirmPhase(opts, in, out, fmt.Sprintf("%sDelete %s (%d approval record(s))? [y/N] ",
		uninstallIndent, abbrevHome(fp.State.Dir, opts.Home), fp.State.Records)) {
		skipped(out)
		return false
	}
	if err := os.RemoveAll(fp.State.Dir); err != nil {
		fmt.Fprintf(out, "%scannot delete %s: %v\n", uninstallIndent, abbrevHome(fp.State.Dir, opts.Home), err)
		return true
	}
	fmt.Fprintf(out, "%sdeleted %s\n", uninstallIndent, abbrevHome(fp.State.Dir, opts.Home))
	return false
}

// auditPhase deletes each existing audit log with its rotated backups and lock file.
func auditPhase(opts uninstallOptions, fp uninstallFootprint, in io.Reader, out io.Writer) bool {
	fmt.Fprintln(out, "\nAudit logs:")
	var present []auditFootprint
	for _, af := range fp.Audit {
		if af.Exists {
			present = append(present, af)
		}
	}
	if len(present) == 0 {
		fmt.Fprintln(out, uninstallIndent+"no audit log present, nothing to remove.")
		return false
	}
	files := 0
	for _, af := range present {
		files += 1 + len(af.Backups)
		if af.LockExists {
			files++
		}
	}
	if !confirmPhase(opts, in, out, fmt.Sprintf("%sDelete %d audit log(s) and their rotated backups — %d file(s) total? [y/N] ",
		uninstallIndent, len(present), files)) {
		skipped(out)
		return false
	}
	failed := false
	for _, af := range present {
		targets := append([]string{af.Path}, af.Backups...)
		if af.LockExists {
			targets = append(targets, af.Lock)
		}
		for _, t := range targets {
			// A file that vanished under us is the outcome we wanted.
			if err := os.Remove(t); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(out, "%scannot delete %s: %v\n", uninstallIndent, abbrevHome(t, opts.Home), err)
				failed = true
				continue
			}
			fmt.Fprintf(out, "%sdeleted %s\n", uninstallIndent, abbrevHome(t, opts.Home))
		}
	}
	return failed
}

// plural picks the singular or plural form for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

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
	"github.com/go-corral/corral/internal/cli/report"
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
		Colors: report.StyleFor(os.Stdout),
	}, os.Stdin, os.Stdout)
}

// uninstallOptions is the flag-free input to runUninstall for tests.
type uninstallOptions struct {
	Home   string
	Host   map[string]string
	Apply  bool
	Yes    bool
	Colors report.Style
}

// runUninstall is the testable core: collect the footprint, then either print it or run removal.
func runUninstall(opts uninstallOptions, in io.Reader, out io.Writer) int {
	c := opts.Colors
	ctx := "footprint on this system"
	if opts.Apply {
		ctx = ""
	}
	writeTitle(out, c, "corral uninstall", ctx)
	// Warn-and-allow: inside the sandbox every path resolves against the sandbox-private $HOME.
	if sandbox.InsideCorral() {
		writeWarnings(out, c, []string{
			"running inside a corral sandbox — the paths below resolve to the sandbox-private $HOME, not the host's. Run `corral uninstall` on the host to see (or remove) the real installation.",
		})
	}

	fp := collectUninstallFootprint(opts)
	if !opts.Apply {
		if fp.ConfigErr != nil {
			writeWarnings(out, c, []string{fmt.Sprintf("global config is invalid (%v) — reporting corral's default locations instead", fp.ConfigErr)})
		}
		printUninstallFootprint(out, c, fp)
		fmt.Fprintln(out)
		c.Message(out, report.None, c.Dim+"nothing was deleted"+c.Reset)
		c.Fix(out, "corral uninstall --apply")
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

// uninstallSection opens a section: a blank line, the rule, and a dim note when set.
func uninstallSection(w io.Writer, c report.Style, title, note string) {
	fmt.Fprintln(w)
	c.Rule(w, title)
	if note != "" {
		c.Message(w, report.None, c.Dim+note+c.Reset)
	}
}

// presence returns the footprint glyph for an item that exists or not.
func presence(exists bool) report.Glyph {
	if exists {
		return report.On
	}
	return report.Off
}

// printUninstallFootprint renders the read-only manifest.
func printUninstallFootprint(out io.Writer, c report.Style, fp uninstallFootprint) {
	reportUninstallEnforcement(out, c, fp)
	reportUninstallState(out, c, fp)
	reportUninstallKept(out, c, fp)
}

// reportUninstallEnforcement lists, per known agent, whether corral's enforcement is registered.
func reportUninstallEnforcement(out io.Writer, c report.Style, fp uninstallFootprint) {
	uninstallSection(out, c, "enforcement", "corral's registration in each agent's own config")
	for _, a := range fp.Agents {
		dir := abbrevHome(a.ConfigDir, fp.Home)
		switch {
		case a.Err != nil:
			c.Row(out, report.Row{Glyph: report.Attention, Label: a.Name, Value: fmt.Sprintf("cannot determine (%v)", a.Err)})
		case a.Registered:
			c.Row(out, report.Row{Glyph: report.On, Label: a.Name, Value: "registered — config dir " + dir})
		default:
			c.Row(out, report.Row{Glyph: report.Off, Label: a.Name, Value: "not registered — config dir " + dir})
		}
		for _, m := range a.Messages {
			// abbrevText, not abbrevHome: an agent's message embeds paths mid-sentence.
			c.Cont(out, c.Dim+strings.TrimSuffix(abbrevText(m, fp.Home), ":")+c.Reset)
		}
	}
}

// reportUninstallState lists corral's own state: cache, trust/state dir, and audit logs.
func reportUninstallState(out io.Writer, c report.Style, fp uninstallFootprint) {
	uninstallSection(out, c, "state", "removed by --apply")

	cache := abbrevHome(fp.Cache.Dir, fp.Home)
	if !fp.Cache.Exists {
		cache += " — not present"
	}
	c.Row(out, report.Row{Glyph: presence(fp.Cache.Exists), Label: "cache", Value: cache})
	if fp.Cache.Exists && len(fp.Cache.Entries) == 0 {
		c.Cont(out, "(empty)")
	}
	for _, e := range fp.Cache.Entries {
		c.Cont(out, fmt.Sprintf("%-24s %9s", e.Name, humanSize(e.Size)))
	}

	state := abbrevHome(fp.State.Dir, fp.Home)
	if !fp.State.Exists {
		state += " — not present"
	} else {
		state += fmt.Sprintf(" — %d approval record(s)", fp.State.Records)
	}
	c.Row(out, report.Row{Glyph: presence(fp.State.Exists), Label: "state", Value: state})

	for _, af := range fp.Audit {
		text := fmt.Sprintf("%s (%s)", abbrevHome(af.Path, fp.Home), af.Source)
		if !af.Exists {
			c.Row(out, report.Row{Glyph: report.Off, Label: "audit", Value: text + " — not present"})
			continue
		}
		detail := fmt.Sprintf("%s, %d rotated backup(s)", humanSize(af.Size), len(af.Backups))
		if af.LockExists {
			detail += ", + " + filepath.Base(af.Lock)
		}
		c.Row(out, report.Row{Glyph: report.On, Label: "audit", Value: text, Reason: detail})
	}
}

// reportUninstallKept prints the print-only section: things uninstall never deletes.
func reportUninstallKept(out io.Writer, c report.Style, fp uninstallFootprint) {
	uninstallSection(out, c, "kept", "uninstall never deletes these; remove them yourself if you want them gone")

	if fp.BinaryErr != nil {
		c.Row(out, report.Row{Glyph: report.Attention, Label: "binary", Value: fmt.Sprintf("cannot resolve this executable (%v)", fp.BinaryErr)})
	} else {
		c.Row(out, report.Row{Glyph: report.On, Label: "binary", Value: abbrevHome(fp.Binary, fp.Home)})
		c.Fix(out, shellQuote([]string{"rm", fp.Binary}))
	}
	c.Cont(out, c.Dim+"and drop any `alias claude='corral run --'` from your shell rc (~/.bashrc, ~/.zshrc, …)"+c.Reset)

	if fp.GlobalConfigExists {
		c.Row(out, report.Row{Glyph: report.On, Label: "config", Value: abbrevHome(fp.GlobalConfig, fp.Home)})
		c.Fix(out, shellQuote([]string{"rm", fp.GlobalConfig}))
	} else {
		c.Row(out, report.Row{Glyph: report.Off, Label: "config", Value: abbrevHome(fp.GlobalConfig, fp.Home) + " — not present"})
	}

	c.Row(out, report.Row{Label: "plugin", Value: "the corral-helper Claude Code plugin, if you installed it"})
	c.Fix(out, "claude plugin uninstall corral-helper@corral")
	c.Fix(out, "claude plugin marketplace remove corral")
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
	c := opts.Colors
	failed := uninstallGCPhase(opts, fp, in, out)
	failed = deregisterPhase(opts, in, out) || failed
	failed = removePhase(opts, in, out, "cache", fp.Cache.Dir, fp.Cache.Exists,
		fmt.Sprintf("%d entr%s", len(fp.Cache.Entries), plural(len(fp.Cache.Entries), "y", "ies"))) || failed
	failed = removePhase(opts, in, out, "state directory", fp.State.Dir, fp.State.Exists,
		fmt.Sprintf("%d approval record(s)", fp.State.Records)) || failed
	failed = auditPhase(opts, fp, in, out) || failed

	reportUninstallKept(out, c, fp)
	fmt.Fprintln(out)
	if failed {
		c.Message(out, report.Blocked, "finished with errors (see above)")
		return 1
	}
	c.Message(out, report.Ready, "done")
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
func skipped(out io.Writer, c report.Style) { c.Message(out, report.Off, "skipped") }

// uninstallGCPhase reaps orphaned provider resources before the rest of the removal, while
// the config is still readable. Delegates to runGC (its own preview and confirmation). A failure
// is a warning, not a stop.
func uninstallGCPhase(opts uninstallOptions, fp uninstallFootprint, in io.Reader, out io.Writer) bool {
	c := opts.Colors
	uninstallSection(out, c, "orphaned resources", "")
	if fp.Cfg == nil {
		c.Message(out, report.Attention, fmt.Sprintf("cannot check: %v", fp.ConfigErr))
		c.Cont(out, c.Dim+"reap them with `corral gc` once the config is fixed"+c.Reset)
		return true
	}
	reapers := providers.Reapers(gcCandidates(fp.Cfg, opts.Home, opts.Host))
	if code := runGC(context.Background(), reapers, gcOptions{Yes: opts.Yes, Colors: c}, in, out); code != 0 {
		c.Message(out, report.Attention, "orphaned resources may remain; continuing with the local footprint")
		return true
	}
	return false
}

// deregisterPhase removes corral's enforcement registration from every known agent.
func deregisterPhase(opts uninstallOptions, in io.Reader, out io.Writer) bool {
	c := opts.Colors
	uninstallSection(out, c, "de-register", "")
	if !confirmPhase(opts, in, out, fmt.Sprintf("De-register corral's enforcement for %s? [y/N] ", strings.Join(agents.Known(), ", "))) {
		skipped(out, c)
		return false
	}
	failed := false
	for _, name := range agents.Known() {
		a, ok := agents.Lookup(name)
		if !ok {
			continue
		}
		res, err := a.Sync(agents.SyncInput{Home: opts.Home, Host: opts.Host, Remove: true})
		if err != nil {
			c.Row(out, report.Row{Glyph: report.Blocked, Label: name, Value: err.Error()})
			failed = true
			continue
		}
		for i, m := range res.Messages {
			if i == 0 {
				c.Row(out, report.Row{Glyph: report.Ready, Label: name, Value: abbrevText(m, opts.Home)})
				continue
			}
			c.Cont(out, abbrevText(m, opts.Home))
		}
		if res.Diff != nil {
			fmt.Fprint(out, unifiedDiff(res.Diff.Before, res.Diff.After, res.Diff.FromLabel, res.Diff.ToLabel, c))
		}
	}
	return failed
}

// removePhase deletes one of corral's directories wholesale. what describes its contents
// in the prompt.
func removePhase(opts uninstallOptions, in io.Reader, out io.Writer, section, dir string, exists bool, what string) bool {
	c := opts.Colors
	uninstallSection(out, c, section, "")
	path := abbrevHome(dir, opts.Home)
	if !exists {
		c.Message(out, report.Off, path+" not present")
		return false
	}
	if !confirmPhase(opts, in, out, fmt.Sprintf("Delete %s (%s)? [y/N] ", path, what)) {
		skipped(out, c)
		return false
	}
	return deleteReported(out, c, path, os.RemoveAll(dir))
}

// deleteReported reports one deletion and whether it failed.
func deleteReported(out io.Writer, c report.Style, path string, err error) bool {
	if err != nil {
		c.Message(out, report.Blocked, "cannot delete "+path)
		c.Cont(out, c.Dim+err.Error()+c.Reset)
		return true
	}
	c.Message(out, report.Ready, "deleted "+path)
	return false
}

// auditPhase deletes each existing audit log with its rotated backups and lock file.
func auditPhase(opts uninstallOptions, fp uninstallFootprint, in io.Reader, out io.Writer) bool {
	c := opts.Colors
	uninstallSection(out, c, "audit logs", "")
	var present []auditFootprint
	for _, af := range fp.Audit {
		if af.Exists {
			present = append(present, af)
		}
	}
	if len(present) == 0 {
		c.Message(out, report.Off, "no audit log present")
		return false
	}
	files := 0
	for _, af := range present {
		files += 1 + len(af.Backups)
		if af.LockExists {
			files++
		}
	}
	if !confirmPhase(opts, in, out, fmt.Sprintf("Delete %d audit log(s) and their rotated backups — %d file(s) total? [y/N] ",
		len(present), files)) {
		skipped(out, c)
		return false
	}
	failed := false
	for _, af := range present {
		targets := append([]string{af.Path}, af.Backups...)
		if af.LockExists {
			targets = append(targets, af.Lock)
		}
		for _, t := range targets {
			err := os.Remove(t)
			// A file that vanished under us is the outcome we wanted.
			if os.IsNotExist(err) {
				err = nil
			}
			failed = deleteReported(out, c, abbrevHome(t, opts.Home), err) || failed
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

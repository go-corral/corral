package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
)

// cmdGC collects and (after approval) reaps orphaned out-of-process provider
// resources left by crashed sessions. It is never destructive without confirmation.
func cmdGC(args []string) int {
	fs := flag.NewFlagSet("gc", flag.ContinueOnError)
	var (
		dryRun   = fs.Bool("dry-run", false, "preview orphaned resources without deleting anything")
		yes      = fs.Bool("yes", false, "skip the confirmation prompt and reap all previewed resources")
		profiles = addProfileFlags(fs)
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: corral gc [--dry-run] [--yes] [-p|--profile name]...")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	cfg, _, err := loadConfig([]string(*profiles))
	if err != nil {
		return fatalf(os.Stderr, "load config: %v", err)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return fatalf(os.Stderr, "cannot resolve home: %v", err)
	}
	reapers := providers.Reapers(gcCandidates(cfg, home, envMap()))

	return runGC(context.Background(), reapers, gcOptions{DryRun: *dryRun, Yes: *yes, Title: true, Colors: report.StyleFor(os.Stdout)}, os.Stdin, os.Stdout)
}

// gcCandidates returns the providers `corral gc` should query for orphans.
func gcCandidates(cfg *config.Config, home string, host map[string]string) []providers.Provider {
	var out []providers.Provider
	// gc inspects orphans from past sessions, not the current project.
	for _, a := range activeProviders(cfg, home, host, "", nil, nil) {
		out = append(out, a.Provider)
	}
	return out
}

type gcOptions struct {
	DryRun bool
	Yes    bool
	// Title prints the command's title line; uninstall embeds gc without it.
	Title  bool
	Colors report.Style
}

// runGC is the testable core: collect orphans, preview, and reap the approved set.
func runGC(ctx context.Context, reapers []providers.Reaper, opts gcOptions, in io.Reader, out io.Writer) int {
	c := opts.Colors
	orphans, errs := providers.CollectOrphans(ctx, reapers)
	if opts.Title {
		count := ""
		if len(orphans) > 0 {
			count = resources(len(orphans), "orphaned resource")
		}
		writeTitle(out, c, "corral gc", count)
	}
	for _, e := range errs {
		c.Message(out, report.Attention, e.Error())
	}
	if len(orphans) == 0 {
		if len(errs) > 0 {
			c.Message(out, report.Attention, "no orphaned resources")
			return 1 // a reaper failed to report; surface as non-zero
		}
		c.Message(out, report.Ready, "no orphaned resources")
		return 0
	}

	for _, o := range orphans {
		c.Row(out, report.Row{Glyph: report.On, Label: o.Provider, Value: o.Describe})
	}

	if opts.DryRun {
		c.Message(out, report.None, c.Dim+"dry-run: nothing deleted"+c.Reset)
		return 0
	}
	// Default-no: anything but an explicit yes aborts.
	if !opts.Yes && !promptYesNo(in, out, fmt.Sprintf("Reap these %d resource(s)? [y/N] ", len(orphans))) {
		c.Message(out, report.None, c.Dim+"nothing deleted"+c.Reset)
		return 0
	}

	if rErrs := providers.Reap(ctx, reapers, orphans); len(rErrs) > 0 {
		for _, e := range rErrs {
			c.Message(out, report.Blocked, e.Error())
		}
		return 1
	}
	c.Message(out, report.Ready, "reaped "+resources(len(orphans), "resource"))
	return 0
}

// resources counts n of noun, pluralized.
func resources(n int, noun string) string {
	return fmt.Sprintf("%d %s%s", n, noun, plural(n, "", "s"))
}

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"

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

	return runGC(context.Background(), reapers, gcOptions{DryRun: *dryRun, Yes: *yes}, os.Stdin, os.Stdout)
}

// gcCandidates returns the providers `corral gc` should query for orphans.
func gcCandidates(cfg *config.Config, home string, host map[string]string) []providers.Provider {
	var out []providers.Provider
	// gc inspects orphans from past sessions, not the current project.
	for _, a := range activeProviders(cfg, home, host, "", nil) {
		out = append(out, a.Provider)
	}
	return out
}

type gcOptions struct {
	DryRun bool
	Yes    bool
}

// runGC is the testable core: collect orphans, preview, and reap the approved set.
func runGC(ctx context.Context, reapers []providers.Reaper, opts gcOptions, in io.Reader, out io.Writer) int {
	orphans, errs := providers.CollectOrphans(ctx, reapers)
	for _, e := range errs {
		fmt.Fprintf(out, "corral gc: warning: %v\n", e)
	}
	if len(orphans) == 0 {
		fmt.Fprintln(out, "corral gc: no orphaned resources found.")
		if len(errs) > 0 {
			return 1 // a reaper failed to report; surface as non-zero
		}
		return 0
	}

	fmt.Fprintf(out, "Found %d orphaned resource(s):\n", len(orphans))
	for _, o := range orphans {
		fmt.Fprintf(out, "  - [%s] %s\n", o.Provider, o.Describe)
	}

	if opts.DryRun {
		fmt.Fprintln(out, "(dry-run) nothing deleted.")
		return 0
	}
	// Default-no: anything but an explicit yes aborts.
	if !opts.Yes && !promptYesNo(in, out, fmt.Sprintf("Reap these %d resource(s)? [y/N] ", len(orphans))) {
		fmt.Fprintln(out, "aborted; nothing deleted.")
		return 0
	}

	if rErrs := providers.Reap(ctx, reapers, orphans); len(rErrs) > 0 {
		for _, e := range rErrs {
			fmt.Fprintf(out, "corral gc: %v\n", e)
		}
		return 1
	}
	fmt.Fprintf(out, "Reaped %d resource(s).\n", len(orphans))
	return 0
}

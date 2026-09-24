package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/selfupdate"
)

// cmdUpdate checks for, and (unless --check) installs, a newer corral release in place.
func cmdUpdate(args []string, version string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	var (
		check   = fs.Bool("check", false, "only report whether a newer version exists; do not download or install")
		yes     = fs.Bool("yes", false, "install without the interactive confirmation prompt")
		timeout = fs.Duration("timeout", 90*time.Second, "overall network timeout for the check and download")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: corral update [--check] [--yes] [--timeout d]")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	out := os.Stdout
	c := report.StyleFor(out)
	writeTitle(out, c, "corral update", "")
	u, err := updaterFor(version)
	if err != nil {
		return fatalf(os.Stderr, "%v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	rel, err := u.LatestRelease(ctx)
	if errors.Is(err, selfupdate.ErrNoRelease) {
		return fatalf(os.Stderr, "no published release found for %s/%s", u.Source.Owner, u.Source.Repo)
	}
	if err != nil {
		return fatalf(os.Stderr, "check for updates: %v", err)
	}
	latest := rel.Version()
	// Refresh the cached check so `corral doctor` reflects this live probe.
	if home, herr := os.UserHomeDir(); herr == nil {
		selfupdate.RecordCheck(selfupdate.StatePath(home), latest, time.Now())
	}

	cmp, comparable := selfupdate.Compare(latest, version)
	switch {
	case comparable && cmp == 0:
		c.Message(out, report.Ready, fmt.Sprintf("up to date (%s)", version))
		return 0
	case comparable && cmp < 0:
		c.Message(out, report.Ready, fmt.Sprintf("%s is newer than the latest release %s", version, latest))
		return 0
	}

	// An update is installable: either latest > current, or current is not a comparable
	// release version (a "dev" build). Report the situation, then act unless --check.
	if comparable {
		c.Message(out, report.Attention, fmt.Sprintf("%s → %s available", version, latest))
	} else {
		c.Message(out, report.Attention, fmt.Sprintf("%q is not a release build; the latest release is %s", version, latest))
	}
	if *check {
		c.Fix(out, "corral update")
		return 0
	}

	target, err := updateTarget()
	if err != nil {
		return fatalf(os.Stderr, "locate the running binary: %v", err)
	}

	c.Row(out, report.Row{Label: "binary", Value: target})
	if !confirmUpdate(*yes, os.Stdin, out) {
		return fatalf(os.Stderr, "update aborted (pass --yes to skip the prompt, or to install non-interactively)")
	}

	progress := &lineWriter{w: os.Stderr, c: report.StyleFor(os.Stderr), g: report.None}
	newVersion, err := u.Apply(ctx, rel, target, progress)
	progress.Flush()
	if err != nil {
		return fatalf(os.Stderr, "update: %v", err)
	}
	c.Message(out, report.Ready, "updated to "+newVersion)
	c.Cont(out, c.Dim+"re-run corral sync if a release note says the hook"+c.Reset)
	c.Cont(out, c.Dim+"registration changed"+c.Reset)
	c.Fix(out, "corral sync")
	return 0
}

// updateTarget resolves the binary path `corral update` will replace, following symlinks.
// Package var for tests.
var updateTarget = func() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(self); err == nil {
		self = resolved
	}
	return self, nil
}

// updaterFor builds the Updater with the fixed release source. Package var for tests.
var updaterFor = func(version string) (*selfupdate.Updater, error) {
	src, err := selfupdate.ResolveSource()
	if err != nil {
		return nil, err
	}
	return selfupdate.New(src, version), nil
}

// confirmUpdate gates the in-place binary replacement. --yes skips it. Package var for tests.
var confirmUpdate = func(yes bool, in *os.File, out io.Writer) bool {
	if yes {
		return true
	}
	if !report.IsTerminal(in) {
		return false // non-interactive and no --yes: do not replace the binary
	}
	return promptYesNo(in, out, "Proceed with the update? [y/N] ")
}

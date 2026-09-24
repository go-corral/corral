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
		fmt.Fprintf(out, "corral is up to date (%s)\n", version)
		return 0
	case comparable && cmp < 0:
		// Running binary is ahead of the latest published release.
		fmt.Fprintf(out, "corral %s is newer than the latest release (%s); nothing to update\n", version, latest)
		return 0
	}

	// An update is installable: either latest > current, or current is not a comparable
	// release version (a "dev" build). Report the situation, then act unless --check.
	if comparable {
		fmt.Fprintf(out, "a newer corral is available: %s → %s\n", version, latest)
	} else {
		fmt.Fprintf(out, "corral %q is not a release build; the latest release is %s\n", version, latest)
	}
	if *check {
		fmt.Fprintln(out, "run 'corral update' to install it")
		return 0
	}

	target, err := updateTarget()
	if err != nil {
		return fatalf(os.Stderr, "locate the running binary: %v", err)
	}

	fmt.Fprintf(out, "this will replace %s\n", target)
	if !confirmUpdate(*yes, os.Stdin, out) {
		return fatalf(os.Stderr, "update aborted (pass --yes to skip the prompt, or to install non-interactively)")
	}

	newVersion, err := u.Apply(ctx, rel, target, os.Stderr)
	if err != nil {
		return fatalf(os.Stderr, "update: %v", err)
	}
	fmt.Fprintf(out, "corral updated to %s\n", newVersion)
	fmt.Fprintln(out, "re-run 'corral sync' if a release note says the hook registration changed")
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

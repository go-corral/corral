// Package cli implements the corral command dispatcher and its subcommands.
//
// corral is two programs in one binary: the launcher (run, sync, doctor) and the
// hook enforcer (hook …). The dispatcher keeps the hook path dependency-light.
package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
)

const usage = `corral — sandbox a coding agent (claude, pi) and enforce policy on its tool calls.

Usage:
  corral <command> [flags]

Commands:
  run        Launch the configured agent inside the sandbox
  hook       Hook enforcer (invoked by Claude Code; reads JSON on stdin)
  sync       Register corral's enforcement hooks (settings.json / extensions); --remove de-registers
  gc         Reap orphaned provider resources from crashed sessions (with preview)
  validate   Check config validity + show the effective policy (what the sandbox enforces)
  doctor     Check host & integration readiness (can corral run here, and is it wired up?)
  update     Check for and install a newer corral release in place
  uninstall  Show corral's on-system footprint; --apply removes it (binary and config stay)
  version    Print the version

Run "corral <command> -h" for command-specific flags.
`

// Main is the entry point. It returns the process exit code.
func Main(args []string, version string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stdout, usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return cmdRun(rest, version)
	case "hook":
		return cmdHook(rest)
	case "sync":
		return cmdSync(rest)
	case "gc":
		return cmdGC(rest)
	case "validate":
		return cmdValidate(rest, version)
	case "doctor":
		return cmdDoctor(rest, version)
	case "update":
		return cmdUpdate(rest, version)
	case "uninstall":
		return cmdUninstall(rest)
	case "version", "--version", "-v":
		fmt.Fprintln(os.Stdout, "corral", version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(os.Stdout, usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "corral: unknown command %q\n\n%s", cmd, usage)
		return 2
	}
}

// fatalf prints to stderr and returns exit code 1.
func fatalf(w io.Writer, format string, a ...any) int {
	fmt.Fprintf(w, "corral: "+format+"\n", a...)
	return 1
}

// parseFlags parses a ContinueOnError flag set. code is 0 on success or help,
// 2 on error. The hook path uses a different contract and does not call this.
func parseFlags(fs *flag.FlagSet, args []string) (code int, ok bool) {
	switch err := fs.Parse(args); err {
	case nil:
		return 0, true
	case flag.ErrHelp:
		return 0, false
	default:
		return 2, false
	}
}

// addProfileFlags registers the repeatable --profile/-p flag.
func addProfileFlags(fs *flag.FlagSet) *stringSlice {
	var v stringSlice
	fs.Var(&v, "profile", "config profile to overlay (repeatable; later profiles win)")
	fs.Var(&v, "p", "shorthand for --profile")
	return &v
}

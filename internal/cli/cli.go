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

	"github.com/go-corral/corral/internal/cli/report"
)

// commands is the help text's command list. note, when set, is printed dimmed below.
var commands = []struct{ name, desc, note string }{
	{"run", "Launch the configured agent inside the sandbox", ""},
	{"hook", "Hook enforcer (invoked by Claude Code; reads JSON on stdin)", ""},
	{"sync", "Register corral's hooks with an agent; --remove undoes it", ""},
	{"gc", "Preview and reap provider resources of crashed sessions", ""},
	{"validate", "Check the config and show the policy the sandbox enforces", ""},
	{"doctor", "Check that this host can run corral and is wired up", ""},
	{"update", "Check for and install a newer corral release in place", ""},
	{"uninstall", "Show corral's on-system footprint; --apply removes it", "binary and config stay"},
	{"version", "Print the version", ""},
}

// writeUsage prints the help text.
func writeUsage(w io.Writer, c report.Style) {
	writeTitle(w, c, "corral", "sandbox claude or pi and enforce policy on their tool calls")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: corral <command> [flags]")
	fmt.Fprintln(w)
	c.Rule(w, "commands")
	for _, cmd := range commands {
		c.Row(w, report.Row{Label: cmd.name, Value: cmd.desc, Reason: cmd.note})
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, c.Dim+`Run "corral <command> -h" for command-specific flags.`+c.Reset)
}

// Main is the entry point. It returns the process exit code.
func Main(args []string, version string) int {
	if len(args) == 0 {
		writeUsage(os.Stdout, report.StyleFor(os.Stdout))
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
		writeUsage(os.Stdout, report.StyleFor(os.Stdout))
		return 0
	default:
		fatalf(os.Stderr, "unknown command %q", cmd)
		fmt.Fprintln(os.Stderr)
		writeUsage(os.Stderr, report.StyleFor(os.Stderr))
		return 2
	}
}

// fatalf prints an error line to w and returns exit code 1.
func fatalf(w io.Writer, format string, a ...any) int {
	report.StyleOf(w).Message(w, report.Blocked, fmt.Sprintf(format, a...))
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

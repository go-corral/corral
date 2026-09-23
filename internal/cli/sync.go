package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/sandbox"
)

// cmdSync installs (or previews) the selected agent's policy enforcement. With --remove
// it de-registers instead.
func cmdSync(args []string) int {
	agentName, args := splitAgentArg(args)
	fs := flag.NewFlagSet("sync", flag.ContinueOnError)
	var (
		settings = fs.String("settings", "", "settings.json to update (claude; default: $CLAUDE_CONFIG_DIR or ~/.claude/settings.json)")
		binary   = fs.String("binary", "", "corral binary path to register (claude; default: this executable)")
		dryRun   = fs.Bool("dry-run", false, "print what would change without writing")
		remove   = fs.Bool("remove", false, "de-register corral's enforcement (claude: strip corral's hooks from settings.json; pi: delete the presence backstop)")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: corral sync [agent] [flags]")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	// Repo-config trust gate: a real sync is side-effectful, so a committed .corral.yml must be
	// approve-once here too. --dry-run is not gated. Session-hook executables are not gated here.
	if !*dryRun {
		_, sources, cerr := loadConfig(nil)
		if cerr != nil {
			return fatalf(os.Stderr, "load config: %v", cerr)
		}
		if !checkRepoConfigTrust(sources, hookExecs{}, false, os.Stdin, os.Stderr, report.StyleFor(os.Stderr)) {
			return 1
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fatalf(os.Stderr, "cannot resolve home: %v", err)
	}
	a := doctorAgent(agentName)
	c := report.StyleFor(os.Stdout)
	writeTitle(os.Stdout, c, "corral sync", a.Name())

	// The corral binary an agent registers as its hook command. A user-given --binary is
	// absolutized: the registered command must name the same binary from any cwd.
	binaryPath := *binary
	if binaryPath == "" {
		self, serr := os.Executable()
		if serr != nil {
			return fatalf(os.Stderr, "cannot resolve own path: %v", serr)
		}
		binaryPath = self
	} else if abs, aerr := filepath.Abs(binaryPath); aerr == nil {
		binaryPath = abs
	}

	// Command-hook agents register `<binary> hook pre-tool-use` inside the sandbox; if
	// that binary lives outside every baseline-mounted directory enforcement silently never
	// fires — warn. Bridge agents and --remove skip the check.
	if len(a.Launch().ExtensionAsset) == 0 && !*remove {
		warnBinaryUnreachable(os.Stderr, report.StyleFor(os.Stderr), binaryPath, home, a.ConfigDir(home, envMap()))
	}

	res, err := a.Sync(agents.SyncInput{
		Home:         home,
		Host:         envMap(),
		DryRun:       *dryRun,
		Remove:       *remove,
		BinaryPath:   binaryPath,
		SettingsPath: *settings,
	})
	if err != nil {
		return fatalf(os.Stderr, "sync %s: %v", a.Name(), err)
	}
	writeSyncReport(os.Stdout, c, res, *dryRun)
	return 0
}

// writeSyncReport prints the sync messages, then the settings diff.
func writeSyncReport(w io.Writer, c report.Style, res agents.SyncReport, dryRun bool) {
	g := report.Ready
	if dryRun {
		g = report.None
	}
	for _, m := range res.Messages {
		c.Message(w, g, m)
	}
	if res.Diff != nil {
		fmt.Fprint(w, unifiedDiff(res.Diff.Before, res.Diff.After, res.Diff.FromLabel, res.Diff.ToLabel, c))
	}
}

// warnBinaryUnreachable prints a heads-up when the hook binary lives outside every directory
// the sandbox baseline mounts. configDir is the agent-resolved config dir.
func warnBinaryUnreachable(w io.Writer, c report.Style, binary, home, configDir string) {
	resolved := binary
	if abs, err := filepath.Abs(resolved); err == nil {
		resolved = abs
	}
	if real, err := filepath.EvalSymlinks(resolved); err == nil {
		resolved = real
	}

	tokens := map[string]string{"HOME": home, "AGENT_CONFIG_DIR": configDir}

	if sandbox.PathReachableInCorral(resolved, tokens, runtime.GOOS) {
		return
	}
	c.Row(w, report.Row{Glyph: report.Attention, Label: "hook binary", Value: abbrevHome(resolved, home),
		Reason: "outside every directory the sandbox mounts: the PreToolUse"})
	for _, ln := range []string{
		"hook will not run inside the sandbox. Install corral under a",
		"baseline-mounted directory such as /usr/local/bin or",
		"~/.local/bin and re-run `corral sync --binary <that path>`.",
		"A binary inside the project works when corral starts there.",
	} {
		c.Cont(w, c.Dim+ln+c.Reset)
	}
}

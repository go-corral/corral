package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/go-corral/corral/internal/agents"
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
		if !checkRepoConfigTrust(sources, hookExecs{}, false, os.Stdin, os.Stderr, colors(colorTo(os.Stderr))) {
			return 1
		}
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return fatalf(os.Stderr, "cannot resolve home: %v", err)
	}
	a := doctorAgent(agentName)

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
		warnBinaryUnreachable(os.Stderr, binaryPath, home, a.ConfigDir(home, envMap()))
	}

	report, err := a.Sync(agents.SyncInput{
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
	for _, m := range report.Messages {
		fmt.Printf("corral: %s\n", m)
	}
	if report.Diff != nil {
		fmt.Print(unifiedDiff(report.Diff.Before, report.Diff.After, report.Diff.FromLabel, report.Diff.ToLabel, colors(colorTo(os.Stdout))))
	}
	return 0
}

// warnBinaryUnreachable prints a heads-up when the hook binary lives outside every directory
// the sandbox baseline mounts. configDir is the agent-resolved config dir.
func warnBinaryUnreachable(w *os.File, binary, home, configDir string) {
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
	fmt.Fprintf(w, "corral: warning: hook binary %s is outside every directory the sandbox mounts.\n", resolved)
	fmt.Fprintln(w, "  A globally-registered hook there cannot be exec'd inside the sandbox, so the")
	fmt.Fprintln(w, "  PreToolUse policy hook will silently not run. Install corral under a baseline-")
	fmt.Fprintln(w, "  mounted directory (e.g. /usr/local/bin or ~/.local/bin) and re-run")
	fmt.Fprintln(w, "  `corral sync --binary <that path>`. (A binary inside your project still works")
	fmt.Fprintln(w, "  when you launch corral from that project — the working directory is mounted.)")
}

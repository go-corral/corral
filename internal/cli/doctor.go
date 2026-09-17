package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/selfupdate"
)

// cmdDoctor reports environment readiness: the sandbox backend, agent availability,
// config layers, provider host availability, and update state.
func cmdDoctor(args []string, version string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	backendFlag := fs.String("backend", "", "sandbox backend to check: bwrap or seatbelt (default: this OS's backend)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: corral doctor [flags]")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	out := os.Stdout
	fmt.Fprintf(out, "corral %s  (%s/%s, %s)\n", version, runtime.GOOS, runtime.GOARCH, runtime.Version())

	// Sandbox backend: ask the resolved backend for its own diagnostics.
	fmt.Fprintln(out, "\nSandbox backend:")
	if kind, err := sandbox.ResolveKind(*backendFlag); err != nil {
		fmt.Fprintf(out, "  %v\n", err)
	} else {
		backend := newBackend(kind, "", config.Sandbox{})
		fmt.Fprintf(out, "  backend: %s\n", backend.Name())
		backend.Doctor(out)
	}

	// Agents: every supported agent's binary availability and enforcement-readiness report.
	fmt.Fprintln(out, "\nAgents:")
	reportAgents(out)

	// The kill switch lives in the launching shell, not a corral file, so surface it here.
	reportHookKillSwitch(out)

	fmt.Fprintln(out, "\nConfig:")
	reportConfig(out)

	fmt.Fprintln(out, "\nProviders (host availability — enable under `providers.<name>`):")
	reportProviders(out)

	fmt.Fprintln(out, "\nUpdate:")
	reportUpdate(out, version)

	return 0
}

// reportHookKillSwitch reports CORRAL_DISABLE_HOOKS as seen in this shell.
func reportHookKillSwitch(out *os.File) {
	raw, set := os.LookupEnv(sandbox.DisableHooksEnvVar)
	switch {
	case !set || strings.TrimSpace(raw) == "":
		return
	case sandbox.EnvEnabled(sandbox.DisableHooksEnvVar):
		fmt.Fprintf(out, "\n  ⚠ %s=%s in this shell: corral's hooks are disabled for any agent started from here\n",
			sandbox.DisableHooksEnvVar, raw)
		fmt.Fprintf(out, "    (a `corral run` session is unaffected — the sandbox marker overrides it)\n")
	default:
		fmt.Fprintf(out, "\n  note: %s=%s is set but not recognized, so hooks stay ACTIVE (only 1/true disable them)\n",
			sandbox.DisableHooksEnvVar, raw)
	}
}

// reportUpdate shows the update source and the cached result of the last version check —
// no network call.
func reportUpdate(out *os.File, version string) {
	cfg, _, err := loadConfig(nil)
	if err != nil {
		fmt.Fprintf(out, "  status: unknown (config error: %v)\n", err)
		return
	}
	if src, err := selfupdate.ResolveSource(); err == nil {
		fmt.Fprintf(out, "  source: %s (%s/%s)\n", src.APIBase, src.Owner, src.Repo)
	}
	if !cfg.Update.CheckOnStart {
		fmt.Fprintln(out, "  launch check: disabled (update.checkOnStart: false)")
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(out, "  status: unknown (cannot resolve home)")
		return
	}
	latest, when, ok := selfupdate.CachedCheck(selfupdate.StatePath(home))
	switch {
	case !ok:
		fmt.Fprintln(out, "  status: not checked yet — run `corral update --check`")
	case selfupdate.IsNewer(latest, version):
		fmt.Fprintf(out, "  status: update available — %s → %s (run `corral update`)\n", version, latest)
	case latest != "":
		fmt.Fprintf(out, "  status: up to date as of last check (latest %s, checked %s)\n", latest, when.Format("2006-01-02 15:04"))
	default:
		fmt.Fprintf(out, "  status: last check (%s) could not reach the release server\n", when.Format("2006-01-02 15:04"))
	}
}

// reportAgents enumerates every supported agent: binary availability and enforcement-readiness.
func reportAgents(out *os.File) {
	home, homeErr := os.UserHomeDir()
	host := envMap()
	// This executable is the binary an agent's registration must name.
	self, _ := os.Executable()
	for _, name := range agents.Known() {
		a, _ := agents.Lookup(name)
		path, found := agentBinary(a)
		if !found {
			fmt.Fprintf(out, "  %-9s not installed (no %s on PATH)\n", name+":", strings.Join(a.Binaries(), "/"))
			continue
		}
		fmt.Fprintf(out, "  %-9s available — %s%s\n", name+":", path, versionSuffix(path))
		if homeErr != nil {
			fmt.Fprintf(out, "    (cannot resolve home: %v — skipping enforcement detail)\n", homeErr)
			continue
		}
		for _, line := range a.Doctor(agents.StatusInput{Home: home, Host: host, Self: self}).Lines {
			fmt.Fprintf(out, "    %s: %s\n", line.Label, line.Status)
		}
	}
}

// agentBinary resolves an agent's program on PATH, trying Binaries names in order.
func agentBinary(a agents.Agent) (string, bool) {
	for _, name := range a.Binaries() {
		if p, err := exec.LookPath(name); err == nil {
			return p, true
		}
	}
	return "", false
}

// versionSuffix returns " (<version>)" from `--version`, or "" on failure.
func versionSuffix(path string) string {
	b, err := exec.Command(path, "--version").Output()
	if err != nil {
		return ""
	}
	if v := strings.TrimSpace(firstLine(string(b))); v != "" {
		return " (" + v + ")"
	}
	return ""
}

// doctorAgent resolves the agent a `[agent]` positional names: the positional if given,
// else the configured agent, else the default.
func doctorAgent(name string) agents.Agent {
	if name == "" {
		if cfg, _, err := loadConfig(nil); err == nil {
			name = cfg.EffectiveAgent()
		}
	}
	if a, ok := agents.Lookup(name); ok {
		return a
	}
	a, _ := agents.Lookup(agents.Default)
	return a
}

// reportConfig is a readiness signal: is the config valid and which layers are detected?
func reportConfig(out *os.File) {
	cfg, sources, err := loadConfig(nil)
	if err != nil {
		fmt.Fprintf(out, "  status: INVALID — %v\n", err)
		fmt.Fprintln(out, "  (run `corral validate` to see the error in context)")
		return
	}
	fmt.Fprintln(out, "  status: valid")
	// Annotate repo-discovered layers with their trust-approval state.
	trustAnn := trustAnnotations(trustEntries(sources))
	for _, s := range sources {
		if s.Path != "" {
			line := fmt.Sprintf("  detected: %s (%s)", s.Path, s.Kind)
			if a, ok := trustAnn[s.Path]; ok {
				line += "  [" + a.label + "]"
			}
			fmt.Fprintln(out, line)
		} else {
			fmt.Fprintf(out, "  detected: %s\n", s.Kind)
		}
	}
	// Session-hook executables ride the same gate.
	if wd, werr := os.Getwd(); werr == nil {
		if execs := collectHookExecs(cfg, wd); len(execs.attr) > 0 {
			hookAnn := trustAnnotations(execs.entries)
			for _, p := range execs.sortedAttrPaths() {
				line := fmt.Sprintf("  hook exec: %s (%s)", p, execs.attr[p])
				a, annotated := hookAnn[p]
				switch {
				case execs.unreadable[p] != "":
					line += "  [unreadable — the launch will fail or skip this hook]"
				case annotated:
					line += "  [" + a.label + "]"
				}
				fmt.Fprintln(out, line)
			}
		}
	}
	fmt.Fprintln(out, "  (run `corral validate` for the effective policy: blocked paths, extra directories, env, providers)")
}

// reportProviders probes each known provider's host prerequisite, independent of config.
func reportProviders(out *os.File) {
	// doctor degrades rather than fails, but says so explicitly.
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(out, "  (cannot resolve home: %v)\n", err)
		return
	}
	host := envMap()
	for _, p := range knownProviders(home, host) {
		status := "unavailable"
		if p.Available(context.Background()) {
			status = "available"
		}
		fmt.Fprintf(out, "  %-11s %s\n", p.Name()+":", status)
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

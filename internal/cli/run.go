package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/selfupdate"
	"mvdan.cc/sh/v3/syntax"
)

// cleanupTimeout bounds provider teardown so a stuck network call cannot hang corral.
const cleanupTimeout = 30 * time.Second

// resolveAgentBinary resolves the agent's program to launch: the first Binaries name on
// PATH, else the bare first entry.
func resolveAgentBinary(a agents.Agent) string {
	for _, name := range a.Binaries() {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return a.Binaries()[0]
}

// materializeExtension writes an agent's embedded policy-extension asset to the host cache
// and returns its path. Idempotent: rewrites only when absent or drifted.
func materializeExtension(home, name string, data []byte) (string, error) {
	if home == "" {
		return "", errors.New("no home to place the policy extension under")
	}
	dir := filepath.Join(home, ".cache", "corral")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	if cur, err := os.ReadFile(path); err != nil || !bytes.Equal(cur, data) {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return "", err
		}
	}
	return path, nil
}

// splitAgentArg peels an optional leading agent positional off a subcommand's args. The
// agent must be first, since Go's flag package stops at the first positional.
func splitAgentArg(args []string) (agent string, rest []string) {
	if len(args) > 0 {
		if _, ok := agents.Lookup(args[0]); ok {
			return args[0], args[1:]
		}
	}
	return "", args
}

// cmdRun launches a coding agent inside the sandbox built from the effective config.
func cmdRun(args []string, version string) int {
	// Peeled before flag parsing since Go's flag package stops at the first positional.
	agentName, args := splitAgentArg(args)

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var (
		dryRun      = fs.Bool("dry-run", false, "print the sandbox command and exit without launching")
		home        = fs.String("home", "", "home directory inside the sandbox (default: $HOME)")
		project     = fs.String("project", "", "project directory mounted read-write (default: current directory)")
		bwrapPath   = fs.String("bwrap", "bwrap", "path to the bwrap binary")
		commandPath = fs.String("command", "", "program to run inside the sandbox (default: claude on PATH)")
		backendFlag = fs.String("backend", "", "sandbox backend: bwrap or seatbelt (default: this OS's backend)")
		profiles    = addProfileFlags(fs)
		yes         = fs.Bool("yes", false, "skip the interactive confirmation shown when a launch raises warnings")
	)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: corral run [agent] [flags] [-- agent-args...]")
		fs.PrintDefaults()
	}
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	if *home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return fatalf(os.Stderr, "cannot resolve home: %v", err)
		}
		*home = h
	}
	if *project == "" {
		wd, err := os.Getwd()
		if err != nil {
			return fatalf(os.Stderr, "cannot resolve working directory: %v", err)
		}
		*project = wd
	}

	// Decide the backend once: the -backend override if given, else this OS's default.
	backendKind, err := sandbox.ResolveKind(*backendFlag)
	if err != nil {
		return fatalf(os.Stderr, "%v", err)
	}

	cfg, sources, err := loadConfig([]string(*profiles))
	if err != nil {
		return fatalf(os.Stderr, "load config: %v", err)
	}
	// Decide the writable workdir before the trust gate: the gate hashes session-hook
	// executables whose relative paths anchor to the workdir.
	projectSrc, substituted, err := resolveWorkdir(*home, *project, *dryRun)
	if err != nil {
		return fatalf(os.Stderr, "%v", err)
	}
	if substituted {
		fmt.Fprintf(os.Stderr, "corral: launched from home; using a fresh scratch workdir at %s "+
			"so the whole home tree is not exposed (write your work elsewhere, or cd into a project first)\n", projectSrc)
	}

	// Trust gate: a committed .corral.yml/.corral.local.yml is approve-once, as is every
	// executable a session hook would run. Runs before any consumption or mint. --yes is
	// refused here; --dry-run is exempt.
	if !*dryRun && !checkRepoConfigTrust(sources, collectHookExecs(cfg, projectSrc), *yes, os.Stdin, os.Stderr, report.StyleFor(os.Stderr)) {
		return 1
	}
	if err := grantAuditDir(cfg, *home, *dryRun); err != nil {
		return fatalf(os.Stderr, "config invalid: %v", err)
	}
	// Always-blocked guard, symlink-resolving half. Runs after the trust gate, before consumption.
	if err := checkResolvedPathGrants(cfg, *home); err != nil {
		return fatalf(os.Stderr, "config invalid: %v", err)
	}
	// A `corral run <agent>` positional overrides the configured agent.
	if agentName != "" {
		cfg.Agent = agentName
	}

	// Resolve the program to run: the configured agent's binary on PATH, or -command to override.
	commandBin := *commandPath
	if commandBin == "" {
		agent, ok := agents.Lookup(cfg.EffectiveAgent())
		if !ok {
			return fatalf(os.Stderr, "unknown agent %q", cfg.EffectiveAgent())
		}
		commandBin = resolveAgentBinary(agent)
	}

	host := envMap()
	spec := sandbox.DefaultSpec(specParams(cfg, *home, projectSrc, host, commandBin))
	// Pin the exact global config so the in-sandbox hook reads the same file.
	pinGlobalConfig(&spec, sources)
	// Pin the agent actually launched so the in-sandbox hook self-protects the right config dir.
	if spec.SetEnv == nil {
		spec.SetEnv = map[string]string{}
	}
	spec.SetEnv[sandbox.AgentEnvVar] = cfg.EffectiveAgent()
	// Pin the audit-log path so the in-sandbox hook does not resolve it against the private home.
	spec.SetEnv[sandbox.AuditPathEnvVar] = configuredAuditPath(cfg, cfg.AgentConfigDir(*home, host))

	// Activate the agent's in-process policy extension, if it ships one (pi's bridge).
	launch := cfg.AgentLaunch()
	var extensionArgs []string
	if len(launch.ExtensionAsset) > 0 {
		assetPath, aerr := materializeExtension(*home, launch.ExtensionName, launch.ExtensionAsset)
		if aerr != nil {
			return fatalf(os.Stderr, "activate %s policy extension: %v", cfg.EffectiveAgent(), aerr)
		}
		spec.Mounts = append(spec.Mounts, sandbox.Mount{Src: assetPath, Dst: assetPath, ReadOnly: true})
		if self, serr := os.Executable(); serr == nil {
			spec.SetEnv[sandbox.BinEnvVar] = self
		}
		extensionArgs = []string{launch.ExtensionFlag, assetPath}
	}
	// Phase A — built-in providers (block, aiignore, paths, env). Pure Mint, resolved before the
	// gate so advisory warnings feed it and deny channels are in the spec before phase B.
	ctx := context.Background()
	sess := newSession(*home, projectSrc)
	resBuiltin, err := providers.Resolve(ctx, sess, builtinProviders(cfg, *home))
	if err != nil {
		return fatalf(os.Stderr, "providers: %v", err)
	}
	if err := resBuiltin.Apply(&spec); err != nil {
		return fatalf(os.Stderr, "providers: %v", err)
	}

	// Construct the backend and compute launch advisories before any mint. Written to stderr
	// so --dry-run's argv stays pipeable.
	backend := newBackend(backendKind, *bwrapPath, cfg.Sandbox)
	// Fold the resolved backend's model-facing notes into the sandbox env.
	setBackendNotes(&spec, backend)
	c := report.StyleFor(os.Stderr)
	warnings := sessionWarnings(cfg, backend.ReadOnlyTargets(spec))
	warnings = append(warnings, resBuiltin.Warnings...)
	// Startup readiness advisory: each agent reports its own set.
	if hostHome, herr := os.UserHomeDir(); herr == nil {
		if a, ok := agents.Lookup(cfg.EffectiveAgent()); ok {
			self, _ := os.Executable()
			warnings = append(warnings, a.LaunchWarnings(agents.StatusInput{Home: hostHome, Host: host, Self: self, WorkDir: projectSrc})...)
		}
	}
	// The kill switch is set in the shell asking for a sandboxed session, where corral ignores it.
	if sandbox.EnvEnabled(sandbox.DisableHooksEnvVar) {
		warnings = append(warnings, fmt.Sprintf("%s is set in this shell, but it has NO effect inside the sandbox — this session is fully "+
			"enforced (the switch only disables corral for an agent started WITHOUT `corral run`)", sandbox.DisableHooksEnvVar))
	}
	// A preStart session hook's captured stderr renders in the banner's format.
	active := activeProviders(cfg, *home, host, projectSrc, bannerSessionHookPresenter(os.Stderr, c))
	command := append([]string{commandBin}, extensionArgs...)
	command = append(command, fs.Args()...)

	// Side-effect-free preview of phase B: each provider's static, secret-free contribution.
	// Credential-minters and session hooks are named (previewOnly) rather than expanded.
	preview, previewOnly, perr := providers.ResolvePreview(ctx, sess, active)
	if perr != nil && *dryRun {
		return fatalf(os.Stderr, "providers: %v", perr)
	}
	// Private-home shadows go through the gate: a detect-only pass over the full static mount set.
	homeArch := baselineArch(backendKind)
	keep := cfg.Providers.Home.KeepRel()
	guardDir := hookGuardDir(cfg, *home, host)
	privHome, homeOn := homeDir(cfg, *home, host)
	var shadows []string
	if homeOn {
		pre := spec // shallow copy: linkHome only reads
		pre.Mounts = append(slices.Clone(spec.Mounts), preview.Mounts()...)
		var serr error
		if shadows, serr = linkHome(&pre, *home, privHome, homeArch, keep, guardDir, false); serr != nil {
			return fatalf(os.Stderr, "home: %v", serr)
		}
		warnings = append(warnings, shadows...)
	}

	banner := bannerInfo{
		version:  version,
		home:     *home,
		workdir:  spec.WorkDir,
		auditLog: effectiveAuditPath(cfg, cfg.AgentConfigDir(*home, host)),
		profiles: []string(*profiles),
	}

	if *dryRun {
		if err := preview.Apply(&spec, resBuiltin); err != nil {
			return fatalf(os.Stderr, "providers: %v", err)
		}
		// The linking pass is skipped on a dry run: it only creates host symlinks and does not
		// mutate spec, so the printed profile is unaffected.
		warnings = append(warnings, preview.Warnings...)
		// Dry-run is network-free, so no version warning. A side-effect provider can't be previewed,
		// so it gets a launch-only row.
		notices := append(append([]providers.Notice{}, resBuiltin.Notices...), preview.Notices...)
		writeStartupBanner(os.Stderr, c, cfg, banner, warnings, notices, previewOnly)
		// Dry-run is an inspection tool and is not gated, but a real run would prompt.
		writeTrustDryRunNote(os.Stderr, c, sources, collectHookExecs(cfg, projectSrc))
		prep, err := backend.Prepare(&spec, os.Stderr)
		if err != nil {
			return fatalf(os.Stderr, "prepare sandbox: %v", err)
		}
		argv, err := backend.Argv(spec, command)
		if err != nil {
			prep.Cleanup()
			return fatalf(os.Stderr, "build sandbox command: %v", err)
		}
		fmt.Println(shellQuote(argv))
		// Name side-effect providers that would act at launch — to stderr so stdout stays pipeable.
		if len(previewOnly) > 0 {
			fmt.Fprintf(os.Stderr, "corral: %d provider(s) not expanded in the profile above — they act only at launch (credential minting, session hooks): %s\n",
				len(previewOnly), strings.Join(previewOnly, ", "))
		}
		prep.Cleanup()
		return 0
	}

	// --- real launch ---

	// Startup banner + confirmation gate, before minting. The gate fires only when warnings
	// exist and stdin is interactive: --yes skips it.
	banner.latest = checkUpdateOnStart(ctx, cfg, *home, version)
	// Print the banner around the gate and phase-B output, so the providers section renders as
	// one contiguous block.
	writeBannerHeader(os.Stderr, c, cfg, banner, warnings)
	if len(warnings) > 0 && !confirmProceed(*yes, os.Stdin, os.Stderr, c) {
		return fatalf(os.Stderr, "launch aborted — warnings not confirmed (pass --yes to skip this prompt)")
	}

	// Confirmed (or nothing to confirm): now Mint. A Mint error on a non-optional provider
	// fails the launch closed. resolveProviders is a test seam over providers.Resolve.
	//
	// The mint-to-launch window is signal-aware: NotifyContext converts SIGINT to ctx cancellation
	// so the interrupt tears down through the normal fail-closed teardown.
	mintCtx, stopMint := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stopMint()
	res, err := resolveProviders(mintCtx, sess, active)
	if err != nil {
		return fatalf(os.Stderr, "providers: %v", err)
	}
	// A single deferred teardown covers every path from here to the launch. prep is declared
	// up front so the nil-guard covers aborts before Prepare ran.
	var prep sandbox.LaunchPrep
	defer func() {
		abortAfterMint(res)
		if prep.Cleanup != nil {
			prep.Cleanup()
		}
	}()
	// A signal that landed as the mint finished must still abort.
	if mintCtx.Err() != nil {
		return fatalf(os.Stderr, "launch aborted — interrupted during provider mint")
	}
	// resBuiltin rides along as prior so a collision is attributed to that provider, not "baseline".
	if err := res.Apply(&spec, resBuiltin); err != nil {
		return fatalf(os.Stderr, "providers: %v", err)
	}
	// With the home provider active, populate the private home with symlinks. After Apply so
	// the full mount set is known.
	var lateShadows []string
	if homeOn {
		late, lerr := linkHome(&spec, *home, privHome, homeArch, keep, guardDir, true)
		if lerr != nil {
			return fatalf(os.Stderr, "home: %v", lerr)
		}
		lateShadows = slices.DeleteFunc(late, func(s string) bool { return slices.Contains(shadows, s) })
	}

	// The providers section prints after the gate and phase-B mint.
	notices := append(append([]providers.Notice{}, resBuiltin.Notices...), res.Notices...)
	writeBannerBody(os.Stderr, c, *home, notices, nil)
	writeWarnings(os.Stderr, c, res.Warnings)
	writeWarnings(os.Stderr, c, lateShadows)

	// Backend pre-launch ceremony. Prepare mutates spec in place and returns cleanup + a pre-exec
	// chdir.
	prep, err = backend.Prepare(&spec, os.Stderr)
	if err != nil {
		return fatalf(os.Stderr, "prepare sandbox: %v", err)
	}

	argv, err := backend.Argv(spec, command)
	if err != nil {
		return fatalf(os.Stderr, "build sandbox command: %v", err)
	}

	if !backend.Available() {
		return fatalf(os.Stderr, "%s", backend.UnavailableHint())
	}

	// Resolve the sandbox launcher (argv[0]: bwrap or sandbox-exec) to an absolute path for exec.
	launcherAbs, err := exec.LookPath(argv[0])
	if err != nil {
		return fatalf(os.Stderr, "resolve %s path: %v", backend.Name(), err)
	}

	// A backend with no in-sandbox working-directory control asks the launcher to chdir.
	if prep.Chdir != "" {
		if err := os.Chdir(prep.Chdir); err != nil {
			return fatalf(os.Stderr, "chdir to work dir %q: %v", prep.Chdir, err)
		}
	}

	// Blank line so corral's banner is separated from claude's own UI.
	fmt.Fprintln(os.Stderr)

	// Launch strategy: syscall.Exec (fast path) when no teardown is needed, otherwise supervise.
	// Empty env: bwrap is PID 1 and its environ is readable via /proc/1/environ.
	if mustSupervise(res) {
		// We outlive the child; the deferred teardown reclaims backend resources.
		return runSupervised(launcherAbs, argv, res)
	}
	if err := syscall.Exec(launcherAbs, argv, []string{}); err != nil {
		return fatalf(os.Stderr, "launch sandbox: %v", err)
	}
	// On success the process is replaced, so the deferred teardown never runs.
	return 0
}

// resolveWorkdir decides what host directory to mount as the writable project. Normally the
// launch directory itself. When it is the user's home, binding it would expose the whole home tree,
// so a fresh scratch dir is used instead. Not cleaned up (under $TMPDIR, reaped by the OS).
func resolveWorkdir(home, project string, dryRun bool) (src string, substituted bool, err error) {
	if !sameDir(home, project) {
		return project, false, nil
	}
	if dryRun {
		return filepath.Join(os.TempDir(), "corral-work-XXXXXX"), true, nil
	}
	scratch, err := os.MkdirTemp("", "corral-work-*")
	if err != nil {
		return "", false, fmt.Errorf("create scratch workdir: %w", err)
	}
	return scratch, true, nil
}

// sameDir reports whether a and b denote the same directory (symlink-resolved).
func sameDir(a, b string) bool {
	return pathutil.Resolve(a) == pathutil.Resolve(b)
}

// runSupervised launches the sandbox as a child, forwards signals, waits for exit, then runs
// session-end hooks and provider cleanup. Returns the child's exit code.
func runSupervised(launcherAbs string, argv []string, res *providers.Resolved) int {
	// Surface a teardown confirmation per provider as it is cleaned up.
	res.LogWriter = os.Stderr
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := res.Cleanup(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "corral: provider cleanup: %v\n", err)
		}
	}()

	cmd := exec.Command(launcherAbs, argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = []string{} // empty, not nil: nil would re-inherit os.Environ()
	if err := cmd.Start(); err != nil {
		// The child never started — fire the session-end hooks with a zero SessionExit.
		runPostSessionHooks(res, providers.SessionExit{})
		return fatalf(os.Stderr, "launch sandbox: %v", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for s := range sigCh {
			_ = cmd.Process.Signal(s)
		}
	}()

	err := cmd.Wait()

	// The agent ran: derive its exit status and hand it to the session-end hooks.
	code, signaled := waitStatus(err)
	// Signal handling stays installed across the session-end hooks, stopped only afterwards: a
	// postEnd hook is unbounded, and with the default disposition restored a Ctrl-C would kill corral
	// outright — skipping the deferred Cleanup.
	runPostSessionHooks(res, providers.SessionExit{Started: true, Code: code, Signaled: signaled})
	signal.Stop(sigCh)
	close(sigCh)
	return code
}

// runPostSessionHooks runs the resolved providers' session-end hooks warn-only.
func runPostSessionHooks(res *providers.Resolved, exit providers.SessionExit) {
	if err := res.RunPostSession(context.Background(), exit); err != nil {
		fmt.Fprintf(os.Stderr, "corral: post-session hooks: %v\n", err)
	}
}

// abortAfterMint tears a launch down after providers minted but before the agent ran:
// session-end hooks first, then LIFO Cleanup. Both run on fresh contexts with opposite bounds.
// One helper so every post-Resolve abort path tears down identically; nil-safe.
func abortAfterMint(res *providers.Resolved) {
	if res == nil {
		return
	}
	res.LogWriter = os.Stderr
	runPostSessionHooks(res, providers.SessionExit{})
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := res.Cleanup(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "corral: provider cleanup: %v\n", err)
	}
}

// waitStatus maps a Wait error to the child's exit code and whether a signal killed it.
func waitStatus(err error) (code int, signaled bool) {
	if err == nil {
		return 0, false
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), true
		}
		return ee.ExitCode(), false
	}
	return fatalf(os.Stderr, "sandbox wait: %v", err), false
}

// exitCode maps a Wait error to a process exit code.
func exitCode(err error) int {
	code, _ := waitStatus(err)
	return code
}

// mustSupervise reports whether the launcher must outlive the child.
func mustSupervise(res *providers.Resolved) bool {
	return res.HasCleanup() || res.HasPostSession()
}

// shellQuote renders argv as a copy-pasteable shell command, for display only. Delegates to
// mvdan.cc/sh for correct quoting of control characters.
func shellQuote(argv []string) string {
	var b strings.Builder
	for i, a := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		q, err := syntax.Quote(a, syntax.LangBash)
		if err != nil {
			// syntax.Quote only fails for input no shell syntax can represent (e.g. a NUL byte), which
			// can't occur in argv strings the OS handed us. Fall back to a minimal single-quote wrap so
			// display degrades rather than dropping the argument.
			q = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		b.WriteString(q)
	}
	return b.String()
}

// checkUpdateOnStart runs the throttled, best-effort launch-time update check. It returns
// the latest version when a newer release exists. Package var for tests.
var checkUpdateOnStart = func(ctx context.Context, cfg *config.Config, home, version string) string {
	if !cfg.Update.CheckOnStart {
		return ""
	}
	src, err := selfupdate.ResolveSource()
	if err != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return selfupdate.CheckOnStart(cctx, selfupdate.New(src, version), selfupdate.StatePath(home), selfupdate.DefaultInterval, time.Now())
}

// confirmProceed gates a launch with advisory warnings behind an explicit "yes". --yes skips
// it. Non-interactive stdin proceeds. Package var for tests.
var confirmProceed = func(yes bool, in *os.File, out io.Writer, c report.Style) bool {
	if yes || !report.IsTerminal(in) {
		return true
	}
	return promptYesNo(in, out, fmt.Sprintf("%sProceed past the warning(s) above? [y/N]%s ", c.Bold, c.Reset))
}

// promptYesNo writes the prompt, reads one line, and reports whether the reply was affirmative.
// An `in` already a *bufio.Reader is used as-is.
func promptYesNo(in io.Reader, out io.Writer, prompt string) bool {
	fmt.Fprint(out, prompt)
	br, ok := in.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(in)
	}
	line, _ := br.ReadString('\n')
	return confirmResponse(line)
}

// confirmResponse reports whether a prompt reply is affirmative. Default-no.
func confirmResponse(line string) bool {
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	default:
		return false
	}
}

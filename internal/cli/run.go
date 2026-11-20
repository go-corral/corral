package cli

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/go-corral/corral/internal/agents"
	"github.com/go-corral/corral/internal/audit"
	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/home"
	"github.com/go-corral/corral/internal/sandbox"
	"github.com/go-corral/corral/internal/selfupdate"
	"github.com/go-corral/corral/internal/sidecar"
	"github.com/go-corral/corral/internal/trust"
	"mvdan.cc/sh/v3/syntax"
)

// cleanupTimeout bounds provider teardown so a stuck network call cannot hang corral.
const cleanupTimeout = 30 * time.Second

// agentLaunch is a test seam over cfg.AgentLaunch.
var agentLaunch = func(cfg *config.Config) agents.Launch { return cfg.AgentLaunch() }

// materializeExtension writes an agent's embedded policy-extension asset to the host cache
// and returns its path. Idempotent: rewrites only when absent or drifted.
func materializeExtension(home, name string, data []byte) (string, error) {
	if home == "" {
		return "", errors.New("no home to place the policy extension under")
	}
	dir := filepath.Join(home, ".cache", "corral")
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
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

// runFlags is the parsed `corral run` command line, with the home and project defaults
// resolved.
type runFlags struct {
	agent    string
	dryRun   bool
	home     string
	project  string
	bwrap    string
	command  string
	backend  string
	profiles []string
	yes      bool
	args     []string
	version  string
}

// parseRunFlags parses the `corral run` command line. ok is false when the command must exit
// with code.
func parseRunFlags(args []string, version string) (f runFlags, code int, ok bool) {
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
		return runFlags{}, code, false
	}

	if *home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return runFlags{}, fatalf(os.Stderr, "cannot resolve home: %v", err), false
		}
		*home = h
	}
	if *project == "" {
		wd, err := os.Getwd()
		if err != nil {
			return runFlags{}, fatalf(os.Stderr, "cannot resolve working directory: %v", err), false
		}
		*project = wd
	}
	return runFlags{
		agent:    agentName,
		dryRun:   *dryRun,
		home:     *home,
		project:  *project,
		bwrap:    *bwrapPath,
		command:  *commandPath,
		backend:  *backendFlag,
		profiles: []string(*profiles),
		yes:      *yes,
		args:     fs.Args(),
		version:  version,
	}, 0, true
}

// launchPlan holds what the dry run and the real launch read after planLaunch.
type launchPlan struct {
	cfg            *config.Config
	sources        []config.Source
	flags          runFlags
	projectSrc     string
	privHome       string
	homeOn         bool
	homeArch       string
	keep           []string
	guardDir       string
	kubes          kubeconfigs
	spec           sandbox.SandboxSpec
	owners         providers.Owners
	sectionRows    []providers.Notice
	checks         []health.Check
	warnings       []string
	backend        sandbox.Backend
	auditPath      string
	agentConfigDir string
	command        []string
	sess           providers.Session
	active         []providers.Active
	preview        *providers.Resolved
	previewOnly    []string
	shadows        []string
	banner         bannerInfo
	c              report.Style
	warnLines      *lineWriter
	hookLog        *lineWriter
}

// planLaunch runs every step before the confirmation gate: config, trust gate, spec, backend,
// warnings, the provider preview and the private-home shadow check. On failure it returns a nil
// plan and the exit code.
func planLaunch(f runFlags) (*launchPlan, int) {
	c := report.StyleFor(os.Stderr)
	warnLines := &lineWriter{w: os.Stderr, c: c, g: report.Attention}

	// Decide the backend once: the -backend override if given, else this OS's default.
	backendKind, err := sandbox.ResolveKind(f.backend)
	if err != nil {
		return nil, fatalf(os.Stderr, "%v", err)
	}

	cfg, sources, err := loadConfig(f.profiles)
	if err != nil {
		return nil, fatalf(os.Stderr, "load config: %v", err)
	}
	var applied []string
	for _, s := range sources {
		if s.Kind == "profile" {
			if strings.Contains(s.Path, ",") {
				return nil, fatalf(os.Stderr, "profile %q: name contains a comma, which is not allowed", s.Path)
			}
			applied = append(applied, s.Path)
		}
	}
	// Decide the writable workdir before the trust gate: the gate hashes session-hook
	// executables whose relative paths anchor to the workdir.
	projectSrc, substituted, err := resolveWorkdir(f.home, f.project, f.dryRun)
	if err != nil {
		return nil, fatalf(os.Stderr, "%v", err)
	}
	if substituted {
		c.Message(os.Stderr, report.Attention, fmt.Sprintf("launched from home; using a fresh scratch workdir at %s "+
			"so the whole home tree is not exposed (write your work elsewhere, or cd into a project first)", projectSrc))
	}
	// The hook finds project config from the workdir, not from this cwd, so the pinned
	// profiles must load from there too.
	if len(applied) > 0 {
		if _, _, err := config.Load(config.LoadOptions{Profiles: applied, GlobalPath: os.Getenv(sandbox.GlobalConfigEnvVar), ProjectDir: projectSrc}); err != nil {
			return nil, fatalf(os.Stderr, "profiles %s: the hook in workdir %s cannot load them: %v", strings.Join(applied, ","), projectSrc, err)
		}
	}

	// A `corral run <agent>` positional overrides the configured agent. Set before the trust
	// gate, because the private home path depends on the agent.
	if f.agent != "" {
		cfg.Agent = f.agent
	}
	host := envMap()
	privHome, homeOn := cfg.Providers.Home.Dir(f.home, cfg.AgentConfigDir(f.home, host))

	// Trust gate: a committed .corral.yml/.corral.local.yml is approve-once, as is every
	// executable a session hook would run and every kubeconfig in a sandbox-writable location.
	// Runs before any consumption or mint. --yes is refused here; --dry-run is exempt.
	kubes := collectKubeconfigs(cfg, projectSrc, privHome)
	if !f.dryRun && !checkRepoConfigTrust(sources, collectHookExecs(cfg, projectSrc), kubes, f.yes, os.Stdin, os.Stderr, c) {
		return nil, 1
	}
	if err := prepareAuditDir(cfg, f.home, f.dryRun); err != nil {
		return nil, fatalf(os.Stderr, "config invalid: %v", err)
	}
	// Always-blocked guard, symlink-resolving half. Runs after the trust gate, before consumption.
	if err := checkResolvedPathGrants(cfg, f.home); err != nil {
		return nil, fatalf(os.Stderr, "config invalid: %v", err)
	}

	// Resolve the program to run: the configured agent's binary on PATH, or -command to override.
	commandBin := f.command
	if commandBin == "" {
		agent, ok := agents.Lookup(cfg.EffectiveAgent())
		if !ok {
			return nil, fatalf(os.Stderr, "unknown agent %q", cfg.EffectiveAgent())
		}
		var found bool
		if commandBin, found = agentBinary(agent); !found {
			commandBin = agent.Binaries()[0]
		}
	}

	spec := sandbox.DefaultSpec(specParams(cfg, f.home, projectSrc, host, commandBin))
	// Pin the exact global config so commands inside the sandbox read the same file.
	pinGlobalConfig(&spec, sources)
	if spec.SetEnv == nil {
		spec.SetEnv = map[string]string{}
	}
	// Pin the applied profiles so commands inside the sandbox apply them too.
	if len(applied) > 0 {
		spec.SetEnv[sandbox.ProfilesEnvVar] = strings.Join(applied, ",")
	}
	// Pin the audit-log path so the sidecar and commands inside the sandbox do not resolve it
	// against the private home.
	agentConfigDir := cfg.AgentConfigDir(f.home, host)
	auditPath := configuredAuditPath(cfg, trust.StateDir(f.home, host["XDG_STATE_HOME"]), agentConfigDir)
	spec.SetEnv[sandbox.AuditPathEnvVar] = auditPath

	// Activate the agent's in-process policy extension, if it ships one.
	launchCfg := agentLaunch(cfg)
	var extensionArgs []string
	if len(launchCfg.ExtensionAsset) > 0 {
		assetPath, aerr := materializeExtension(f.home, launchCfg.ExtensionName, launchCfg.ExtensionAsset)
		if aerr != nil {
			return nil, fatalf(os.Stderr, "activate %s policy extension: %v", cfg.EffectiveAgent(), aerr)
		}
		if launchCfg.ExtensionEnv != nil {
			dir := filepath.Dir(assetPath)
			spec.Mounts = append(spec.Mounts, sandbox.Mount{Src: dir, Dst: dir, ReadOnly: true})
			extEnv, eerr := launchCfg.ExtensionEnv(assetPath, host)
			if eerr != nil {
				return nil, fatalf(os.Stderr, "activate %s policy extension: %v", cfg.EffectiveAgent(), eerr)
			}
			maps.Copy(spec.SetEnv, extEnv)
		} else {
			spec.Mounts = append(spec.Mounts, sandbox.Mount{Src: assetPath, Dst: assetPath, ReadOnly: true})
			extensionArgs = []string{launchCfg.ExtensionFlag, assetPath}
		}
	}
	agentArgs := slices.Concat(cfg.AgentArgs(), f.args)
	if launchCfg.Args != nil {
		var aerr error
		if agentArgs, aerr = launchCfg.Args(cfg.AgentArgs(), f.args); aerr != nil {
			return nil, fatalf(os.Stderr, "%s args: %v", cfg.EffectiveAgent(), aerr)
		}
	}
	// The config sections apply before the gate, so their warnings feed it and their masks are in
	// the spec before any feature provider mounts.
	owners, sectionRows, sectionWarnings := applyConfigSections(&spec, cfg, f.home, projectSrc)

	// Construct the backend and compute launch advisories before any mint. Written to stderr
	// so --dry-run's argv stays pipeable.
	backend := newBackend(backendKind, f.bwrap, cfg.Sandbox)
	// Fold the resolved backend's model-facing notes into the sandbox env.
	setBackendNotes(&spec, backend)
	checks := sessionWarnings(cfg, backendKind, backend.ReadOnlyTargets(spec))
	warnings := sectionWarnings
	// Startup readiness advisory: each agent reports its own set.
	if hostHome, herr := os.UserHomeDir(); herr == nil {
		if a, ok := agents.Lookup(cfg.EffectiveAgent()); ok {
			self, _ := os.Executable()
			checks = append(checks, a.LaunchWarnings(agents.StatusInput{Home: hostHome, Host: host, Self: self, WorkDir: projectSrc})...)
		}
	}
	// The kill switch is set in the shell asking for a sandboxed session, where corral ignores it.
	if sandbox.EnvEnabled(sandbox.DisableHooksEnvVar) {
		checks = append(checks, health.Check{State: health.Warn, Label: "environment", Value: sandbox.DisableHooksEnvVar + " is set in this shell",
			Reason: "no effect here: this session is enforced; an agent started without corral run is not",
			Fix:    "unset " + sandbox.DisableHooksEnvVar})
	}
	sess := newSession(f.home, projectSrc)
	// A preStart session hook's captured stderr renders in the banner's format.
	hookLog := &lineWriter{w: os.Stderr, c: c, g: report.None}
	// The kubernetes provider loads a gated kubeconfig only from bytes with the hash the gate checked.
	active := activeProviders(cfg, f.home, host, projectSrc, kubes.approved(), bannerSessionHookPresenter(os.Stderr, c), hookLog)
	command := append([]string{commandBin}, extensionArgs...)
	command = append(command, agentArgs...)

	// Side-effect-free preview of the feature providers: each one's static, secret-free contribution.
	// Credential-minters and session hooks are named (previewOnly) rather than expanded.
	preview, previewOnly, perr := providers.ResolvePreview(context.Background(), sess, active)
	if perr != nil && f.dryRun {
		return nil, fatalf(os.Stderr, "providers: %v", perr)
	}
	// Private-home shadows go through the gate: a detect-only pass over the full static mount set.
	homeArch := baselineArch(backendKind)
	keep := cfg.Providers.Home.KeepRel()
	guardDir := hookGuardDir(cfg, f.home, host)
	var shadows []string
	if homeOn {
		pre := spec // shallow copy: home.Link only reads
		pre.Mounts = append(slices.Clone(spec.Mounts), preview.Mounts()...)
		var serr error
		if shadows, serr = home.Link(&pre, f.home, privHome, homeArch, keep, guardDir, false); serr != nil {
			return nil, fatalf(os.Stderr, "home: %v", serr)
		}
		warnings = append(warnings, shadows...)
	}

	banner := bannerInfo{
		version:  f.version,
		home:     f.home,
		workdir:  spec.WorkDir,
		auditLog: auditPath,
		profiles: f.profiles,
	}

	return &launchPlan{
		cfg:            cfg,
		sources:        sources,
		flags:          f,
		projectSrc:     projectSrc,
		privHome:       privHome,
		homeOn:         homeOn,
		homeArch:       homeArch,
		keep:           keep,
		guardDir:       guardDir,
		kubes:          kubes,
		spec:           spec,
		owners:         owners,
		sectionRows:    sectionRows,
		checks:         checks,
		warnings:       warnings,
		backend:        backend,
		auditPath:      auditPath,
		agentConfigDir: agentConfigDir,
		command:        command,
		sess:           sess,
		active:         active,
		preview:        preview,
		previewOnly:    previewOnly,
		shadows:        shadows,
		banner:         banner,
		c:              c,
		warnLines:      warnLines,
		hookLog:        hookLog,
	}, 0
}

// cmdRun launches a coding agent inside the sandbox built from the effective config.
func cmdRun(args []string, version string) int {
	f, code, ok := parseRunFlags(args, version)
	if !ok {
		return code
	}
	p, code := planLaunch(f)
	if p == nil {
		return code
	}
	if f.dryRun {
		return printDryRun(p)
	}
	return launch(p)
}

func (p *launchPlan) notices(extra []providers.Notice) []providers.Notice {
	return append(slices.Clone(p.sectionRows), extra...)
}

// buildSandboxArgv prepares the backend and builds the sandbox argv. On an Argv error it runs the
// prep's cleanup and returns a zero prep.
func buildSandboxArgv(backend sandbox.Backend, spec *sandbox.SandboxSpec, command []string, warnLines *lineWriter) (sandbox.LaunchPrep, []string, int) {
	prep, err := backend.Prepare(spec, warnLines)
	warnLines.Flush()
	if err != nil {
		return prep, nil, fatalf(os.Stderr, "prepare sandbox: %v", err)
	}
	argv, err := backend.Argv(*spec, command)
	if err != nil {
		prep.Cleanup()
		return sandbox.LaunchPrep{}, nil, fatalf(os.Stderr, "build sandbox command: %v", err)
	}
	return prep, argv, 0
}

// printDryRun prints the banner and the sandbox command of the plan without a launch.
func printDryRun(p *launchPlan) int {
	if err := p.preview.Apply(&p.spec, p.owners); err != nil {
		return fatalf(os.Stderr, "providers: %v", err)
	}
	// The linking pass is skipped on a dry run: it only creates host symlinks and does not
	// mutate spec, so the printed profile is unaffected.
	p.warnings = append(p.warnings, p.preview.Warnings...)
	// Dry-run is network-free, so no version warning. A side-effect provider can't be previewed,
	// so it gets a launch-only row.
	writeStartupBanner(os.Stderr, p.c, p.cfg, p.banner, p.checks, p.warnings, p.notices(p.preview.Notices), p.previewOnly)
	// Dry-run is an inspection tool and is not gated, but a real run would prompt.
	writeTrustDryRunNote(os.Stderr, p.c, p.sources, collectHookExecs(p.cfg, p.projectSrc), p.kubes)
	prep, argv, code := buildSandboxArgv(p.backend, &p.spec, p.command, p.warnLines)
	if code != 0 {
		return code
	}
	fmt.Println(shellQuote(slices.Concat([]string{"env", "-i"}, p.spec.Environ(), argv)))
	// Name side-effect providers that would act at launch — to stderr so stdout stays pipeable.
	if len(p.previewOnly) > 0 {
		p.c.Message(os.Stderr, report.None, fmt.Sprintf("%d provider(s) not expanded in the profile above — they act only at launch (credential minting, session hooks): %s",
			len(p.previewOnly), strings.Join(p.previewOnly, ", ")))
	}
	prep.Cleanup()
	return 0
}

// launch shows the gate, mints the providers, starts the sidecar and supervises the agent.
func launch(p *launchPlan) int {
	// Registered before the teardown, so it runs after the session-end hooks.
	defer p.hookLog.Flush()
	ctx := context.Background()
	// Startup banner + confirmation gate, before minting. The gate fires only when warnings
	// exist and stdin is interactive: --yes skips it.
	p.banner.latest = checkUpdateOnStart(ctx, p.cfg, p.flags.home, p.flags.version)
	// Print the banner around the gate and the feature providers' output, so the providers section
	// renders as one contiguous block.
	writeBannerHeader(os.Stderr, p.c, p.cfg, p.banner, p.checks, p.warnings)
	if len(p.checks)+len(p.warnings) > 0 && !confirmProceed(p.flags.yes, os.Stdin, os.Stderr, p.c) {
		return fatalf(os.Stderr, "launch aborted — warnings not confirmed (pass --yes to skip this prompt)")
	}

	// Confirmed (or nothing to confirm): now Mint. A Mint error on a non-optional provider
	// fails the launch closed. resolveProviders is a test seam over providers.Resolve.
	//
	// The mint-to-launch window is signal-aware: NotifyContext converts SIGINT to ctx cancellation
	// so the interrupt tears down through the normal fail-closed teardown.
	mintCtx, stopMint := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stopMint()
	res, err := resolveProviders(mintCtx, p.sess, p.active)
	p.hookLog.Flush()
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
	// owners attributes a collision with a config section to that section, not "baseline".
	if err := res.Apply(&p.spec, p.owners); err != nil {
		return fatalf(os.Stderr, "providers: %v", err)
	}
	// With the home provider active, populate the private home with symlinks. After Apply so
	// the full mount set is known.
	var lateShadows []string
	if p.homeOn {
		late, lerr := home.Link(&p.spec, p.flags.home, p.privHome, p.homeArch, p.keep, p.guardDir, true)
		if lerr != nil {
			return fatalf(os.Stderr, "home: %v", lerr)
		}
		lateShadows = slices.DeleteFunc(late, func(s string) bool { return slices.Contains(p.shadows, s) })
	}

	// The providers section prints after the gate and the feature providers' mint.
	writeBannerBody(os.Stderr, p.c, p.flags.home, p.notices(res.Notices), nil)
	writeWarnings(os.Stderr, p.c, res.Warnings)
	writeWarnings(os.Stderr, p.c, lateShadows)

	// Move the selected agent's legacy default log before the sidecar writes the new one.
	if p.cfg.Policy.Audit.Path == "" {
		for _, err := range audit.MoveLegacy(legacyAuditPath(p.agentConfigDir), p.auditPath) {
			p.c.Message(os.Stderr, report.Attention, fmt.Sprintf("legacy audit log not moved: %v; move the file into %s or delete it by hand",
				err, filepath.Dir(p.auditPath)))
		}
	}

	// The sidecar evaluates the session's hook events against a policy fixed here, built from
	// what the sandbox sees: its HOME, environment, and working directory.
	if p.spec.SetEnv["HOME"] == "" {
		return fatalf(os.Stderr, "policy: HOME is empty in the sandbox environment")
	}
	handler, err := policyHandler(engineInputs{
		cfg:       p.cfg,
		home:      p.spec.SetEnv["HOME"],
		env:       maps.Clone(p.spec.SetEnv),
		workDir:   p.spec.WorkDir,
		auditPath: p.spec.SetEnv[sandbox.AuditPathEnvVar],
	})
	if err != nil {
		return fatalf(os.Stderr, "policy: %v", err)
	}
	srv, err := sidecar.Start(handler)
	if err != nil {
		return fatalf(os.Stderr, "sidecar: %v", err)
	}
	// Registered after the teardown, so it runs first on an abort and, on a launch, after
	// runSupervised has run the session-end hooks.
	defer func() { _ = srv.Close() }()
	p.spec.SetEnv[sandbox.SidecarSocketEnvVar] = srv.Path()
	// An overlay comes after every read-write bind and blocked-path mask, so neither a writable
	// ancestor nor a masked ancestor of the directory covers it.
	p.spec.Mounts = append(p.spec.Mounts, sandbox.Mount{Src: srv.Dir(), ReadOnly: true, Overlay: true})

	// Backend pre-launch ceremony. Prepare mutates spec in place and returns cleanup + a pre-launch
	// chdir.
	var argv []string
	var code int
	if prep, argv, code = buildSandboxArgv(p.backend, &p.spec, p.command, p.warnLines); code != 0 {
		return code
	}

	if !p.backend.Available() {
		return fatalf(os.Stderr, "%s", p.backend.UnavailableHint())
	}

	// Resolve the sandbox launcher (argv[0]: bwrap or sandbox-exec) to an absolute path.
	launcherAbs, err := exec.LookPath(argv[0])
	if err != nil {
		return fatalf(os.Stderr, "resolve %s path: %v", p.backend.Name(), err)
	}

	// A backend with no in-sandbox working-directory control asks the launcher to chdir.
	if prep.Chdir != "" {
		if err := os.Chdir(prep.Chdir); err != nil {
			return fatalf(os.Stderr, "chdir to work dir %q: %v", prep.Chdir, err)
		}
	}

	// Blank line so corral's banner is separated from claude's own UI.
	fmt.Fprintln(os.Stderr)

	// We outlive the child to serve the sidecar; the deferred teardown reclaims backend resources.
	return runSupervised(launcherAbs, argv, p.spec.Environ(), res)
}

// resolveWorkdir decides what host directory to mount as the writable project. Normally the
// launch directory itself. When it is the user's home, binding it would expose the whole home tree
// and back the always-blocked masks with the real host secret paths, so a fresh scratch dir is used
// instead. Not cleaned up (under $TMPDIR, reaped by the OS).
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
func runSupervised(launcherAbs string, argv, env []string, res *providers.Resolved) int {
	c := report.StyleFor(os.Stderr)
	// Surface a teardown confirmation per provider as it is cleaned up.
	res.OnTeardown = teardownReporter(os.Stderr, c)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
		defer cancel()
		if err := res.Cleanup(ctx); err != nil {
			c.Message(os.Stderr, report.Attention, fmt.Sprintf("provider cleanup: %v", err))
		}
	}()

	cmd := exec.Command(launcherAbs, argv[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// No host variable may reach the helper: bwrap is PID 1 and /proc/1/environ is readable inside
	// the sandbox. The values travel here, not in argv, which any local user can read.
	cmd.Env = env
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
		report.StyleFor(os.Stderr).Message(os.Stderr, report.Attention, fmt.Sprintf("post-session hooks: %v", err))
	}
}

// abortAfterMint tears a launch down after providers minted but before the agent ran:
// session-end hooks first, then LIFO Cleanup. Both run on fresh contexts with opposite bounds.
// One helper so every post-Resolve abort path tears down identically; nil-safe.
func abortAfterMint(res *providers.Resolved) {
	if res == nil {
		return
	}
	c := report.StyleFor(os.Stderr)
	res.OnTeardown = teardownReporter(os.Stderr, c)
	runPostSessionHooks(res, providers.SessionExit{})
	ctx, cancel := context.WithTimeout(context.Background(), cleanupTimeout)
	defer cancel()
	if err := res.Cleanup(ctx); err != nil {
		c.Message(os.Stderr, report.Attention, fmt.Sprintf("provider cleanup: %v", err))
	}
}

// teardownReporter renders each provider teardown as a row: confirmed, or failed with the
// residual-credential risk.
func teardownReporter(w io.Writer, c report.Style) func(string, error, string) {
	return func(provider string, err error, hint string) {
		if err != nil {
			c.Row(w, report.Row{Glyph: report.Blocked, Label: provider, Value: "teardown failed", Reason: hint})
			return
		}
		c.Row(w, report.Row{Glyph: report.Ready, Label: provider, Value: "minted credentials torn down"})
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

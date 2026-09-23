// Package seatbelt is the macOS sandbox backend: it compiles a sandbox.SandboxSpec
// into a Seatbelt (SBPL) profile run via sandbox-exec.
package seatbelt

import (
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/sandbox"
)

// Backend compiles a SandboxSpec into a macOS Seatbelt (SBPL) profile. Unlike
// bwrap, which exposes only bind-mounted paths, Seatbelt's (allow default) would
// let a session exec any host binary unless process-exec* is denied and
// re-allowed for the readable set.
type Backend struct {
	Path    string
	cfg     Config
	resolve symlinkResolver
}

func New(path string, cfg Config) Backend {
	if path == "" {
		path = "sandbox-exec"
	}
	return Backend{Path: path, cfg: cfg, resolve: realSymlink{}}
}

func (b Backend) Name() string { return "seatbelt" }

func (b Backend) Available() bool {
	if runtime.GOOS != "darwin" {
		return false
	}
	_, err := exec.LookPath(b.bin())
	return err == nil
}

func (b Backend) UnavailableHint() string {
	return "sandbox-exec not found; the seatbelt backend requires macOS with sandbox-exec on PATH"
}

func (b Backend) Doctor() []health.Check {
	return []health.Check{sandbox.ToolCheck(b.bin(), "the seatbelt backend requires macOS with sandbox-exec on PATH")}
}

// ReadOnlyTargets returns the macOS baseline's read-only targets for spec's
// tokens — the Seatbelt analogue of bwrap's read-only mounts. Only (subpath …)
// rules qualify; (literal …) single nodes have no subtree, and regex rules
// aren't paths. Returned paths are /private-normalized to match Seatbelt.
func (b Backend) ReadOnlyTargets(spec sandbox.SandboxSpec) []string {
	read, write, _ := compileMacOSBaseline(sandbox.RulesFor(spec), spec.Tokens, b.resolve)
	writeSet := make(map[string]bool, len(write))
	for _, it := range write {
		writeSet[it.val] = true
	}
	seen := make(map[string]bool, len(read))
	var out []string
	for _, it := range read {
		if it.kind != sbSubpath || writeSet[it.val] || seen[it.val] {
			continue
		}
		seen[it.val] = true
		out = append(out, it.val)
	}
	return out
}

const tmpAgentNote = "/tmp is not accessible; use the directory named by $TMPDIR for temporary files."

const xcrunTempNote = "macOS SIP tools (xcrun, /usr/bin/git, /usr/bin/clang) may print a harmless " +
	"\"couldn't create cache file ... xcrun_db-* (Operation not permitted)\" warning — they use a " +
	"sandbox-denied temp dir, not $TMPDIR; the command still succeeds, so ignore it and do not try to fix it."

// machStrictNote heads off wasted turns under strict mach-lookup. A denied Mach
// service surfaces as a generic failure or a hang, not an obvious sandbox denial.
const machStrictNote = "macOS strict mach-lookup is on: a command that fails or hangs on a network, " +
	"keychain/credential, or code-signing step may have hit a denied Mach service (logged as " +
	"\"corral-mach\"). Don't keep retrying — surface it; the user can allow the service via " +
	"sandbox.seatbelt.mach.allow, or fall back to sandbox.seatbelt.mach.lookup: open."

func (b Backend) AgentNotes() []string {
	notes := []string{tmpAgentNote, xcrunTempNote}
	if b.cfg.Mach.Strict() {
		notes = append(notes, machStrictNote)
	}
	return notes
}

// Prepare creates a private session temp dir and repoints temp variables and
// $SESSION_TMPDIR. macOS shares the host $TMPDIR across processes, so isolation
// prevents cross-process reads and predictable-name races. Failure is fail-safe:
// launch continues without temp access and emits a warning.
func (b Backend) Prepare(spec *sandbox.SandboxSpec, w io.Writer) (sandbox.LaunchPrep, error) {
	prep := sandbox.LaunchPrep{Cleanup: func() {}, Chdir: spec.WorkDir}
	if spec.SetEnv == nil {
		spec.SetEnv = map[string]string{}
	}
	if spec.Tokens == nil {
		spec.Tokens = map[string]string{}
	}

	d, err := os.MkdirTemp("/tmp", fmt.Sprintf("corral-%d-", os.Getuid()))
	if err != nil {
		fmt.Fprintf(w, "corral: warning: could not create a session temp dir under /tmp (%v); "+
			"temp file operations may fail inside the sandbox\n", err)
		return prep, nil
	}
	for _, k := range append([]string{"TMPDIR", "TMP", "TEMPDIR"}, spec.TempEnvAliases...) {
		spec.SetEnv[k] = d
	}
	sess := strings.TrimRight(d, "/")
	spec.SetEnv["TMPPREFIX"] = sess + "/zsh"
	spec.Tokens["SESSION_TMPDIR"] = sess
	prep.Cleanup = func() { removeTemp(d) }
	return prep, nil
}

// Argv compiles spec into a full sandbox-exec invocation: the binary, the
// profile inline via -p, then /usr/bin/env -i. Env keys are sorted for
// deterministic (golden-testable) output.
func (b Backend) Argv(spec sandbox.SandboxSpec, command []string) ([]string, error) {
	if len(command) == 0 {
		return nil, errors.New("sandbox: empty command")
	}
	profile, err := b.profile(spec)
	if err != nil {
		return nil, err
	}
	bin := b.bin()

	argv := []string{bin, "-p", profile, "/usr/bin/env", "-i"}
	for _, k := range slices.Sorted(maps.Keys(spec.SetEnv)) {
		argv = append(argv, k+"="+spec.SetEnv[k])
	}
	argv = append(argv, command...)
	return argv, nil
}

func (b Backend) bin() string {
	if b.Path == "" {
		return "sandbox-exec"
	}
	return b.Path
}

func (b Backend) profile(spec sandbox.SandboxSpec) (string, error) {
	read, write, homePaths := compileMacOSBaseline(sandbox.RulesFor(spec), spec.Tokens, b.resolve)

	var mountSeeds []string
	for _, m := range spec.Mounts {
		if m.Src == "" || !path.IsAbs(m.Src) {
			return "", fmt.Errorf("sandbox: mount source must be an absolute path, got %q", m.Src)
		}
		val := normalizeMacPath(m.Src)
		it := sbItem{kind: sbSubpath, val: val}
		read = append(read, it)
		if !m.ReadOnly {
			write = append(write, it)
		}
		mountSeeds = append(mountSeeds, val)
	}

	// Metadata ancestors: under deny-by-default reads, $HOME and the components
	// above each allowed entry are unreadable, breaking tools that resolve a
	// realpath by lstat-ing every component (kustomize, EvalSymlinks). Granting
	// file-read-metadata on ancestors lets the walk proceed while directory
	// contents stay unreadable.
	home := normalizeMacPath(spec.Tokens["HOME"])
	seeds := make([]string, 0, len(homePaths)+len(mountSeeds)+2)
	if home != "" {
		seeds = append(seeds, home)
	}
	seeds = append(seeds, homePaths...)
	seeds = append(seeds, mountSeeds...)
	if sess := normalizeMacPath(spec.Tokens["SESSION_TMPDIR"]); sess != "" {
		seeds = append(seeds, sess)
	}
	meta := metadataAncestors(seeds)

	var sb strings.Builder
	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n\n")

	sb.WriteString(";; Writes: deny everything, then re-allow a specific set.\n")
	sb.WriteString("(deny file-write*)\n")
	sb.WriteString("(allow file-write*\n")
	for _, it := range write {
		fmt.Fprintf(&sb, "  %s\n", it.sbpl())
	}
	sb.WriteString(")\n\n")

	sb.WriteString(";; Reads: deny by default, then re-allow the system roots the agent needs to\n")
	sb.WriteString(";; boot (dyld shared cache, frameworks, libraries, locale/CA data) plus its\n")
	sb.WriteString(";; own state and the resolved agent binary dir. $HOME stays deny-by-default\n")
	sb.WriteString(";; (only the entries below are readable); /Users/<others>, /Volumes stay denied.\n")
	sb.WriteString("(deny file-read*)\n")
	sb.WriteString("(allow file-read*\n")
	for _, it := range read {
		fmt.Fprintf(&sb, "  %s\n", it.sbpl())
	}
	sb.WriteString(")\n\n")

	// exec is a subset of file-read, so the blocked-path deny below covers it too.
	sb.WriteString(";; Exec: deny by default, then re-allow EXACTLY the readable set above — a\n")
	sb.WriteString(";; binary (or a #! script's interpreter) may be exec'd only from a path the\n")
	sb.WriteString(";; sandbox can also read. Without this, (allow default) lets the session exec\n")
	sb.WriteString(";; any binary on the host, even in dirs whose contents are otherwise hidden.\n")
	sb.WriteString("(deny process-exec*)\n")
	sb.WriteString("(allow process-exec*\n")
	for _, it := range read {
		fmt.Fprintf(&sb, "  %s\n", it.sbpl())
	}
	sb.WriteString(")\n\n")

	if len(meta) > 0 {
		sb.WriteString(";; Metadata-only (lstat) on the ancestors of the readable paths, so\n")
		sb.WriteString(";; realpath walks that lstat each component still succeed under the\n")
		sb.WriteString(";; deny-by-default read policy (directory contents stay unreadable).\n")
		sb.WriteString("(allow file-read-metadata\n")
		for _, p := range meta {
			fmt.Fprintf(&sb, "  (literal \"%s\")\n", sbplEscape(p))
		}
		sb.WriteString(")\n\n")
	}

	if len(spec.BlockedPaths) > 0 || len(spec.BlockedFiles) > 0 {
		sb.WriteString(";; Blocked paths (always-blocked + config) — deny all reads, writes, and execs.\n")
		sb.WriteString(";; Placed after the allow rules so it overrides them, e.g. ~/.ssh. process-exec*\n")
		sb.WriteString(";; is included so a secret dir/file nested under an allowed mount can't be exec'd.\n")
		sb.WriteString("(deny file-read* file-write* process-exec*\n")
		for _, p := range spec.BlockedPaths {
			fmt.Fprintf(&sb, "  (subpath \"%s\")\n", sbplEscape(normalizeMacPath(p)))
		}
		// block.files: (literal …) is precise since a file has no subtree. Excluded
		// from the lstat re-allow below, so even a blocked file's existence stays hidden.
		for _, p := range spec.BlockedFiles {
			fmt.Fprintf(&sb, "  (literal \"%s\")\n", sbplEscape(normalizeMacPath(p)))
		}
		sb.WriteString(")\n\n")

		// Re-allow lstat of each blocked directory's leaf so the hook can
		// canonicalize these roots at boot. Without it the deny masks
		// file-read-metadata and the hook's policy init fails closed on
		// lstat(~/.ssh). Literal-scoped; contents stay denied.
		if len(spec.BlockedPaths) > 0 {
			sb.WriteString(";; ...but re-allow lstat of the blocked-DIRECTORY leaves so the hook can\n")
			sb.WriteString(";; canonicalize them at startup (literal only — contents stay hidden).\n")
			sb.WriteString("(allow file-read-metadata\n")
			for _, p := range spec.BlockedPaths {
				fmt.Fprintf(&sb, "  (literal \"%s\")\n", sbplEscape(normalizeMacPath(p)))
			}
			sb.WriteString(")\n\n")
		}
	}

	if spec.Net == sandbox.NetNone {
		sb.WriteString(";; Network isolation.\n")
		sb.WriteString("(deny network*)\n\n")
	}

	sb.WriteString(";; Process isolation — keep a compromised session from inspecting or controlling\n")
	sb.WriteString(";; other processes. process-info* covers the proc_info syscall family;\n")
	sb.WriteString(";; mach-task-read/mach-task-name cover the read/name task ports behind\n")
	sb.WriteString(";; mach_vm_read/vmmap (else a session could dump ssh-agent / gpg-agent memory);\n")
	sb.WriteString(";; mach-priv-task-port covers the full control port (task_for_pid), which also\n")
	sb.WriteString(";; allows WRITING another task's memory and injecting threads. (target others)\n")
	sb.WriteString(";; leaves self- and same-sandbox (child) targets intact.\n")
	sb.WriteString("(deny process-info* (target others))\n")
	sb.WriteString("(deny mach-task-read mach-task-name (target others))\n")
	sb.WriteString("(deny mach-priv-task-port (target others))\n\n")

	if b.cfg.Mach.Strict() {
		sb.WriteString(";; Strict mach-lookup: deny by default, re-allow only the curated allowlist. The escape\n")
		sb.WriteString(";; services (LaunchServices/quarantine), the data-reach ones (pasteboard/mds/contacts), and\n")
		sb.WriteString(";; analyticsd telemetry are denied by absence. (Apple Events cross-app RCE is NOT closed\n")
		sb.WriteString(";; even here — appleeventsd brokers it via the bootstrap port; an accepted residual.)\n")
		// The (with message …) tag stamps "corral-mach" into each denial's
		// sandbox-violation log line so `log stream` can isolate corral's denials.
		sb.WriteString(`(deny mach-lookup (with message "corral-mach"))` + "\n")
		sb.WriteString("(allow mach-lookup\n")
		for _, s := range machAllowlist {
			fmt.Fprintf(&sb, "  %s\n", s.sbpl())
		}
		for _, raw := range b.cfg.Mach.Allow {
			fmt.Fprintf(&sb, "  %s\n", machAllowEntry(raw).sbpl())
		}
		sb.WriteString(")\n")
	} else {
		// Open mode: keep allow-default mach-lookup and scope the deny to the
		// sandbox-escape services (LaunchServices/launchd hand-off).
		sb.WriteString(";; Sandbox-escape hardening: deny the LaunchServices/launchd hand-off `open` uses to\n")
		sb.WriteString(";; spawn its target OUTSIDE this profile. Both coreservices subspaces are load-bearing —\n")
		sb.WriteString(";; denying either alone still escapes. (Apple Events cross-app RCE is NOT closable in SBPL:\n")
		sb.WriteString(";; appleeventsd brokers the send via the bootstrap port — neither a mach-lookup deny nor\n")
		sb.WriteString(";; (deny appleevent-send) stops it, both verified on macOS 26. Accepted OS-layer residual.)\n")
		sb.WriteString("(deny mach-lookup\n")
		sb.WriteString(`  (global-name-regex #"^com\.apple\.coreservices\.launchservices")` + "\n")
		sb.WriteString(`  (global-name-regex #"^com\.apple\.coreservices\.quarantine")` + "\n")
		sb.WriteString(")\n")
	}

	return sb.String(), nil
}

func removeTemp(dir string) {
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
}

type sbKind int

const (
	sbSubpath sbKind = iota
	sbLiteral
	sbRegex
)

type sbItem struct {
	kind sbKind
	val  string
}

func (it sbItem) sbpl() string {
	switch it.kind {
	case sbRegex:
		return fmt.Sprintf(`(regex #"%s")`, it.val)
	case sbLiteral:
		return fmt.Sprintf(`(literal "%s")`, sbplEscape(it.val))
	default:
		return fmt.Sprintf(`(subpath "%s")`, sbplEscape(it.val))
	}
}

// compileMacOSBaseline turns the baseline rules into SBPL read/write filters.
// Every macOS-applicable rule is readable; writeable ones also join the write
// set. recursive:false → literal, regex:true → regex, else subpath;
// resolveSymlinks fully canonicalizes and additionally grants each symlink node
// it crossed; a rule whose token is missing/empty is skipped (fail-safe).
// homePaths collects the readable paths under $HOME for metadata-ancestor
// derivation.
func compileMacOSBaseline(rules []sandbox.Rule, tokens map[string]string, resolve symlinkResolver) (read, write []sbItem, homePaths []string) {
	home := normalizeMacPath(tokens["HOME"])
	for _, r := range rules {
		if !sandbox.ArchMatch(r, "macos") {
			continue
		}
		val, ok := sandbox.ExpandPath(r.Path, tokens)
		if !ok || val == "" {
			continue
		}
		var kind sbKind
		switch {
		case r.Regex:
			kind = sbRegex
		case r.Recursive != nil && !*r.Recursive:
			kind = sbLiteral
		default:
			kind = sbSubpath
		}
		seed := func(p string) {
			if home != "" && pathutil.Under(p, home) {
				homePaths = append(homePaths, p)
			}
		}
		if kind != sbRegex {
			if r.ResolveSymlinks {
				var links []string
				val, links = resolve.resolve(val)
				// Each crossed node gets a read grant of its own so the kernel
				// may readlink it. Node-only (never subpath): the grant buys
				// traversal, not the link target's tree. Read-only even for a
				// writeable rule — a write lands on the target, not the link.
				for _, l := range links {
					l = normalizeMacPath(l)
					read = append(read, sbItem{kind: sbLiteral, val: l})
					seed(l)
				}
			}
			val = normalizeMacPath(val)
		}
		it := sbItem{kind: kind, val: val}
		read = append(read, it)
		if r.Writeable {
			write = append(write, it)
		}
		if kind != sbRegex {
			seed(val)
		}
	}
	return read, write, homePaths
}

// metadataAncestors returns the sorted, de-duplicated ancestors of the seed
// paths, each seed's parent up to (not including) the root.
func metadataAncestors(seeds []string) []string {
	set := map[string]bool{}
	for _, s := range seeds {
		if s == "" || s == "/" {
			continue
		}
		for cur := path.Dir(s); cur != "" && cur != "/" && cur != "."; cur = path.Dir(cur) {
			set[cur] = true
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// normalizeMacPath maps the macOS root symlinks /var, /tmp, /etc onto their
// kernel-resolved /private targets, which Seatbelt rules match against. Only
// subtrees map (/var/X → /private/var/X); bare nodes and anything already under
// /private pass through.
func normalizeMacPath(p string) string {
	for _, pre := range []string{"/var/", "/tmp/", "/etc/"} {
		if strings.HasPrefix(p, pre) {
			return "/private" + p
		}
	}
	return p
}

// NormalizeMacPath exposes normalizeMacPath to the launcher's paths.rw-shadow
// advisory, which must fold a config grant the same way the profile folds its
// targets.
func NormalizeMacPath(p string) string { return normalizeMacPath(p) }

// sbplEscape escapes a Go string for an SBPL double-quoted string literal:
// backslash and double-quote.
func sbplEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// symlinkResolver canonicalizes a path through every symlink hop. Seatbelt
// matches a rule against the kernel-canonical path of the file opened, so
// resolving only one hop (or leaving a symlinked ancestor unresolved) grants a
// path the kernel never presents — the read then EPERMs.
//
// links carries every symlink node crossed, because canonicalizing is itself a
// policed read: under deny-by-default reads a node the profile does not name
// EPERMs before the granted target is reached. A resolveSymlinks rule needs the
// same grant for the hops it resolves past.
type symlinkResolver interface {
	resolve(p string) (target string, links []string)
}

type realSymlink struct{}

func (realSymlink) resolve(p string) (string, []string) {
	resolved, err := filepath.EvalSymlinks(p)
	if err != nil {
		return p, symlinkNodes(p)
	}
	return resolved, symlinkNodes(p)
}

// maxSymlinkHops bounds the walk against a cycle or a pathological chain. It
// only caps how many nodes get grants: the resolved target is granted
// regardless, so a truncated walk under-grants rather than failing the launch.
const maxSymlinkHops = 40

// symlinkNodes returns every symlink crossed while canonicalizing p, each named
// by the path at which the kernel meets it, in walk order, excluding the final
// target. It walks component by component because EvalSymlinks reports only
// the endpoint, and it is the intermediate nodes that need their own grants.
func symlinkNodes(p string) []string {
	if !filepath.IsAbs(p) {
		return nil
	}
	sep := string(os.PathSeparator)
	split := func(q string) []string {
		return strings.Split(strings.TrimPrefix(filepath.Clean(q), sep), sep)
	}
	var out []string
	seen := map[string]bool{}
	cur, rest := sep, split(p)
	for hops := 0; len(rest) > 0; {
		name := rest[0]
		rest = rest[1:]
		if name == "" || name == "." {
			continue
		}
		cur = filepath.Join(cur, name)
		fi, err := os.Lstat(cur)
		if err != nil {
			return out
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if hops++; hops > maxSymlinkHops {
			return out
		}
		if !seen[cur] {
			seen[cur] = true
			out = append(out, cur)
		}
		tgt, err := os.Readlink(cur)
		if err != nil {
			return out
		}
		if !filepath.IsAbs(tgt) {
			tgt = filepath.Join(filepath.Dir(cur), tgt)
		}
		rest = append(split(tgt), rest...)
		cur = sep
	}
	return out
}

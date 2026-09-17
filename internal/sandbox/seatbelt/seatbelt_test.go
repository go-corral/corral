package seatbelt

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/sandbox"
)

var update = flag.Bool("update", false, "regenerate golden files")

// macTestTokens supplies every macOS token, so no rule is skipped for a missing
// token. Uses a /Users home (realistic macOS) so the outer-ancestor (/Users)
// derivation is exercised.
func macTestTokens() map[string]string {
	return map[string]string{
		"HOME":             "/Users/u",
		"AGENT_CONFIG_DIR": "/Users/u/.claude",
		"SESSION_TMPDIR":   "/tmp/corral-501-abc", // an isolated dir under /tmp (deny-by-default tree)
		"AGENT_BIN_DIR":    "/opt/claude/bin",
	}
}

// noResolve is a symlinkResolver that returns paths unchanged, so golden tests stay deterministic
// (the real resolver hits the host filesystem). The baseline's resolveSymlinks rules
// (~/.gitconfig, /etc/resolv.conf) compile to their unresolved paths under it.
type noResolve struct{}

func (noResolve) resolve(p string) (string, []string) { return p, nil }

// mapResolve resolves a fixed set of symlinks for the resolveSymlinks test. A mapped path counts
// as the one node crossed, so the fake exercises the node-grant path too.
type mapResolve struct{ m map[string]string }

func (r mapResolve) resolve(p string) (string, []string) {
	if t, ok := r.m[p]; ok {
		return t, []string{p}
	}
	return p, nil
}

// macBackend is a Backend with the no-op symlink resolver (deterministic tests).
// Per-launch tokens travel in the spec now, so withTok injects them.
func macBackend() Backend { return Backend{Path: "sandbox-exec", resolve: noResolve{}} }

// withTok returns a copy of spec carrying tokens (the per-launch token map the
// backend expands baseline rule paths against).
func withTok(spec sandbox.SandboxSpec, tokens map[string]string) sandbox.SandboxSpec {
	spec.Tokens = tokens
	return spec
}

func hasItem(items []sbItem, kind sbKind, val string) bool {
	for _, it := range items {
		if it.kind == kind && it.val == val {
			return true
		}
	}
	return false
}

func contains(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}

func TestNormalizeMacPath(t *testing.T) {
	cases := map[string]string{
		"/var/folders/x":   "/private/var/folders/x",
		"/tmp/y":           "/private/tmp/y",
		"/etc/resolv.conf": "/private/etc/resolv.conf",
		"/etc":             "/etc", // bare symlink node passes through
		"/var":             "/var",
		"/tmp":             "/tmp",
		"/private/var":     "/private/var", // already resolved
		"/usr":             "/usr",
		"/Users/u/proj":    "/Users/u/proj",
	}
	for in, want := range cases {
		if got := normalizeMacPath(in); got != want {
			t.Errorf("normalizeMacPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// NormalizeMacPath is the exported entry the cli paths.rw-shadow advisory uses; it
// must stay byte-identical to the internal transform so the two sides cannot drift.
func TestNormalizeMacPathExported(t *testing.T) {
	for _, p := range []string{"/var/log", "/tmp/x", "/etc/hosts", "/usr", "/private/var", "/Users/u/p"} {
		if got, want := NormalizeMacPath(p), normalizeMacPath(p); got != want {
			t.Errorf("NormalizeMacPath(%q) = %q, want %q (must match the internal transform)", p, got, want)
		}
	}
}

func TestSBPLEscape(t *testing.T) {
	if got := sbplEscape(`a"b\c`); got != `a\"b\\c` {
		t.Errorf("sbplEscape = %q, want %q", got, `a\"b\\c`)
	}
	if got := (sbItem{kind: sbSubpath, val: `/a b`}).sbpl(); got != `(subpath "/a b")` {
		t.Errorf("subpath sbpl = %q", got)
	}
	if got := (sbItem{kind: sbLiteral, val: `/x`}).sbpl(); got != `(literal "/x")` {
		t.Errorf("literal sbpl = %q", got)
	}
	if got := (sbItem{kind: sbRegex, val: `^/dev/ttys`}).sbpl(); got != `(regex #"^/dev/ttys")` {
		t.Errorf("regex sbpl = %q", got)
	}
}

func TestMetadataAncestors(t *testing.T) {
	seeds := []string{"/Users/u", "/Users/u/.claude", "/Users/u/.config/git", "/", ""}
	got := metadataAncestors(seeds)
	want := []string{"/Users", "/Users/u", "/Users/u/.config"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("metadataAncestors = %v, want %v", got, want)
	}
}

func TestCompileMacOSBaselineBehavior(t *testing.T) {
	read, write, homePaths := compileMacOSBaseline(sandbox.BaselineRules(), macTestTokens(), noResolve{})

	// System roots: read-only subpaths, never writable.
	for _, p := range []string{"/usr", "/System", "/Library", "/sbin", "/opt"} {
		if !hasItem(read, sbSubpath, p) {
			t.Errorf("%s must be a read subpath", p)
		}
		if hasItem(write, sbSubpath, p) {
			t.Errorf("%s must NOT be writable", p)
		}
	}

	// /etc nodes are /private-normalized; resolv.conf is a single node (literal).
	if !hasItem(read, sbLiteral, "/private/etc/resolv.conf") {
		t.Error("/etc/resolv.conf must compile to a /private literal")
	}
	if !hasItem(read, sbSubpath, "/private/etc/ssl") {
		t.Error("/etc/ssl must compile to a /private subpath")
	}
	// The bare /etc /tmp /var symlink nodes pass through as literals (the kernel
	// readlinks them during path resolution).
	for _, p := range []string{"/etc", "/tmp", "/var", "/"} {
		if !hasItem(read, sbLiteral, p) {
			t.Errorf("%s must compile to a read literal (symlink/root node)", p)
		}
	}

	// $AGENT_CONFIG_DIR: writable subpath, present in both read and write.
	if !hasItem(read, sbSubpath, "/Users/u/.claude") || !hasItem(write, sbSubpath, "/Users/u/.claude") {
		t.Error("$AGENT_CONFIG_DIR must be a writable subpath (read+write)")
	}

	// Device nodes: writable literals; the pty/fd regexes are writable regexes.
	if !hasItem(read, sbLiteral, "/dev/null") || !hasItem(write, sbLiteral, "/dev/null") {
		t.Error("/dev/null must be a writable literal")
	}
	if !hasItem(read, sbRegex, "^/dev/ttys") || !hasItem(write, sbRegex, "^/dev/ttys") {
		t.Error("^/dev/ttys must be a writable regex")
	}
	if !hasItem(read, sbRegex, "^/dev/fd/") {
		t.Error("^/dev/fd/ must be a read regex")
	}

	// macOS-specific writable state.
	if !hasItem(write, sbSubpath, "/Users/u/Library/Keychains") {
		t.Error("$HOME/Library/Keychains must be writable")
	}
	if !hasItem(write, sbSubpath, "/private/tmp/corral-501-abc") {
		t.Error("$SESSION_TMPDIR must be a writable, /private-normalized subpath")
	}

	// Linux-only rules must not leak into the macOS compile.
	for _, p := range []string{"/lib", "/lib64"} {
		if hasItem(read, sbSubpath, p) {
			t.Errorf("Linux-only %s must not appear in the macOS compile", p)
		}
	}

	// homePaths carries the readable $HOME-internal paths (for ancestor derivation),
	// and only those strictly under $HOME.
	for _, p := range homePaths {
		if !pathutil.Under(p, "/Users/u") {
			t.Errorf("homePaths must be strictly under $HOME; got %q", p)
		}
	}
	if len(homePaths) == 0 {
		t.Error("expected some $HOME-internal readable paths")
	}
}

func TestCompileMacOSSkipsMissingToken(t *testing.T) {
	// AGENT_BIN_DIR empty -> the $AGENT_BIN_DIR rule is skipped (never emit a
	// partially-resolved or empty path).
	tok := macTestTokens()
	tok["AGENT_BIN_DIR"] = ""
	read, _, _ := compileMacOSBaseline(sandbox.BaselineRules(), tok, noResolve{})
	for _, it := range read {
		if it.val == "" || it.val == "/opt/claude/bin" {
			t.Errorf("missing AGENT_BIN_DIR must skip its rule; got %q", it.val)
		}
	}
}

func TestCompileMacOSNonStandardHome(t *testing.T) {
	// Root's home (/var/root) maps under /private; the readable $HOME paths and the
	// ancestor seed must agree (both normalized) so metadata derivation is not
	// silently emptied — a realpath walk under such a home would otherwise break.
	tok := map[string]string{
		"HOME":             "/var/root",
		"AGENT_CONFIG_DIR": "/var/root/.claude",
		"SESSION_TMPDIR":   "/var/folders/zz/T",
		"AGENT_BIN_DIR":    "/opt/claude/bin",
	}
	read, _, homePaths := compileMacOSBaseline(sandbox.BaselineRules(), tok, noResolve{})
	if !hasItem(read, sbSubpath, "/private/var/root/.claude") {
		t.Error("$AGENT_CONFIG_DIR must compile under /private for a /var/root home")
	}
	found := false
	for _, p := range homePaths {
		if p == "/private/var/root/.claude" {
			found = true
		}
		if !strings.HasPrefix(p, "/private/var/root/") {
			t.Errorf("homePaths must be under the normalized home; got %q", p)
		}
	}
	if !found {
		t.Error("normalized $HOME-internal path missing from homePaths (metadata would be empty)")
	}
	profile, err := macBackend().profile(withTok(sandbox.SandboxSpec{SetEnv: map[string]string{}}, tok))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, `(literal "/private/var/root")`) {
		t.Error("metadata ancestors must include the normalized home dir")
	}
}

func TestCompileMacOSClaudeBinDirUnderHome(t *testing.T) {
	// claude installed under $HOME (nvm / standalone) is the case where $AGENT_BIN_DIR
	// is the sole allow-rule for the binary dir: $HOME is deny-by-default and /opt does
	// not cover it. Verify it lands in the read set (not write) and seeds its ancestors.
	tok := macTestTokens()
	tok["AGENT_BIN_DIR"] = "/Users/u/.nvm/versions/node/v20/bin"
	read, write, homePaths := compileMacOSBaseline(sandbox.BaselineRules(), tok, noResolve{})
	if !hasItem(read, sbSubpath, "/Users/u/.nvm/versions/node/v20/bin") {
		t.Error("$AGENT_BIN_DIR under $HOME must be a read subpath")
	}
	if hasItem(write, sbSubpath, "/Users/u/.nvm/versions/node/v20/bin") {
		t.Error("$AGENT_BIN_DIR is read-only; must not be writable")
	}
	found := false
	for _, p := range homePaths {
		if p == "/Users/u/.nvm/versions/node/v20/bin" {
			found = true
		}
	}
	if !found {
		t.Error("$HOME-internal AGENT_BIN_DIR must seed metadata ancestors")
	}
	profile, err := macBackend().profile(withTok(sandbox.SandboxSpec{SetEnv: map[string]string{}}, tok))
	if err != nil {
		t.Fatal(err)
	}
	for _, anc := range []string{"/Users/u/.nvm", "/Users/u/.nvm/versions/node/v20"} {
		if !strings.Contains(profile, `(literal "`+anc+`")`) {
			t.Errorf("metadata ancestors must include %q", anc)
		}
	}
}

func TestSeatbeltRejectsRelativeMountSource(t *testing.T) {
	spec := sandbox.SandboxSpec{Mounts: []sandbox.Mount{{Src: "relative/path"}}}
	if _, err := macBackend().Argv(withTok(spec, macTestTokens()), []string{"true"}); err == nil {
		t.Error("a relative mount source must fail closed")
	}
}

func TestCompileMacOSResolveSymlinks(t *testing.T) {
	// resolveSymlinks runs before normalization: /etc/foo -> /etc/real/foo ->
	// /private/etc/real/foo. mapResolve stands in for the real EvalSymlinks resolver.
	rules := []sandbox.Rule{{Path: "/etc/foo", Description: "d", ResolveSymlinks: true, Archs: []string{"macos"}}}
	res := mapResolve{m: map[string]string{"/etc/foo": "/etc/real/foo"}}
	read, _, _ := compileMacOSBaseline(rules, macTestTokens(), res)
	if len(read) != 2 || !hasItem(read, sbSubpath, "/private/etc/real/foo") {
		t.Errorf("resolveSymlinks then normalize failed; got %+v", read)
	}
	// The crossed node is granted alongside the target, as a node, so the kernel may readlink it.
	if !hasItem(read, sbLiteral, "/private/etc/foo") {
		t.Errorf("the crossed symlink node must be granted too; got %+v", read)
	}
}

func TestSeatbeltArgvEnvAndCommand(t *testing.T) {
	spec := fixedMacSpec()
	spec.SetEnv = map[string]string{"B": "2", "A": "1"}
	argv, err := macBackend().Argv(withTok(spec, macTestTokens()), []string{"claude", "--model", "opus"})
	if err != nil {
		t.Fatal(err)
	}
	if argv[0] != "sandbox-exec" || argv[1] != "-p" {
		t.Errorf("argv must start with `sandbox-exec -p`; got %v", argv[:2])
	}
	// After the profile: `/usr/bin/env -i A=1 B=2 claude --model opus`.
	want := []string{"/usr/bin/env", "-i", "A=1", "B=2", "claude", "--model", "opus"}
	if got := argv[3:]; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("argv tail = %v, want %v", got, want)
	}
}

func TestSeatbeltEmptyCommand(t *testing.T) {
	if _, err := macBackend().Argv(withTok(fixedMacSpec(), macTestTokens()), nil); err == nil {
		t.Error("empty command must fail closed")
	}
}

func TestSeatbeltEmptyMountSource(t *testing.T) {
	spec := sandbox.SandboxSpec{Mounts: []sandbox.Mount{{Src: ""}}}
	if _, err := macBackend().Argv(withTok(spec, macTestTokens()), []string{"true"}); err == nil {
		t.Error("an empty mount source must fail closed")
	}
}

func TestSeatbeltProfileStructure(t *testing.T) {
	spec := fixedMacSpec()
	spec.Net = sandbox.NetNone
	profile, err := macBackend().profile(withTok(spec, macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}
	mustContain := []string{
		"(version 1)",
		"(allow default)",
		"(deny file-write*)",
		"(deny file-read*)",
		"(deny process-exec*)", // exec deny-by-default, re-allowed on the read set
		"(allow process-exec*",
		"(allow file-read-metadata",
		"(deny network*)", // NetNone
		"(deny process-info* (target others))",
		"(deny mach-task-read mach-task-name (target others))",
	}
	for _, s := range mustContain {
		if !strings.Contains(profile, s) {
			t.Errorf("profile missing %q", s)
		}
	}

	// Blocked paths are denied after the read-allow set so they win, and they are
	// /private-normalized.
	blockIdx := strings.Index(profile, "(deny file-read* file-write*")
	readAllowIdx := strings.Index(profile, "(allow file-read*")
	if blockIdx < 0 || blockIdx < readAllowIdx {
		t.Error("blocked-path deny must come after the read-allow set")
	}
	if !strings.Contains(profile, `(subpath "/Users/u/.ssh")`) {
		t.Error("blocked secret dir must be denied as a subpath")
	}
}

// TestSeatbeltExecTracksReadSet pins the "you may only run what you can read"
// invariant on macOS: process-exec* is denied by default and re-allowed on exactly
// the readable set (byte-identical to the file-read* allow body), so a session can
// never exec a binary in a directory whose contents it cannot read. Without it,
// (allow default) would permit executing any binary on the host.
func TestSeatbeltExecTracksReadSet(t *testing.T) {
	profile, err := macBackend().profile(withTok(fixedMacSpec(), macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}

	// exec must be deny-by-default before the re-allow (last-match-wins).
	denyExecIdx := strings.Index(profile, "(deny process-exec*)")
	allowExecIdx := strings.Index(profile, "(allow process-exec*\n")
	if denyExecIdx < 0 || allowExecIdx < 0 {
		t.Fatalf("profile must deny then re-allow process-exec*; profile:\n%s", profile)
	}
	if denyExecIdx > allowExecIdx {
		t.Error("(deny process-exec*) must come BEFORE (allow process-exec* …) so the allow wins")
	}

	// The exec-allow body must be byte-identical to the read-allow body: exec ⊆ read,
	// and in fact == the read set. Comparing the rendered bodies catches any drift
	// (a path added to reads but not to exec, or vice-versa).
	readBody := allowBody(t, profile, "(allow file-read*\n")
	execBody := allowBody(t, profile, "(allow process-exec*\n")
	if readBody != execBody {
		t.Errorf("exec allow set must equal the read allow set\n--- read ---\n%s\n--- exec ---\n%s", readBody, execBody)
	}

	// The exec re-allow must sit after the read allow and before the blocked-path deny,
	// so a blocked path (which lists process-exec* too) overrides the exec allow.
	readAllowIdx := strings.Index(profile, "(allow file-read*\n")
	blockIdx := strings.Index(profile, "(deny file-read* file-write* process-exec*\n")
	if blockIdx < 0 {
		t.Fatal("blocked-path deny must list process-exec* alongside file-read*/file-write*")
	}
	if readAllowIdx >= allowExecIdx || allowExecIdx >= blockIdx {
		t.Errorf("exec allow (%d) must be between read allow (%d) and blocked deny (%d)", allowExecIdx, readAllowIdx, blockIdx)
	}

	// A blocked secret dir must therefore also be exec-denied: it appears inside the
	// (deny … process-exec* …) block.
	if !strings.Contains(profile[blockIdx:], `(subpath "/Users/u/.ssh")`) {
		t.Error("blocked secret dir must be denied exec (under the process-exec* deny)")
	}
}

// allowBody returns the indented filter lines of the SBPL `(allow …` block that
// starts with header, i.e. everything between the header line and its closing ")".
func allowBody(t *testing.T, profile, header string) string {
	t.Helper()
	start := strings.Index(profile, header)
	if start < 0 {
		t.Fatalf("profile missing block %q", header)
	}
	rest := profile[start+len(header):]
	end := strings.Index(rest, ")\n")
	if end < 0 {
		t.Fatalf("unterminated block %q", header)
	}
	return rest[:end]
}

// TestSeatbeltExecEmptyBlockedPathsHasNoExecInDeny: with no blocked paths the whole
// blocked-deny block is omitted, so process-exec* must not appear in a deny there —
// but the deny-by-default + re-allow exec pair is still emitted unconditionally.
func TestSeatbeltExecAlwaysDeniedByDefault(t *testing.T) {
	spec := sandbox.SandboxSpec{
		WorkDir:      "/Users/u/proj",
		BlockedPaths: nil,
		BlockedFiles: nil,
		SetEnv:       map[string]string{},
		Tokens:       macTestTokens(),
	}
	profile, err := macBackend().profile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, "(deny process-exec*)") || !strings.Contains(profile, "(allow process-exec*\n") {
		t.Error("exec deny-by-default + re-allow must be emitted even with no blocked paths")
	}
	if strings.Contains(profile, "(deny file-read* file-write* process-exec*") {
		t.Error("no blocked paths → no blocked-deny block at all")
	}
}

// TestSeatbeltBlockedLeafMetadataAllowed pins the fix for the hook self-deadlock:
// the blocked-root leaf must get file-read-metadata back (so the pre-tool-use
// hook can lstat/canonicalize it inside this sandbox) while its contents stay
// denied. The metadata allow must be a literal (not a subpath, which would leak
// the names of files inside) and must come after the deny so last-match-wins.
func TestSeatbeltBlockedLeafMetadataAllowed(t *testing.T) {
	profile, err := macBackend().profile(withTok(fixedMacSpec(), macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}
	denyIdx := strings.Index(profile, `(deny file-read* file-write*`)
	metaAllow := "(allow file-read-metadata\n  (literal \"/Users/u/.ssh\")"
	metaIdx := strings.Index(profile, metaAllow)
	if metaIdx < 0 {
		t.Fatalf("blocked leaf must regain file-read-metadata as a literal; profile:\n%s", profile)
	}
	if metaIdx < denyIdx {
		t.Error("blocked-leaf metadata allow must come AFTER the blocked-path deny (last-match-wins)")
	}
	// Contents must not be readable: no subpath metadata, no read* re-allow on the leaf.
	if strings.Contains(profile, `(allow file-read-metadata`+"\n"+`  (subpath "/Users/u/.ssh")`) {
		t.Error("metadata on the blocked leaf must be literal-scoped, not a subpath (would leak filenames)")
	}
}

func TestSeatbeltVarDeniedByAbsence(t *testing.T) {
	// The broad /private/var content grant is removed, so /var/folders (other
	// processes' temp+cache) and the rest of /var content are denied by absence — no
	// deny rule, no WriteString. Only a single narrow leaf (/private/var/select, the
	// shell selector /bin/sh reads) is granted. claude's temp is the /tmp/corral-* dir.
	read, write, _ := compileMacOSBaseline(sandbox.BaselineRules(), macTestTokens(), noResolve{})
	for _, items := range [][]sbItem{read, write} {
		for _, it := range items {
			if it.val == "/private/var" || strings.HasPrefix(it.val, "/private/var/folders") {
				t.Errorf("/var content must not be granted (denied by absence); got %q", it.val)
			}
		}
	}
	profile, err := macBackend().profile(withTok(sandbox.SandboxSpec{SetEnv: map[string]string{}}, macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, "var/folders") {
		t.Error("profile must not mention /var/folders (denied by absence, not an explicit rule)")
	}
	// The narrow shell-selector leaf is granted (so /bin/sh doesn't error on /var/select/sh).
	if !strings.Contains(profile, `(subpath "/private/var/select")`) {
		t.Error("/private/var/select must be granted (the shell selector leaf)")
	}
}

func TestSeatbeltSessionTempIsolatedUnderTmp(t *testing.T) {
	profile, err := macBackend().profile(withTok(fixedMacSpec(), macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}
	// The session dir under /private/tmp is read+write (from the $SESSION_TMPDIR rule)...
	if !strings.Contains(profile, `(subpath "/private/tmp/corral-501-abc")`) {
		t.Error("the session temp dir must be granted under /private/tmp")
	}
	// ...its ancestors get metadata so traversal into it resolves under deny-by-default...
	for _, anc := range []string{`(literal "/private/tmp")`, `(literal "/private")`} {
		if !strings.Contains(profile, anc) {
			t.Errorf("metadata ancestor %s missing (traversal into the session dir)", anc)
		}
	}
	// ...and the rest of /private/tmp is not broadly readable (no subpath for the whole
	// tree — only the session dir), so other /tmp files stay hidden by deny-by-default.
	if strings.Contains(profile, `(subpath "/private/tmp")`) {
		t.Error("/private/tmp must not be a broad read subpath — only the session dir")
	}
}

func TestSeatbeltProfileNetOpenHasNoNetworkDeny(t *testing.T) {
	profile, err := macBackend().profile(withTok(fixedMacSpec(), macTestTokens())) // NetOpen
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, "(deny network*)") {
		t.Error("NetOpen must not deny the network (0.1 ships full network)")
	}
}

// TestMacOSConformance: every macOS rule yields exactly one read directive, and every
// shared (arch-less) concrete rule appears in the macOS compile as its
// /private-normalized path. The Linux half of this cross-platform invariant — that the
// same shared rule appears in the bwrap compile — is the bwrap package's
// TestLinuxConformance.
func TestMacOSConformance(t *testing.T) {
	tok := map[string]string{
		"HOME": "/home/u", "AGENT_CONFIG_DIR": "/home/u/.claude", "XDG_RUNTIME_DIR": "/run/user/1000",
		"SESSION_TMPDIR": "/var/folders/zz/T", "AGENT_BIN_DIR": "/opt/claude/bin",
	}
	mread, _, _ := compileMacOSBaseline(sandbox.BaselineRules(), tok, noResolve{})

	var macRuleCount int
	for _, r := range sandbox.BaselineRules() {
		if sandbox.ArchMatch(r, "macos") {
			macRuleCount++
		}
	}
	if len(mread) != macRuleCount {
		t.Errorf("conformance: %d macOS rules but %d read directives", macRuleCount, len(mread))
	}

	macVals := map[string]bool{}
	for _, it := range mread {
		macVals[it.val] = true
	}
	for _, r := range sandbox.BaselineRules() {
		if len(r.Archs) != 0 || r.Regex {
			continue // shared, concrete rules only
		}
		l, _ := sandbox.ExpandPath(r.Path, tok)
		if m := normalizeMacPath(l); !macVals[m] {
			t.Errorf("shared rule %q missing from macOS compile (%s)", r.Path, m)
		}
	}
}

func TestNoSecretPathsInMacOSCompile(t *testing.T) {
	read, write, _ := compileMacOSBaseline(sandbox.BaselineRules(), macTestTokens(), noResolve{})
	for _, items := range [][]sbItem{read, write} {
		for _, it := range items {
			low := strings.ToLower(it.val)
			for _, secret := range []string{".ssh", ".gnupg", ".aws"} {
				if strings.Contains(low, secret) {
					t.Errorf("macOS compile must not expose a secret dir; got %q", it.val)
				}
			}
		}
	}
}

// ReadOnlyTargets is the Seatbelt analogue of the bwrap read-only mount set, backing
// the paths.rw-shadow warning on macOS. /usr is a stable read-only system root;
// $AGENT_CONFIG_DIR is writeable, so it must not appear; secret dirs never appear.
func TestSeatbeltReadOnlyTargets(t *testing.T) {
	home := "/Users/u"
	claudeDir := home + "/.claude"
	spec := sandbox.SandboxSpec{Tokens: map[string]string{"HOME": home, "AGENT_CONFIG_DIR": claudeDir}}
	ro := macBackend().ReadOnlyTargets(spec)
	if !contains(ro, "/usr") {
		t.Errorf("macOS read-only targets should include /usr: %v", ro)
	}
	if contains(ro, claudeDir) {
		t.Errorf("writeable $AGENT_CONFIG_DIR %q must not appear among read-only targets: %v", claudeDir, ro)
	}
	for _, secret := range []string{home + "/.ssh", home + "/.gnupg", home + "/.aws"} {
		if contains(ro, secret) {
			t.Errorf("secret dir %q must not be a read-only baseline target: %v", secret, ro)
		}
	}
}

// Prepare creates the isolated per-session temp dir, points the spec's temp env vars
// + its $SESSION_TMPDIR token at it, asks the launcher to chdir to WorkDir, and its
// cleanup removes the dir. (This runs wherever MkdirTemp("/tmp", …) works,
// which is what makes `--dry-run -backend seatbelt` faithful cross-platform.)
func TestSeatbeltPrepare(t *testing.T) {
	spec := sandbox.SandboxSpec{
		WorkDir:        "/Users/u/proj",
		SetEnv:         map[string]string{},
		Tokens:         map[string]string{"HOME": "/Users/u"},
		TempEnvAliases: []string{"CLAUDE_CODE_TMPDIR"}, // agent-supplied alias (claude); the backend repoints it too
	}
	prep, err := New("", Config{}).Prepare(&spec, io.Discard)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(prep.Cleanup)
	if prep.Chdir != "/Users/u/proj" {
		t.Errorf("seatbelt must ask the launcher to chdir to WorkDir; got %q", prep.Chdir)
	}
	d := spec.Tokens["SESSION_TMPDIR"]
	if d == "" {
		t.Skip("session temp dir could not be created under /tmp (the documented fail-safe path)")
	}
	if fi, err := os.Stat(d); err != nil || !fi.IsDir() {
		t.Fatalf("session temp dir %q must exist as a dir: %v", d, err)
	}
	for _, k := range []string{"TMPDIR", "TMP", "TEMPDIR", "CLAUDE_CODE_TMPDIR"} {
		if spec.SetEnv[k] != d {
			t.Errorf("Prepare must point %s at the session temp dir; got %q want %q", k, spec.SetEnv[k], d)
		}
	}
	// $TMPPREFIX (zsh's heredoc temp prefix) must point inside the session dir, not
	// at the bare dir — zsh appends random chars to it to form the temp file name.
	if want := d + "/zsh"; spec.SetEnv["TMPPREFIX"] != want {
		t.Errorf("Prepare must point TMPPREFIX inside the session temp dir; got %q want %q", spec.SetEnv["TMPPREFIX"], want)
	}
	prep.Cleanup()
	if _, err := os.Stat(d); !os.IsNotExist(err) {
		t.Errorf("cleanup must remove the session temp dir (stat err=%v)", err)
	}
}

// fixedMacSpec is a host-independent spec for golden-testing the Seatbelt profile.
func fixedMacSpec() sandbox.SandboxSpec {
	return sandbox.SandboxSpec{
		WorkDir: "/Users/u/proj",
		Mounts: []sandbox.Mount{
			{Src: "/Users/u/proj"},                    // project, read-write
			{Src: "/Users/u/work/ro", ReadOnly: true}, // config paths.ro under $HOME
			{Src: "/var/run/docker.sock"},             // provider socket -> /private-normalized
		},
		BlockedPaths: []string{"/Users/u/.ssh", "/Users/u/.gnupg", "/Users/u/.aws"},
		BlockedFiles: []string{"/Users/u/.netrc", "/Users/u/proj/.env"}, // config block.files
		SetEnv:       map[string]string{"HOME": "/Users/u", "PATH": "/usr/bin:/bin", "TERM": "xterm-256color"},
		Net:          sandbox.NetOpen,
	}
}

// TestCompileMacOSBaselineGolden pins the compiled macOS baseline (read/write
// directives) against testdata — the security-critical law→SBPL mapping.
func TestCompileMacOSBaselineGolden(t *testing.T) {
	read, write, _ := compileMacOSBaseline(sandbox.BaselineRules(), macTestTokens(), noResolve{})
	var b strings.Builder
	b.WriteString("# read\n")
	for _, it := range read {
		fmt.Fprintf(&b, "%s\n", it.sbpl())
	}
	b.WriteString("# write\n")
	for _, it := range write {
		fmt.Fprintf(&b, "%s\n", it.sbpl())
	}
	checkGolden(t, filepath.Join("testdata", "baseline_macos.golden"), b.String())
}

// TestSeatbeltProfileGolden pins the full generated SBPL profile for a fixed spec. macBackend uses a
// zero-value Config, so this pins the open (opt-out) mach posture.
func TestSeatbeltProfileGolden(t *testing.T) {
	profile, err := macBackend().profile(withTok(fixedMacSpec(), macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "seatbelt_profile.golden"), profile)
}

// TestSeatbeltProfileStrictGolden pins the strict mach posture — corral's macOS default, so the
// SBPL every real session runs. It captures the full emitted allowlist, so any edit to
// mach-allow.json (or the user-allow emission) surfaces as a reviewable golden diff. The two user
// allow entries exercise the exact-name and trailing-"*" prefix compile paths.
func TestSeatbeltProfileStrictGolden(t *testing.T) {
	b := Backend{Path: "sandbox-exec", resolve: noResolve{}, cfg: Config{Mach: Mach{
		Lookup: "strict",
		Allow:  []string{"com.example.custom", "com.example.family.*"},
	}}}
	profile, err := b.profile(withTok(fixedMacSpec(), macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "seatbelt_profile_strict.golden"), profile)
}

// checkGolden compares got against the golden file, regenerating it under -update.
func checkGolden(t *testing.T, path, got string) {
	t.Helper()
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run `go test ./internal/sandbox/seatbelt -update`): %v", path, err)
	}
	if got != string(want) {
		t.Errorf("mismatch with %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

package policy

import (
	"fmt"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// BashRule parses a Bash tool call with a real shell parser (not a regex) and denies dangerous
// constructs a regex gate misses: two-step pipe-to-shell, split/symbolic world-writable chmod,
// and shell redirections into secret files. A command that cannot be parsed is denied (fail-closed).
type BashRule struct {
	ConfigDir string // canonical effective agent config dir; shell writes/deletes under it are blocked
	// Footprint is the active agent's static enforcement footprint, anchored under ConfigDir.
	// AllFootprints is every registered agent's footprint, scanned by config-dir path segment.
	Footprint     AgentFootprint
	AllFootprints []AgentFootprint
	// HookPaths are canonical absolute paths of non-corral hook scripts; nil falls back to
	// the static ConfigDir/hooks assumption.
	HookPaths []string
	// ExtraProtectedPaths are additional canonical runtime artifacts whose write/delete is
	// blocked, each mapped to a reason. Nil when none.
	ExtraProtectedPaths map[string]string
	// AuditLogBase is the canonical audit-log path; the live log and rotation backups are
	// prefix-protected from shell delete/truncate. Empty when unknown.
	AuditLogBase string
}

func (r *BashRule) Name() string { return "bash" }

func (r *BashRule) Evaluate(ev *HookEvent) (Decision, bool, error) {
	if ev.isMCP() {
		// MCP tools have no shell-command contract; skip them to avoid false-blocking.
		return Decision{}, false, nil
	}
	cmd, ok, err := ev.BashCommand()
	if err != nil {
		return Decision{}, false, err
	}
	if !ok {
		return Decision{}, false, nil
	}
	pb, perr := parseBash(cmd)
	if perr != nil {
		return Decision{
			Action: Deny,
			Rule:   r.Name(),
			Reason: fmt.Sprintf("could not parse the shell command, so it cannot be verified safe: %v", perr),
		}, true, nil
	}
	sp := selfProtect{configDir: r.ConfigDir, footprint: r.Footprint, allFootprints: r.AllFootprints, hookPaths: r.HookPaths, extraPaths: r.ExtraProtectedPaths, auditLogBase: r.AuditLogBase}
	if d, hit := pb.check(r.Name(), sp, ev.Cwd); hit {
		return d, true, nil
	}
	return Decision{}, false, nil
}

// shellInterpreters names commands that execute code from their input. Gated only for pipe
// destinations and process-substitution bodies, never plain commands, so `eval "$(ssh-agent -s)"`,
// `source ~/.bashrc`, and `exec bash` stay allowed. Out of scope: `eval "$(curl …)"`
// (command-substitution-fed), uncatchable without flagging legitimate `eval "$(tool init)"`.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "dash": true, "zsh": true,
	"ksh": true, "csh": true, "tcsh": true, "fish": true,
	"eval": true, "source": true, ".": true, "exec": true,
}

var fileReaders = map[string]bool{
	"cat": true, "less": true, "more": true, "head": true, "tail": true,
	"source": true, ".": true, "xxd": true, "od": true, "strings": true,
	"base64": true, "nl": true, "tac": true,
}

var netTools = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true, "netcat": true,
	"telnet": true, "scp": true, "ftp": true,
}

var credKeywords = []string{"API_KEY", "APIKEY", "TOKEN", "PASSWORD", "PASSWD", "SECRET", "CREDENTIAL", "PRIVATE_KEY"}

type parsedBash struct {
	cmds           []simpleCommand
	pipeDests      []simpleCommand
	redirects      []redirect
	shellProcSubst bool
}

type simpleCommand struct {
	name  string
	words []argWord
}

func (c simpleCommand) args() []argWord {
	if len(c.words) <= 1 {
		return nil
	}
	return c.words[1:]
}

// argWord is a best-effort rendering of a shell word: literal text with parameter expansions
// rendered back to `$NAME` form so they remain matchable.
type argWord struct {
	text         string
	hasExpansion bool
}

type redirect struct {
	write    bool
	target   string
	expanded bool
}

func parseBash(cmd string) (*parsedBash, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil, err
	}
	pb := &parsedBash{}
	dest := map[*syntax.Stmt]bool{}

	syntax.Walk(f, func(n syntax.Node) bool {
		switch x := n.(type) {
		case *syntax.CallExpr:
			sc := callToSimple(x)
			pb.cmds = append(pb.cmds, sc)
			if shellInterpreters[sc.name] && callHasProcSubst(x) {
				pb.shellProcSubst = true
			}
		case *syntax.ProcSubst:
			for _, st := range x.Stmts {
				if ce, ok := st.Cmd.(*syntax.CallExpr); ok && shellInterpreters[callToSimple(ce).name] {
					pb.shellProcSubst = true
				}
			}
		case *syntax.Redirect:
			rw := wordText(x.Word)
			pb.redirects = append(pb.redirects, redirect{
				write:    isWriteRedir(x.Op),
				target:   rw.text,
				expanded: rw.hasExpansion,
			})
		case *syntax.BinaryCmd:
			if x.Op == syntax.Pipe || x.Op == syntax.PipeAll {
				stmts := flattenPipe(x)
				for _, st := range stmts[1:] {
					dest[st] = true
				}
			}
		}
		return true
	})

	for st := range dest {
		if ce, ok := st.Cmd.(*syntax.CallExpr); ok {
			pb.pipeDests = append(pb.pipeDests, callToSimple(ce))
		}
	}
	return pb, nil
}

func flattenPipe(b *syntax.BinaryCmd) []*syntax.Stmt {
	var out []*syntax.Stmt
	var rec func(s *syntax.Stmt)
	rec = func(s *syntax.Stmt) {
		if bc, ok := s.Cmd.(*syntax.BinaryCmd); ok && (bc.Op == syntax.Pipe || bc.Op == syntax.PipeAll) {
			rec(bc.X)
			rec(bc.Y)
			return
		}
		out = append(out, s)
	}
	rec(b.X)
	rec(b.Y)
	return out
}

func callToSimple(ce *syntax.CallExpr) simpleCommand {
	sc := simpleCommand{}
	for i, w := range ce.Args {
		aw := wordText(w)
		sc.words = append(sc.words, aw)
		if i == 0 {
			sc.name = commandBase(aw)
		}
	}
	return sc
}

// commandBase resolves a command word to its base name (/usr/bin/rm matches "rm"). A word with
// an expansion in the command position is unresolvable → "".
func commandBase(w argWord) string {
	if w.hasExpansion || w.text == "" {
		return ""
	}
	return filepath.Base(w.text)
}

// wordText renders a shell word to matchable text, recording whether it contained an expansion.
// Parameter expansions render as `$NAME`, command substitutions as `$(...)`.
func wordText(w *syntax.Word) argWord {
	if w == nil {
		return argWord{}
	}
	var b strings.Builder
	exp := false
	var parts func(ps []syntax.WordPart)
	parts = func(ps []syntax.WordPart) {
		for _, part := range ps {
			switch p := part.(type) {
			case *syntax.Lit:
				b.WriteString(p.Value)
			case *syntax.SglQuoted:
				b.WriteString(p.Value)
			case *syntax.DblQuoted:
				parts(p.Parts)
			case *syntax.ParamExp:
				exp = true
				if p.Param != nil {
					b.WriteString("$" + p.Param.Value)
				}
			case *syntax.CmdSubst:
				exp = true
				b.WriteString("$(...)")
			default:
				exp = true
			}
		}
	}
	parts(w.Parts)
	return argWord{text: b.String(), hasExpansion: exp}
}

func isWriteRedir(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll:
		return true
	}
	return false
}

func (pb *parsedBash) check(ruleName string, sp selfProtect, cwd string) (Decision, bool) {
	deny := func(reason string) (Decision, bool) {
		return Decision{Action: Deny, Rule: ruleName, Reason: reason}, true
	}

	for _, sc := range pb.pipeDests {
		if shellInterpreters[sc.name] {
			return deny(fmt.Sprintf("piping into %q executes arbitrary downloaded code and is blocked", sc.name))
		}
	}
	if pb.shellProcSubst {
		return deny("a shell interpreter driven by process substitution can execute dynamic or downloaded code and is blocked")
	}

	for _, sc := range pb.cmds {
		for _, a := range sc.args() {
			switch a.text {
			case "--dangerously-skip-permissions":
				return deny("`--dangerously-skip-permissions` disables Claude Code's own safety and is blocked")
			case "--no-verify":
				return deny("`--no-verify` bypasses commit/push hooks and is blocked")
			}
		}

		switch sc.name {
		case "":
			// Command name hidden behind a shell expansion: block only when an argument is a
			// secret path or corral's own config; a benign expanded command is unaffected.
			if reason, _, hit := firstSensitiveArg(sc.args(), cwd, sp, true); hit {
				return deny(fmt.Sprintf("a command whose name is hidden by a shell expansion targets %s and cannot be verified safe, so it is blocked", reason))
			}
		case "rm":
			if reason, hit := checkRM(sc, sp, cwd); hit {
				return deny(reason)
			}
		case "ln":
			if reason, hit := checkLn(sc, sp, cwd); hit {
				return deny(reason)
			}
		case "chmod":
			if reason, hit := checkChmod(sc); hit {
				return deny(reason)
			}
		case "shred", "truncate", "wipe":
			if reason, _, hit := firstSensitiveArg(sc.args(), cwd, sp, true); hit {
				return deny(fmt.Sprintf("%s of %s is blocked", sc.name, reason))
			}
		case "find":
			if reason, hit := checkFind(sc, sp, cwd); hit {
				return deny(reason)
			}
		}

		if netTools[sc.name] {
			if kw, hit := credExfil(sc); hit {
				return deny(fmt.Sprintf("network command %q with a credential-looking argument (%s) is blocked as possible exfiltration", sc.name, kw))
			}
		}

		if fileReaders[sc.name] {
			if reason, _, hit := firstSensitiveArg(sc.args(), cwd, sp, false); hit {
				return deny(fmt.Sprintf("reading %s via `%s` bypasses the Read gate and is blocked", reason, sc.name))
			}
		}
	}

	for _, rd := range pb.redirects {
		if !rd.write {
			continue
		}
		if reason, self, hit := matchSensitive(rd.target, rd.expanded, cwd, sp, true); hit {
			if self {
				return deny(fmt.Sprintf("redirecting output into %s would disable corral and is blocked", reason))
			}
			return deny(fmt.Sprintf("redirecting output into %s is blocked", reason))
		}
	}

	return Decision{}, false
}

// checkRM denies a recursive rm targeting a catastrophic or secret path.
func checkRM(sc simpleCommand, sp selfProtect, cwd string) (string, bool) {
	recursive := false
	var targets []argWord
	for _, a := range sc.args() {
		t := a.text
		switch {
		case t == "--recursive" || t == "-r" || t == "-R":
			recursive = true
		case strings.HasPrefix(t, "-") && !strings.HasPrefix(t, "--"):
			if strings.ContainsAny(t[1:], "rR") {
				recursive = true
			}
		case strings.HasPrefix(t, "--"):
			// other long flag
		default:
			targets = append(targets, a)
		}
	}
	if !recursive {
		return "", false
	}
	for _, a := range targets {
		clean := strings.TrimRight(a.text, "/")
		switch clean {
		case "", "/", "~", "$HOME", "/*":
			return fmt.Sprintf("recursive delete of %q", a.text), true
		}
		if reason, _, hit := matchSensitive(a.text, a.hasExpansion, cwd, sp, true); hit {
			return fmt.Sprintf("recursive delete of %s", reason), true
		}
	}
	return "", false
}

// checkFind denies `find … -delete` targeting a secret/credential path or corral's own config.
func checkFind(sc simpleCommand, sp selfProtect, cwd string) (string, bool) {
	deletes := false
	for _, a := range sc.args() {
		if a.text == "-delete" {
			deletes = true
			break
		}
	}
	if !deletes {
		return "", false
	}
	if reason, _, hit := firstSensitiveArg(sc.args(), cwd, sp, true); hit {
		return fmt.Sprintf("find -delete targeting %s is blocked", reason), true
	}
	return "", false
}

// checkLn denies creating a link whose source or link name is a secret/credential path or
// corral's own config: `ln -s ~/.ssh /tmp/bridge` builds a symlink bridge, `ln ~/.aws/credentials x`
// hard-links secret content. Either endpoint being sensitive is enough.
func checkLn(sc simpleCommand, sp selfProtect, cwd string) (string, bool) {
	for _, a := range sc.args() {
		if strings.HasPrefix(a.text, "-") {
			continue
		}
		if reason, self, hit := matchSensitive(a.text, a.hasExpansion, cwd, sp, true); hit {
			if self {
				return fmt.Sprintf("creating a link to %s would disable corral and is blocked", reason), true
			}
			return fmt.Sprintf("creating a link to %s is blocked", reason), true
		}
	}
	return "", false
}

// pathCandidates returns the raw shell token and, for literal paths, its canonical form. The raw
// token is always retained, so canonicalization can only add a deny. Expansions and unresolvable
// paths remain raw because this Bash check is a secondary layer.
func pathCandidates(text string, expanded bool, cwd string) []string {
	if expanded || text == "" {
		return []string{text}
	}
	canon, err := Canonicalize(text, cwd)
	if err != nil || canon == text {
		return []string{text}
	}
	return []string{text, canon}
}

// matchSensitive sweeps a shell token's path candidates (raw + symlink-resolved) and reports the
// first that is a secret/credential path (classifySensitive) or, when checkSelf is true, corral's
// own protected config (selfConfigMatch). The self return distinguishes the two. classifySensitive
// is tested before selfConfigMatch; the two never match the same canonical path, so the order does
// not change which message a token produces.
func matchSensitive(text string, expanded bool, cwd string, sp selfProtect, checkSelf bool) (reason string, self bool, hit bool) {
	for _, c := range pathCandidates(text, expanded, cwd) {
		if r, h := classifySensitive(c); h {
			return r, false, true
		}
		if checkSelf {
			if r, ok := selfConfigMatch(c, sp); ok {
				return r, true, true
			}
		}
	}
	return "", false, false
}

func firstSensitiveArg(args []argWord, cwd string, sp selfProtect, checkSelf bool) (reason string, self bool, hit bool) {
	for _, a := range args {
		if r, s, h := matchSensitive(a.text, a.hasExpansion, cwd, sp, checkSelf); h {
			return r, s, h
		}
	}
	return "", false, false
}

func callHasProcSubst(ce *syntax.CallExpr) bool {
	for _, w := range ce.Args {
		for _, part := range w.Parts {
			if _, ok := part.(*syntax.ProcSubst); ok {
				return true
			}
		}
	}
	return false
}

// checkChmod denies a chmod that grants world (other) write — octal or symbolic.
func checkChmod(sc simpleCommand) (string, bool) {
	for _, a := range sc.args() {
		t := a.text
		if strings.HasPrefix(t, "-") {
			continue
		}
		if grantsWorldWrite(t) {
			return fmt.Sprintf("chmod mode %q grants world-writable access", t), true
		}
		break
	}
	return "", false
}

// grantsWorldWrite reports whether a chmod mode (octal or symbolic) gives the "other" class
// write permission.
func grantsWorldWrite(mode string) bool {
	if isOctal(mode) {
		last := mode[len(mode)-1] - '0'
		return last&2 != 0
	}
	for _, clause := range strings.Split(mode, ",") {
		who, perms, ok := splitSymbolic(clause)
		if !ok {
			continue
		}
		// Only explicit 'o' (other) or 'a' (all) targets the world. An empty who (e.g. "+w")
		// is umask-masked and usually does not grant other-write, so flagging it would over-block.
		targetsOther := strings.ContainsAny(who, "oa")
		if targetsOther && strings.Contains(perms, "w") {
			return true
		}
	}
	return false
}

// isOctal recognizes 1–4 octal digits. A 1- or 2-digit mode still sets the "other" bits
// (e.g. `chmod 7` = world-rwx).
func isOctal(s string) bool {
	if len(s) == 0 || len(s) > 4 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '7' {
			return false
		}
	}
	return true
}

// splitSymbolic splits a symbolic chmod clause into (who, perms). A "-" (remove) clause never
// grants, so it reports ok=false.
func splitSymbolic(clause string) (who, perms string, ok bool) {
	i := strings.IndexAny(clause, "+-=")
	if i < 0 {
		return "", "", false
	}
	if clause[i] == '-' {
		return "", "", false
	}
	return clause[:i], clause[i+1:], true
}

// credExfil reports an inline credential assignment (e.g. `API_KEY=…`) on a network command
// line. It does not flag a bare keyword substring to keep false positives low.
func credExfil(sc simpleCommand) (string, bool) {
	for _, a := range sc.args() {
		upper := strings.ToUpper(a.text)
		for _, kw := range credKeywords {
			if strings.Contains(upper, kw+"=") {
				return kw, true
			}
		}
	}
	return "", false
}

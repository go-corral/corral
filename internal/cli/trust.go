package cli

import (
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/providers/hooks"
	"github.com/go-corral/corral/internal/trust"
)

// trustEntries maps the config layers the trust gate covers — the repo-discovered
// project and local files — onto trust.Entry. Global config (user-owned, outside the
// repo) and non-file layers (defaults, profile) are implicitly trusted and excluded. The
// trust package must not import config, so this translation lives here, the composition
// root.
func trustEntries(sources []config.Source) []trust.Entry {
	var out []trust.Entry
	for _, s := range sources {
		if (s.Kind == "project" || s.Kind == "local") && s.Path != "" {
			out = append(out, trust.Entry{Path: s.Path, SHA256: s.SHA256})
		}
	}
	return out
}

// hookExecs is the trust gate's view of the session-hook executables: hashed entries for
// every readable file an enabled hook names, a resolved-path → config-path attribution map
// covering every enabled hook (readable or not), and the read failures for the read-only
// views (validate) to explain. The zero value means "no hooks to gate" — sync passes it,
// because sync never runs a hook (the executables are gated on `run`, the command that
// executes them).
type hookExecs struct {
	entries    []trust.Entry
	attr       map[string]string
	unreadable map[string]string
}

// collectHookExecs resolves and hashes every enabled session hook's executable for the trust
// gate. workdir anchors relative paths via hooks.ResolveExec — the exact rule the provider execs
// by, so the gate hashes the file that will run. The config layer does not matter: global config
// is implicitly trusted as config, but the file it points at is host-run code and is pinned like
// any other — the trust unit is the executable. An unreadable file yields no entry and never
// fails the gate (the runtime already fails closed for a non-optional preStart, warns for the
// rest, and the postEnd fire-time re-verify refuses a file unreadable at launch). Entries are
// deduped by resolved path; attribution joins every config path naming the same file.
func collectHookExecs(cfg *config.Config, workdir string) hookExecs {
	res := hookExecs{attr: map[string]string{}, unreadable: map[string]string{}}
	for _, ev := range []struct {
		name string
		m    map[string]hooks.Hook
	}{
		{"preStart", cfg.Providers.Hooks.PreStart},
		{"postEnd", cfg.Providers.Hooks.PostEnd},
	} {
		keys := make([]string, 0, len(ev.m))
		for k := range ev.m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, key := range keys {
			hk := ev.m[key]
			if !hk.IsEnabled() {
				continue
			}
			path := hooks.ResolveExec(hk.Exec, workdir)
			label := "providers.hooks." + ev.name + "." + key
			if prev, seen := res.attr[path]; seen {
				res.attr[path] = prev + ", " + label
				continue
			}
			res.attr[path] = label
			sum, err := hooks.HashFile(path)
			if err != nil {
				res.unreadable[path] = err.Error()
				continue
			}
			res.entries = append(res.entries, trust.Entry{Path: path, SHA256: sum})
		}
	}
	return res
}

// sortedAttrPaths returns the attributed executable paths in stable order for rendering.
func (h hookExecs) sortedAttrPaths() []string {
	paths := make([]string, 0, len(h.attr))
	for p := range h.attr {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	return paths
}

// trustStore opens the approval store at the real host home — never `corral run --home`
// (that flag names the sandbox home, an in-sandbox concern), so the store stays where the
// operator's approvals live regardless of the launch's sandbox-home override.
func trustStore() (*trust.Store, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home for the config-trust store: %w", err)
	}
	return trust.NewStore(trust.DefaultDir(home)), nil
}

// The two fail-closed explanations. Kept as constants so the run/sync paths and the tests
// share the exact wording. Both cover the gate's whole surface — repo config and
// session-hook executables ride the same approval.
const (
	trustNonInteractiveMsg = "approving repo config or session-hook executables requires one interactive run " +
		"in a terminal — run `corral run`/`corral sync` there to review and approve them, after which " +
		"non-interactive runs proceed."
	trustYesRefusalMsg = "--yes means \"proceed past warnings\", not \"approve new repo-supplied code\" — " +
		"approve it once in an interactive terminal first."
	trustDeclinedMsg = "not approved — aborted."
)

// promptTrustApproval asks the operator to approve what writeTrustPending just listed — the
// header above already named what is pending, so the question stays uniform. It returns
// answered=false when no interactive answer is possible (stdin is not a terminal); otherwise
// answered=true with approved reflecting the y/N reply (default-no). It is a package var so
// tests can drive the interactive path without a real terminal.
var promptTrustApproval = func(in *os.File, out io.Writer, c report.Style) (answered, approved bool) {
	if !report.IsTerminal(in) {
		return false, false
	}
	return true, promptYesNo(in, out, fmt.Sprintf("%sApprove for future runs? [y/N]%s ", c.Bold, c.Reset))
}

// checkRepoConfigTrust enforces approve-once for repo-shipped config and session-hook
// executables before a side-effectful command consumes them. Returns true to proceed.
func checkRepoConfigTrust(sources []config.Source, execs hookExecs, yes bool, in *os.File, out io.Writer, c report.Style) bool {
	cfgEntries := trustEntries(sources)
	all := append(append([]trust.Entry{}, cfgEntries...), execs.entries...)
	if len(all) == 0 {
		return true // nothing to gate
	}
	store, err := trustStore()
	if err != nil {
		c.Message(out, report.Blocked, err.Error())
		return false
	}
	pending := store.Pending(all)
	if len(pending) == 0 {
		return true // everything already approved
	}

	// Split for rendering: config files first, then hook executables.
	var cfgPending, execPending []trust.Result
	for _, p := range pending {
		if _, ok := execs.attr[p.Path]; ok {
			execPending = append(execPending, p)
		} else {
			cfgPending = append(cfgPending, p)
		}
	}
	writeTrustPending(out, c, cfgPending, execPending, execs.attr)

	if yes {
		c.Message(out, report.Blocked, trustYesRefusalMsg)
		return false
	}
	answered, approved := promptTrustApproval(in, out, c)
	switch {
	case !answered:
		c.Message(out, report.Blocked, trustNonInteractiveMsg)
		return false
	case !approved:
		c.Message(out, report.Blocked, trustDeclinedMsg)
		return false
	}
	// Persist all covered entries (not just pending): re-approval is idempotent.
	if err := store.Approve(all); err != nil {
		c.Message(out, report.Blocked, fmt.Sprintf("could not record config approval: %v", err))
		return false
	}
	return true
}

// trustStates returns the approval state of each trust entry. Best-effort.
func trustStates(entries []trust.Entry) map[string]trust.State {
	if len(entries) == 0 {
		return nil
	}
	store, err := trustStore()
	if err != nil {
		return nil
	}
	out := make(map[string]trust.State, len(entries))
	for _, r := range store.Check(entries) {
		out[r.Path] = r.State
	}
	return out
}

// trustWarnings warns about each repo config layer and session-hook executable that is not
// approved or changed since approval, and about each hook executable corral cannot read.
func trustWarnings(cfg *config.Config, sources []config.Source) []health.Check {
	var out []health.Check
	states := trustStates(trustEntries(sources))
	for _, s := range sources {
		if st, ok := states[s.Path]; ok && st != trust.StateApproved {
			out = append(out, trustCheck(s.Kind, reportText(s.Path), st, "run or sync"))
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		return out
	}
	execs := collectHookExecs(cfg, wd)
	hookStates := trustStates(execs.entries)
	for _, p := range execs.sortedAttrPaths() {
		st, noted := hookStates[p]
		switch {
		case execs.unreadable[p] != "":
			out = append(out, health.Check{State: health.Warn, Label: "hook exec", Value: reportText(p),
				Reason: reportText(execs.attr[p]) + "; " + reportText(execs.unreadable[p]) + "; the launch fails or skips this hook"})
		case noted && st != trust.StateApproved:
			out = append(out, trustCheck("hook exec", reportText(p)+" ("+reportText(execs.attr[p])+")", st, "run"))
		}
	}
	return out
}

// trustCheck warns about a gated item that is not approved or changed since approval.
// gate names the commands that ask for approval.
func trustCheck(label, path string, state trust.State, gate string) health.Check {
	if state == trust.StateChanged {
		return health.Check{State: health.Warn, Label: label, Value: "changed since approval",
			Reason: path + "; corral asks again on the next " + gate}
	}
	return health.Check{State: health.Warn, Label: label, Value: "not approved",
		Reason: path + "; corral asks on the next " + gate}
}

// writeTrustDryRunNote annotates a --dry-run preview with the approval state. Silent when
// everything is already approved or the store cannot be opened.
func writeTrustDryRunNote(out io.Writer, c report.Style, sources []config.Source, execs hookExecs) {
	entries := append(trustEntries(sources), execs.entries...)
	if len(entries) == 0 {
		return
	}
	store, err := trustStore()
	if err != nil {
		return
	}
	pending := store.Pending(entries)
	if len(pending) == 0 {
		return
	}
	c.Message(out, report.Attention, "not yet approved — a real run would prompt to approve:")
	writePendingRows(out, c, pending, execs.attr)
}

// pendingState renders a trust.Result's state for the pending lists.
func pendingState(p trust.Result) string {
	if p.State == trust.StateChanged {
		return "changed"
	}
	return "new"
}

// writePendingRows lists pending entries, each hook executable with the config paths that
// name it.
func writePendingRows(out io.Writer, c report.Style, pending []trust.Result, attr map[string]string) {
	for _, p := range pending {
		c.Row(out, report.Row{Label: pendingState(p), Value: p.Path, Reason: attr[p.Path]})
	}
}

// writeTrustPending lists what the gate is stopping on.
func writeTrustPending(out io.Writer, c report.Style, cfgPending, execPending []trust.Result, attr map[string]string) {
	subjects := make([]string, 0, 2)
	if len(cfgPending) > 0 {
		subjects = append(subjects, "repo config")
	}
	if len(execPending) > 0 {
		s := "session-hook executables"
		if len(execPending) == 1 {
			s = "session-hook executable"
		}
		subjects = append(subjects, s)
	}
	c.Message(out, report.Attention, "unapproved "+strings.Join(subjects, " and ")+" — review, then approve:")
	writePendingRows(out, c, cfgPending, attr)
	writePendingRows(out, c, execPending, attr)
}

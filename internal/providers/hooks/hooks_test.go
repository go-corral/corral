package hooks

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
)

// recorder is a runner seam that captures each command it is handed (never exec'ing a real
// script). It simulates a hook's behavior keyed on the script's basename (argv[0] arrives
// workdir-resolved): stdout/stderr write what a preStart hook would print into the respective
// capture buffer, and failOn returns a nonzero-exit error. log captures corral's own
// attribution lines (which New would write to os.Stderr).
type recorder struct {
	cmds   []*exec.Cmd
	failOn map[string]error  // script basename → error to return
	stdout map[string]string // script basename → bytes to write to cmd.Stdout (the contribution capture)
	stderr map[string]string // script basename → bytes to write to cmd.Stderr (the human-channel capture)
	log    bytes.Buffer      // corral's attribution lines (headers, plain-default output blocks)
}

func (r *recorder) run(cmd *exec.Cmd) error {
	r.cmds = append(r.cmds, cmd)
	key := filepath.Base(cmd.Args[0])
	if s, ok := r.stdout[key]; ok && cmd.Stdout != nil {
		_, _ = io.WriteString(cmd.Stdout, s) // as if the hook printed to stdout
	}
	if s, ok := r.stderr[key]; ok && cmd.Stderr != nil {
		_, _ = io.WriteString(cmd.Stderr, s) // as if the hook printed to stderr
	}
	if err, ok := r.failOn[key]; ok {
		return err
	}
	return nil
}

// newWith builds a *hooks wired to the recorder seam (bypassing New's real cmd.Run) and
// routing corral's header lines into the recorder's log buffer instead of os.Stderr.
func newWith(cfg Config, rec *recorder) *hooks {
	return &hooks{cfg: cfg, agent: "claude", run: rec.run, log: &rec.log}
}

func TestNameAndAvailable(t *testing.T) {
	p := New(Config{}, "claude", nil)
	if p.Name() != "hooks" {
		t.Errorf("Name() = %q, want hooks", p.Name())
	}
	if !p.Available(context.Background()) {
		t.Error("Available() must be true (nothing to probe)")
	}
}

// Session hooks must never run on a dry run: Mint refuses with the standard ErrNoDryRun.
func TestMintRefusesDryRun(t *testing.T) {
	rec := &recorder{}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "./a.sh"}}}, rec)
	_, err := h.Mint(context.Background(), spec.Session{}, true)
	if err == nil {
		t.Fatal("Mint(dryRun=true) must return an error — a session hook must never run on a preview")
	}
	if !strings.Contains(err.Error(), "no dry-run mode") {
		t.Errorf("want ErrNoDryRun, got %v", err)
	}
	if len(rec.cmds) != 0 {
		t.Errorf("dry run must not execute any session hook, ran %d", len(rec.cmds))
	}
}

// preStart entries run in lexical key order (run-parts style), and disabled entries are
// skipped (reported, not run).
func TestMintPreStartLexicalOrderAndSkipsDisabled(t *testing.T) {
	rec := &recorder{}
	h := newWith(Config{PreStart: map[string]Hook{
		"30-c": {Exec: "c"},
		"10-a": {Exec: "a"},
		"20-b": {Exec: "b", Enabled: boolPtr(false)}, // disabled → skipped
	}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	var ran []string
	for _, cmd := range rec.cmds {
		ran = append(ran, cmd.Args[len(cmd.Args)-1])
	}
	if strings.Join(ran, ",") != "a,c" {
		t.Errorf("ran %v, want [a c] (lexical order, disabled 20-b skipped)", ran)
	}
	// Status is one compact summary row inventorying the run entries and the skipped one.
	if len(c.Status) != 1 || c.Status[0] != "preStart ran 10-a, 30-c · skipped 20-b (disabled)" {
		t.Errorf("Status = %q, want the compact per-event summary row", c.Status)
	}
}

// The command is the script exec'd directly — argv[0] is the workdir-resolved script path (no
// shell, no $PATH lookup), the configured args follow — with cwd = the session workdir and
// env = host env plus the CORRAL_* session vars. Session hooks are one-way: stdin is left
// unwired (os/exec then hands the child /dev/null, so reading it hits EOF instead of hanging
// on a prompt nobody sees), and for preStart both output streams are capture buffers — stdout
// the contribution channel, stderr the human channel surfaced after the hook exits.
func TestMintCommandWiring(t *testing.T) {
	t.Setenv("A_HOST_VAR", "host-value") // proves the host env is inherited
	rec := &recorder{}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "./scripts/hello.sh", Args: []string{"--fast", "two"}}}}, rec)
	sess := spec.Session{ID: "sess-1", WorkDir: "/work/dir"}
	if _, err := h.Mint(context.Background(), sess, false); err != nil {
		t.Fatal(err)
	}
	if len(rec.cmds) != 1 {
		t.Fatalf("want 1 command, got %d", len(rec.cmds))
	}
	cmd := rec.cmds[0]
	// argv: the resolved script, then the configured args verbatim.
	want := []string{"/work/dir/scripts/hello.sh", "--fast", "two"}
	if strings.Join(cmd.Args, " ") != strings.Join(want, " ") {
		t.Errorf("argv = %v, want %v", cmd.Args, want)
	}
	if cmd.Dir != "/work/dir" {
		t.Errorf("cwd = %q, want the session workdir", cmd.Dir)
	}
	// One-way: stdin unwired (→ /dev/null), stdout and stderr each a capture buffer.
	if cmd.Stdin != nil {
		t.Error("session hooks are one-way — stdin must be unwired (/dev/null), never os.Stdin")
	}
	if _, ok := cmd.Stdout.(*cappedBuffer); !ok {
		t.Errorf("preStart stdout must be the contribution capture buffer, got %T", cmd.Stdout)
	}
	if _, ok := cmd.Stderr.(*cappedBuffer); !ok {
		t.Errorf("preStart stderr must be the display capture buffer, got %T", cmd.Stderr)
	}
	// A hook that wrote nothing surfaces nothing — no header, no empty region.
	if rec.log.Len() != 0 {
		t.Errorf("a quiet hook must leave no attribution output, got %q", rec.log.String())
	}
	env := envMap(cmd.Env)
	if env["CORRAL_EVENT"] != "preStart" || env["CORRAL_AGENT"] != "claude" ||
		env["CORRAL_SESSION_ID"] != "sess-1" || env["CORRAL_WORKDIR"] != "/work/dir" {
		t.Errorf("CORRAL_* session env wrong: %v", filterCorral(cmd.Env))
	}
	if env["A_HOST_VAR"] != "host-value" {
		t.Error("the host environment must be inherited by the session hook")
	}
	// preStart carries no exit code.
	if _, ok := env["CORRAL_AGENT_EXIT"]; ok {
		t.Error("preStart must not set CORRAL_AGENT_EXIT")
	}
}

// A non-optional preStart failure aborts: Mint returns an error naming the entry, paired with a
// contribution that carries nothing but the postEnd closure — the abort is itself an "aborted
// launch where a preStart hook ran", so the session-end teardown must still fire (the engine
// honors only PostSession from a failed Mint).
func TestMintPreStartFatalFailureAbortsWithPairedTeardown(t *testing.T) {
	rec := &recorder{failOn: map[string]error{"boom": errors.New("nonzero exit")}}
	h := newWith(Config{
		PreStart: map[string]Hook{"10-a": {Exec: "boom"}},
		PostEnd:  map[string]Hook{"report": {Exec: "r"}},
	}, rec)
	c, err := h.Mint(context.Background(), spec.Session{}, false)
	if err == nil {
		t.Fatal("a non-optional preStart failure must return a Mint error (fail-closed abort)")
	}
	if !strings.Contains(err.Error(), "providers.hooks.preStart.10-a") {
		t.Errorf("error must attribute the entry, got %v", err)
	}
	if c == nil || c.PostSession == nil {
		t.Fatalf("the abort must still pair the postEnd teardown, got %+v", c)
	}
	// Nothing else may ride along: a failed Mint must not reach the spec.
	if c.Env != nil || c.Status != nil || c.AgentNotes != nil || c.Mounts != nil || c.Cleanup != nil {
		t.Errorf("the paired contribution must carry ONLY PostSession, got %+v", c)
	}
}

// With no postEnd entry there is nothing to pair, so a fail-closed abort returns no
// contribution at all.
func TestMintPreStartFatalFailureNoPostEndNoContribution(t *testing.T) {
	rec := &recorder{failOn: map[string]error{"boom": errors.New("nonzero exit")}}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "boom"}}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{}, false)
	if err == nil {
		t.Fatal("a non-optional preStart failure must return a Mint error")
	}
	if c != nil {
		t.Errorf("nothing to pair without a postEnd entry, got %+v", c)
	}
}

// An optional preStart failure warns and continues to the next entry.
func TestMintPreStartOptionalFailureContinues(t *testing.T) {
	rec := &recorder{failOn: map[string]error{"boom": errors.New("nonzero exit")}}
	h := newWith(Config{PreStart: map[string]Hook{
		"10-a": {Exec: "boom", Optional: true},
		"20-b": {Exec: "ok"},
	}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatalf("an optional failure must not abort: %v", err)
	}
	if len(rec.cmds) != 2 {
		t.Errorf("both entries must run despite the optional failure, ran %d", len(rec.cmds))
	}
	joined := strings.Join(c.Status, "\n")
	// The failure gets a key-attributed detail row; the ran list holds only 20-b.
	if !strings.Contains(joined, "10-a: failed but optional — continuing") {
		t.Errorf("Status must warn about the optional failure: %q", c.Status)
	}
	if !strings.Contains(joined, "preStart ran 20-b") || strings.Contains(joined, "ran 10-a") {
		t.Errorf("the failed entry must not appear in the ran list: %q", c.Status)
	}
}

// PostSession is registered iff at least one enabled postEnd entry exists.
func TestMintPostSessionRegistration(t *testing.T) {
	rec := &recorder{}
	// preStart-only → no PostSession.
	c, err := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "a"}}}, rec).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.PostSession != nil {
		t.Error("no PostSession without an enabled postEnd entry")
	}
	// Only a disabled postEnd → still no PostSession.
	c2, _ := newWith(Config{PostEnd: map[string]Hook{"report": {Exec: "r", Enabled: boolPtr(false)}}}, rec).Mint(context.Background(), spec.Session{}, false)
	if c2.PostSession != nil {
		t.Error("a disabled postEnd entry must not register a PostSession")
	}
	// An enabled postEnd → PostSession present.
	c3, _ := newWith(Config{PostEnd: map[string]Hook{"report": {Exec: "r"}}}, rec).Mint(context.Background(), spec.Session{}, false)
	if c3.PostSession == nil {
		t.Error("an enabled postEnd entry must register a PostSession")
	}
}

// touchFiles creates real hook files in a fresh temp workdir (the recorder never execs, so
// the mode is irrelevant) — the postEnd launch-time hashing needs bytes on disk to pin.
func touchFiles(t *testing.T, names ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("#!/bin/sh\n# "+n+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// PostSession runs enabled entries in lexical order, exports CORRAL_EVENT=postEnd and the
// decimal exit code, and runs all entries even when one fails — joining failures with per-key
// attribution (optional has no effect on postEnd).
func TestPostSessionRunsAllAndJoinsErrors(t *testing.T) {
	rec := &recorder{failOn: map[string]error{"b": errors.New("boom-b")}}
	h := newWith(Config{PostEnd: map[string]Hook{
		"10-a": {Exec: "a"},
		"20-b": {Exec: "b"}, // fails
		"30-c": {Exec: "c", Optional: true},
	}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{ID: "s", WorkDir: touchFiles(t, "a", "b", "c")}, false)
	if err != nil {
		t.Fatal(err)
	}
	perr := c.PostSession(context.Background(), spec.SessionExit{Started: true, Code: 7})
	if perr == nil {
		t.Fatal("PostSession must return the joined error when an entry fails")
	}
	if !strings.Contains(perr.Error(), "providers.hooks.postEnd.20-b") || !strings.Contains(perr.Error(), "boom-b") {
		t.Errorf("joined error must attribute the failing entry, got %v", perr)
	}
	// All three ran, in lexical order, despite 20-b failing.
	var ran []string
	for _, cmd := range rec.cmds {
		ran = append(ran, filepath.Base(cmd.Args[0]))
		env := envMap(cmd.Env)
		if env["CORRAL_EVENT"] != "postEnd" {
			t.Errorf("postEnd command missing CORRAL_EVENT=postEnd: %v", filterCorral(cmd.Env))
		}
		if env["CORRAL_AGENT_EXIT"] != "7" {
			t.Errorf("CORRAL_AGENT_EXIT = %q, want 7 (decimal exit code)", env["CORRAL_AGENT_EXIT"])
		}
	}
	if strings.Join(ran, ",") != "a,b,c" {
		t.Errorf("postEnd ran %v, want [a b c] (lexical order, all entries)", ran)
	}
}

// On an aborted launch (zero SessionExit) the exit code is reported as "aborted".
func TestPostSessionAbortedExit(t *testing.T) {
	rec := &recorder{}
	h := newWith(Config{PostEnd: map[string]Hook{"report": {Exec: "r"}}}, rec)
	c, _ := h.Mint(context.Background(), spec.Session{WorkDir: touchFiles(t, "r")}, false)
	if err := c.PostSession(context.Background(), spec.SessionExit{}); err != nil {
		t.Fatal(err)
	}
	if got := envMap(rec.cmds[0].Env)["CORRAL_AGENT_EXIT"]; got != "aborted" {
		t.Errorf("CORRAL_AGENT_EXIT on an aborted launch = %q, want \"aborted\"", got)
	}
}

// --- postEnd fire-time re-verify ---
//
// The launch-to-session-end window is the one window where a live in-sandbox agent can edit a
// workdir hook file, so postEnd re-hashes its executable at fire time against the hash taken
// at closure-build (Mint) time. A changed, vanished, or launch-unreadable file skips that
// entry with an attributed warning — the other entries still run.

func TestPostEndSkipsExecutableChangedDuringSession(t *testing.T) {
	rec := &recorder{}
	dir := touchFiles(t, "good", "tampered")
	h := newWith(Config{PostEnd: map[string]Hook{
		"10-good":     {Exec: "good"},
		"20-tampered": {Exec: "tampered"},
	}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{WorkDir: dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	// The "session": the agent rewrites one hook file in the writable workdir.
	if err := os.WriteFile(filepath.Join(dir, "tampered"), []byte("#!/bin/sh\nexfiltrate\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	perr := c.PostSession(context.Background(), spec.SessionExit{Started: true, Code: 0})
	if perr == nil || !strings.Contains(perr.Error(), "providers.hooks.postEnd.20-tampered: skipped") ||
		!strings.Contains(perr.Error(), "changed during the session") {
		t.Fatalf("the tampered entry must be skipped with attribution, got %v", perr)
	}
	if len(rec.cmds) != 1 || filepath.Base(rec.cmds[0].Args[0]) != "good" {
		t.Errorf("only the unchanged entry may run, ran %d command(s)", len(rec.cmds))
	}
}

func TestPostEndSkipsExecutableUnreadableAtLaunch(t *testing.T) {
	rec := &recorder{}
	dir := t.TempDir() // the hook file does not exist at launch
	h := newWith(Config{PostEnd: map[string]Hook{"report": {Exec: "appears-later"}}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{WorkDir: dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	// A file appearing during the session (agent-authored) must never run on the host.
	if err := os.WriteFile(filepath.Join(dir, "appears-later"), []byte("#!/bin/sh\nevil\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	perr := c.PostSession(context.Background(), spec.SessionExit{Started: true, Code: 0})
	if perr == nil || !strings.Contains(perr.Error(), "could not be read at launch") {
		t.Fatalf("a launch-unreadable executable must skip with the launch-read warning, got %v", perr)
	}
	if len(rec.cmds) != 0 {
		t.Error("the agent-authored file must not run")
	}
}

func TestPostEndSkipsExecutableVanished(t *testing.T) {
	rec := &recorder{}
	dir := touchFiles(t, "gone")
	h := newWith(Config{PostEnd: map[string]Hook{"report": {Exec: "gone"}}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{WorkDir: dir}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "gone")); err != nil {
		t.Fatal(err)
	}
	perr := c.PostSession(context.Background(), spec.SessionExit{Started: true, Code: 0})
	if perr == nil || !strings.Contains(perr.Error(), "no longer readable") {
		t.Fatalf("a vanished executable must skip with attribution, got %v", perr)
	}
	if len(rec.cmds) != 0 {
		t.Error("nothing may run when the executable vanished")
	}
}

// --- preStart stdout contribution channel ---

// Empty (or whitespace-only) stdout is the common case: the hook ran fine and contributes
// nothing — no env, no agent notes, no failure.
func TestPreStartEmptyStdoutNoContribution(t *testing.T) {
	rec := &recorder{stdout: map[string]string{"c": "   \n\t "}} // whitespace only
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "c"}}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Env != nil || c.AgentNotes != nil {
		t.Errorf("whitespace-only stdout must contribute nothing, got env=%v notes=%v", c.Env, c.AgentNotes)
	}
	if !strings.Contains(strings.Join(c.Status, "\n"), "preStart ran 10-a") {
		t.Errorf("the hook still ran successfully: %q", c.Status)
	}
}

// A full, valid contribution lands: env merges into Contribution.Env, agentNotes ride as
// authored, and status lines append prefixed with their authoring hook for attribution.
func TestPreStartValidContribution(t *testing.T) {
	rec := &recorder{stdout: map[string]string{
		"c": `{"corralContributionVersion":1,"env":{"FOO":"bar"},"agentNotes":["note one"],"status":["did a thing"]}`,
	}}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "c"}}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Env["FOO"] != "bar" {
		t.Errorf("env not merged into the contribution: %v", c.Env)
	}
	if len(c.AgentNotes) != 1 || c.AgentNotes[0] != "note one" {
		t.Errorf("agentNotes must ride as authored: %v", c.AgentNotes)
	}
	if !strings.Contains(strings.Join(c.Status, "\n"), "10-a: did a thing") {
		t.Errorf("status must append prefixed with the authoring hook's key: %q", c.Status)
	}
}

// Every stdout that is neither empty nor exactly one versioned JSON object fails the hook with
// the standard "stdout is reserved" wording, the specific detail, and the config-path attribution.
func TestPreStartStdoutContractViolations(t *testing.T) {
	cases := []struct{ name, stdout, detail string }{
		{"missing marker", `{"env":{"A":"b"}}`, `"corralContributionVersion" marker is missing`},
		{"wrong version", `{"corralContributionVersion":2}`, "unsupported contribution version 2"},
		{"unknown field", `{"corralContributionVersion":1,"bogus":true}`, `unknown field "bogus"`},
		{"trailing data", `{"corralContributionVersion":1}{"corralContributionVersion":1}`, "trailing data"},
		{"top-level array", `[{"corralContributionVersion":1}]`, "expected a single JSON contribution object"},
		{"top-level string", `"hello"`, "expected a single JSON contribution object"},
		{"non-JSON text", "Hallo", "expected a single JSON contribution object"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{stdout: map[string]string{"c": tc.stdout}}
			h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "c"}}}, rec)
			_, err := h.Mint(context.Background(), spec.Session{}, false)
			if err == nil {
				t.Fatalf("%s must fail the hook", tc.name)
			}
			if !strings.Contains(err.Error(), "stdout is reserved for the contribution interface") ||
				!strings.Contains(err.Error(), "prints and logs belong on stderr") {
				t.Errorf("missing the standard contract wording: %v", err)
			}
			if !strings.Contains(err.Error(), tc.detail) {
				t.Errorf("error %q missing detail %q", err.Error(), tc.detail)
			}
			if !strings.Contains(err.Error(), "providers.hooks.preStart.10-a") {
				t.Errorf("error must attribute the entry: %v", err)
			}
		})
	}
}

// stdout past the 1 MiB cap is a contract violation (the buffer is truncated, so parsing it
// would be meaningless), reported with the standard wording.
func TestPreStartCapExceeded(t *testing.T) {
	rec := &recorder{stdout: map[string]string{"c": strings.Repeat("x", maxContribBytes+1)}}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "c"}}}, rec)
	_, err := h.Mint(context.Background(), spec.Session{}, false)
	if err == nil || !strings.Contains(err.Error(), "capture limit") {
		t.Fatalf("output over the cap must fail the hook, got %v", err)
	}
	if !strings.Contains(err.Error(), "stdout is reserved for the contribution interface") {
		t.Errorf("a cap violation must use the standard contract wording: %v", err)
	}
}

// A contract violation on an optional hook warns and drops that hook's contribution, never
// aborting; the launch proceeds without the dropped env.
func TestPreStartOptionalViolationDropped(t *testing.T) {
	rec := &recorder{stdout: map[string]string{"bad": "Hallo"}}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "bad", Optional: true}}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatalf("an optional contract violation must not abort: %v", err)
	}
	if len(c.Env) != 0 {
		t.Errorf("the violating hook's contribution must be dropped, got env %v", c.Env)
	}
	joined := strings.Join(c.Status, "\n")
	// The hook did run (exit 0), so it stays in the ran list; the drop is a detail row.
	if !strings.Contains(joined, "preStart ran 10-a") || !strings.Contains(joined, "10-a: contribution dropped") {
		t.Errorf("Status must keep the hook in the ran list and note the dropped contribution: %q", c.Status)
	}
}

// A contract violation on a non-optional hook aborts the launch closed with a Mint error. With
// no postEnd configured there is nothing to pair, so no contribution comes back.
func TestPreStartNonOptionalViolationAborts(t *testing.T) {
	rec := &recorder{stdout: map[string]string{"bad": "Hallo"}}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "bad"}}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{}, false)
	if err == nil {
		t.Fatal("a non-optional contract violation must return a Mint error (fail-closed abort)")
	}
	if c != nil {
		t.Errorf("no contribution on a fail-closed abort, got %+v", c)
	}
}

// The contribution's env names and values get the same scrutiny config's env.set gets, because
// they come from a script rather than from corral's own code: a name that is not a POSIX
// variable name would otherwise reach `bwrap --setenv` and define something else, a NUL byte
// cannot survive execve, and an oversized payload would fail the launch in the backend with no
// attribution. Each is an attributed hook failure instead.
func TestPreStartEnvAndNoteValidation(t *testing.T) {
	big := strings.Repeat("x", maxContribPayloadBytes+1)
	cases := []struct{ name, stdout, detail string }{
		{"name with =", `{"corralContributionVersion":1,"env":{"A=B":"x"}}`, `env "A=B" is not a valid environment variable name`},
		{"name with space", `{"corralContributionVersion":1,"env":{"A B":"x"}}`, `is not a valid environment variable name`},
		{"leading digit", `{"corralContributionVersion":1,"env":{"1A":"x"}}`, `is not a valid environment variable name`},
		{"NUL in value", `{"corralContributionVersion":1,"env":{"A":"x\u0000y"}}`, `env "A" has a NUL byte in its value`},
		{"NUL in note", `{"corralContributionVersion":1,"agentNotes":["a\u0000b"]}`, "a contributed note has a NUL byte"},
		{"oversized payload", `{"corralContributionVersion":1,"env":{"A":"` + big + `"}}`, "over the"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recorder{stdout: map[string]string{"c": tc.stdout}}
			h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "c"}}}, rec)
			_, err := h.Mint(context.Background(), spec.Session{}, false)
			if err == nil {
				t.Fatalf("%s must fail the hook", tc.name)
			}
			if !strings.Contains(err.Error(), tc.detail) {
				t.Errorf("error %q missing detail %q", err.Error(), tc.detail)
			}
			if !strings.Contains(err.Error(), "providers.hooks.preStart.10-a") {
				t.Errorf("error must attribute the entry: %v", err)
			}
		})
	}
}

// A duplicate env key across two hooks of this provider fails the later hook, attributed to
// its config path (optional semantics still apply, but here both are required so it aborts).
func TestPreStartEnvDuplicateAcrossHooksLaterFails(t *testing.T) {
	rec := &recorder{stdout: map[string]string{
		"a": `{"corralContributionVersion":1,"env":{"SHARED":"1"}}`,
		"b": `{"corralContributionVersion":1,"env":{"SHARED":"2"}}`,
	}}
	h := newWith(Config{PreStart: map[string]Hook{
		"10-a": {Exec: "a"},
		"20-b": {Exec: "b"},
	}}, rec)
	_, err := h.Mint(context.Background(), spec.Session{}, false)
	if err == nil {
		t.Fatal("a duplicate env key across two hooks must fail the later hook")
	}
	if !strings.Contains(err.Error(), "providers.hooks.preStart.20-b") || !strings.Contains(err.Error(), "SHARED") {
		t.Errorf("the LATER hook (20-b) must be blamed for the duplicate: %v", err)
	}
}

// An empty env variable name is a validation failure of the contributing hook.
func TestPreStartEmptyEnvName(t *testing.T) {
	rec := &recorder{stdout: map[string]string{"c": `{"corralContributionVersion":1,"env":{"":"x"}}`}}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "c"}}}, rec)
	_, err := h.Mint(context.Background(), spec.Session{}, false)
	if err == nil || !strings.Contains(err.Error(), "empty variable name") {
		t.Fatalf("an empty env name must fail the hook, got %v", err)
	}
}

// With no injected presenter (the plain default, as doctor/gc build the provider) a preStart
// hook's captured stderr is surfaced to (the seam for) stderr as a corral-attributed block —
// after the hook, and only when it wrote something. A truncated capture says so out loud.
func TestPreStartPlainDefaultSurfacesStderr(t *testing.T) {
	rec := &recorder{stderr: map[string]string{"noisy": "warming caches\nfetch failed, retrying"}}
	h := newWith(Config{PreStart: map[string]Hook{
		"10-quiet": {Exec: "quiet"},
		"20-noisy": {Exec: "noisy"},
	}}, rec)
	if _, err := h.Mint(context.Background(), spec.Session{}, false); err != nil {
		t.Fatal(err)
	}
	got := rec.log.String()
	if strings.Contains(got, "10-quiet") {
		t.Errorf("a quiet hook must surface nothing, got %q", got)
	}
	// The block is attributed to the config path, carries the output verbatim, and is
	// newline-terminated even when the hook's last line was not.
	if !strings.Contains(got, "corral: output from pre-start session hook providers.hooks.preStart.20-noisy:\n"+
		"warming caches\nfetch failed, retrying\n") {
		t.Errorf("missing the attributed output block: %q", got)
	}
}

// Captured stderr past the display cap is truncated for display — marked, but never a hook
// failure: stderr is the human channel, not a contract surface.
func TestPreStartStderrOverflowTruncatesNeverFails(t *testing.T) {
	rec := &recorder{stderr: map[string]string{"c": strings.Repeat("x", maxStderrBytes+1)}}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "c"}}}, rec)
	var truncated bool
	h.present = func(_, _, _ string, trunc bool) { truncated = trunc }
	if _, err := h.Mint(context.Background(), spec.Session{}, false); err != nil {
		t.Fatalf("stderr overflow must never fail the hook: %v", err)
	}
	if !truncated {
		t.Error("the presenter must be told the capture was truncated")
	}
}

// With a launcher-injected presenter, each enabled preStart hook that wrote to stderr is
// presented once after it ran, in lexical key order, with event="preStart", the short entry key
// (not the full providers.hooks.… path), and the captured output; a quiet hook is skipped
// entirely. corral prints no attribution of its own — the presenter owns the rendering.
func TestPreStartPresenterInjection(t *testing.T) {
	rec := &recorder{stderr: map[string]string{"a": "out-a\n", "c": "out-c\n"}}
	h := newWith(Config{PreStart: map[string]Hook{
		"10-a": {Exec: "a"},
		"20-b": {Exec: "b"}, // quiet → never presented
		"30-c": {Exec: "c"},
	}}, rec)

	type call struct{ event, key, output string }
	var calls []call
	h.present = func(event, key, output string, _ bool) {
		calls = append(calls, call{event: event, key: key, output: output})
	}

	if _, err := h.Mint(context.Background(), spec.Session{}, false); err != nil {
		t.Fatal(err)
	}
	want := []call{
		{event: "preStart", key: "10-a", output: "out-a\n"},
		{event: "preStart", key: "30-c", output: "out-c\n"},
	}
	if len(calls) != len(want) {
		t.Fatalf("presenter calls = %+v, want %+v (quiet 20-b skipped)", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Errorf("presenter call %d = %+v, want %+v", i, calls[i], want[i])
		}
	}
	if rec.log.Len() != 0 {
		t.Errorf("an injected presenter owns the rendering; corral must print none, got %q", rec.log.String())
	}
}

// A failing hook's captured stderr is surfaced too — before Mint returns the abort error, so
// the hook's own diagnostics precede the error that cites it.
func TestPreStartPresenterCalledOnFailure(t *testing.T) {
	rec := &recorder{
		failOn: map[string]error{"boom": errors.New("nonzero exit")},
		stderr: map[string]string{"boom": "cannot reach VPN\n"},
	}
	h := newWith(Config{PreStart: map[string]Hook{"10-a": {Exec: "boom"}}}, rec)
	var got string
	h.present = func(_, _, output string, _ bool) { got = output }
	if _, err := h.Mint(context.Background(), spec.Session{}, false); err == nil {
		t.Fatal("the hook must fail the launch")
	}
	if got != "cannot reach VPN\n" {
		t.Errorf("the failing hook's stderr must be surfaced before the abort, got %q", got)
	}
}

// The presenter governs preStart only: postEnd keeps the corral:-prefixed header and the concrete
// os.Stderr even when a preStart presenter is injected, and the presenter is never called for it.
func TestPostEndIgnoresPresenter(t *testing.T) {
	rec := &recorder{stderr: map[string]string{"r": "report noise\n"}}
	h := newWith(Config{PostEnd: map[string]Hook{"report": {Exec: "r"}}}, rec)
	var presented int
	h.present = func(string, string, string, bool) { presented++ }

	c, err := h.Mint(context.Background(), spec.Session{WorkDir: touchFiles(t, "r")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PostSession(context.Background(), spec.SessionExit{Started: true, Code: 0}); err != nil {
		t.Fatal(err)
	}
	if presented != 0 {
		t.Errorf("the presenter must never be called for postEnd, got %d call(s)", presented)
	}
	cmd := rec.cmds[len(rec.cmds)-1]
	if cmd.Stderr != os.Stderr {
		t.Error("postEnd cmd.Stderr must stay the concrete os.Stderr")
	}
	if !strings.Contains(rec.log.String(), "corral: running post-end session hook providers.hooks.postEnd.report") {
		t.Errorf("postEnd must keep the corral:-prefixed header: %q", rec.log.String())
	}
}

// postEnd keeps stdout+stderr passthrough (nothing captured or parsed — a session report
// legitimately prints), gets the attributed header line before it runs, and is one-way like
// every session hook: stdin unwired.
func TestPostEndStdioPassthroughAndHeader(t *testing.T) {
	rec := &recorder{}
	h := newWith(Config{PostEnd: map[string]Hook{"report": {Exec: "r"}}}, rec)
	c, err := h.Mint(context.Background(), spec.Session{WorkDir: touchFiles(t, "r")}, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.PostSession(context.Background(), spec.SessionExit{Started: true, Code: 0}); err != nil {
		t.Fatal(err)
	}
	cmd := rec.cmds[len(rec.cmds)-1]
	if cmd.Stdout != os.Stdout || cmd.Stderr != os.Stderr {
		t.Error("postEnd must keep stdout/stderr passthrough — nothing captured")
	}
	if cmd.Stdin != nil {
		t.Error("session hooks are one-way — postEnd stdin must be unwired (/dev/null) too")
	}
	if !strings.Contains(rec.log.String(), "corral: running post-end session hook providers.hooks.postEnd.report") {
		t.Errorf("missing the post-end attribution header line: %q", rec.log.String())
	}
}

// --- script resolution & direct exec ---

// ResolveExec is one resolution rule with two consumers (the provider's exec and the trust
// gate's hashing): every relative form — including a bare name, which must never become a
// $PATH lookup — resolves against the workdir; absolute paths are cleaned and kept.
func TestResolveExec(t *testing.T) {
	for _, tc := range []struct{ script, workdir, want string }{
		{"./scripts/u.sh", "/w", "/w/scripts/u.sh"},
		{"scripts/u.sh", "/w", "/w/scripts/u.sh"},
		{"update.sh", "/w", "/w/update.sh"}, // bare name = workdir file, not $PATH
		{"../shared/u.sh", "/w/sub", "/w/shared/u.sh"},
		{"/abs/u.sh", "/w", "/abs/u.sh"},
		{"/abs//x/../u.sh", "/w", "/abs/u.sh"}, // cleaned
	} {
		if got := ResolveExec(tc.script, tc.workdir); got != tc.want {
			t.Errorf("ResolveExec(%q, %q) = %q, want %q", tc.script, tc.workdir, got, tc.want)
		}
	}
}

// realRunner builds a *hooks that actually execs (no recorder seam), logging to a buffer.
func realRunner(cfg Config, log *bytes.Buffer) *hooks {
	return &hooks{cfg: cfg, agent: "claude", run: func(cmd *exec.Cmd) error { return cmd.Run() }, log: log}
}

// End to end with a real file: the script runs without any shell — the kernel honors the
// shebang and the configured args arrive as argv — and its stderr is captured and surfaced
// through the plain default after it exits.
func TestRealExecutableDirectExec(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hello.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"arg1=$1\" >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	h := realRunner(Config{PreStart: map[string]Hook{"10-a": {Exec: "./hello.sh", Args: []string{"val"}}}}, &log)
	if _, err := h.Mint(context.Background(), spec.Session{WorkDir: dir}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "arg1=val") {
		t.Errorf("the script's stderr (proving shebang + args) must surface: %q", log.String())
	}
}

// A script without the executable bit fails the launch with the actionable +x hint; a missing
// file fails with exec's own path-naming error. Both attribute the entry.
func TestRealExecutableLaunchFailures(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "noexec.sh"), []byte("#!/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, script, detail string }{
		{"not executable", "./noexec.sh", "chmod +x"},
		{"missing file", "./missing.sh", "missing.sh"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var log bytes.Buffer
			h := realRunner(Config{PreStart: map[string]Hook{"10-a": {Exec: tc.script}}}, &log)
			_, err := h.Mint(context.Background(), spec.Session{WorkDir: dir}, false)
			if err == nil {
				t.Fatal("the launch must fail closed")
			}
			if !strings.Contains(err.Error(), tc.detail) || !strings.Contains(err.Error(), "providers.hooks.preStart.10-a") {
				t.Errorf("error = %v, want detail %q with attribution", err, tc.detail)
			}
		})
	}
}

// --- helpers ---

func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i >= 0 {
			m[e[:i]] = e[i+1:]
		}
	}
	return m
}

func filterCorral(env []string) []string {
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, "CORRAL_") {
			out = append(out, e)
		}
	}
	return out
}

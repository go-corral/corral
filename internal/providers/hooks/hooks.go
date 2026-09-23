// Package hooks implements the session-hooks provider: host-side scripts corral runs around the
// agent session — preStart before it starts (may abort the launch), postEnd after it ends. They
// run outside the sandbox and are unrelated to the `corral hook` enforcer.
package hooks

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-corral/corral/internal/providers/spec"
)

const (
	maxContribBytes     = 1 << 20 // 1 MiB; exceeding it is a contract violation, not silent truncation
	contributionVersion = 1
	maxStderrBytes      = 64 << 10 // 64 KiB; display-only — overflow truncates what is shown
	// maxContribPayloadBytes bounds what one hook passes into the sandbox (env values + notes),
	// versus maxContribBytes on what corral reads. The destination is an execve argv, capped at
	// MAX_ARG_STRLEN (128 KiB); without the bound a large contribution surfaces as a cryptic backend
	// E2BIG instead of an attributed hook failure here.
	maxContribPayloadBytes = 64 << 10 // 64 KiB
)

type hooks struct {
	cfg   Config
	agent string
	// run executes one prepared command — a seam: New wires cmd.Run; tests swap it to capture the
	// *exec.Cmd or inject stdout without exec'ing a real script.
	run func(*exec.Cmd) error
	// present is the launcher-injected preStart presenter (see Presenter).
	present Presenter
	// log receives corral's attribution lines, one per line.
	log io.Writer
}

// Presenter renders a preStart hook's captured stderr. The launcher (internal/cli) injects it,
// since presentation belongs to the cli layer hooks can't import without a cycle. A nil Presenter
// selects the plain default: a corral-attributed block on log.
type Presenter func(event, key, output string, truncated bool)

// New builds the session-hooks provider. agent is exported to scripts as CORRAL_AGENT; present is
// the preStart presenter (see Presenter), nil for the plain default; log receives corral's
// attribution lines, os.Stderr when nil.
func New(cfg Config, agent string, present Presenter, log io.Writer) spec.Provider {
	if log == nil {
		log = os.Stderr
	}
	return &hooks{cfg: cfg, agent: agent, present: present, run: func(cmd *exec.Cmd) error { return cmd.Run() }, log: log}
}

func (h *hooks) Name() string { return "hooks" }

// Available is always true: a missing script fails the run instead of silently skipping the provider.
func (h *hooks) Available(ctx context.Context) bool { return true }

// Mint runs the enabled preStart hooks in lexical key order and returns a Contribution. A
// non-optional preStart failure fails the launch closed — hooks is first among feature providers,
// so nothing has minted yet — while abortContribution still lets postEnd fire for entries that ran.
// Session hooks never run on a dry run.
func (h *hooks) Mint(ctx context.Context, sess spec.Session, dryRun bool) (*spec.Contribution, error) {
	if dryRun {
		return nil, spec.ErrNoDryRun("hooks", "run pre-start session hooks")
	}

	var ran, skipped, details []string
	var agentNotes []string
	env := map[string]string{}
	for _, key := range sortedKeys(h.cfg.PreStart) {
		hk := h.cfg.PreStart[key]
		label := "providers.hooks.preStart." + key
		if !hk.IsEnabled() {
			skipped = append(skipped, key)
			continue
		}
		out := newCappedBuffer(maxContribBytes)
		errOut := newCappedBuffer(maxStderrBytes)
		runErr := describeRunError(h.run(h.command(ctx, sess, "preStart", hk, out, errOut)))
		h.surfacePreStart(key, label, errOut)
		if runErr != nil {
			if hk.Optional {
				details = append(details, fmt.Sprintf("%s: failed but optional — continuing (%v)", key, runErr))
				continue
			}
			return h.abortContribution(sess), fmt.Errorf("%s: %w", label, runErr)
		}

		pc, verr := h.parseContribution(out, label)
		if verr == nil && pc != nil {
			verr = validateContribution(env, pc, label)
		}
		if verr != nil {
			if hk.Optional {
				ran = append(ran, key)
				details = append(details, fmt.Sprintf("%s: contribution dropped — %v", key, verr))
				continue
			}
			return h.abortContribution(sess), verr
		}

		ran = append(ran, key)
		if pc != nil {
			for _, k := range sortedStringKeys(pc.Env) {
				env[k] = pc.Env[k]
			}
			for _, s := range pc.Status {
				details = append(details, fmt.Sprintf("%s: %s", key, s))
			}
			agentNotes = append(agentNotes, pc.AgentNotes...)
		}
	}

	var status []string
	var parts []string
	if len(ran) > 0 {
		parts = append(parts, "ran "+strings.Join(ran, ", "))
	}
	if len(skipped) > 0 {
		parts = append(parts, "skipped "+strings.Join(skipped, ", ")+" (disabled)")
	}
	if len(parts) > 0 {
		status = append(status, "preStart "+strings.Join(parts, " · "))
	}
	status = append(status, details...)

	contrib := &spec.Contribution{Status: status}
	if len(env) > 0 {
		contrib.Env = env
	}
	if len(agentNotes) > 0 {
		contrib.AgentNotes = agentNotes
	}
	if countEnabled(h.cfg.PostEnd) > 0 {
		contrib.PostSession = h.postSession(sess)
	}
	return contrib, nil
}

// abortContribution is the partial contribution a fail-closed preStart abort returns with its
// error: only the paired postEnd closure, since the engine honors just PostSession from a failed
// Mint and the postEnd that undoes earlier entries' work must still run. nil when no postEnd is enabled.
func (h *hooks) abortContribution(sess spec.Session) *spec.Contribution {
	if countEnabled(h.cfg.PostEnd) == 0 {
		return nil
	}
	return &spec.Contribution{PostSession: h.postSession(sess)}
}

// contribution is the strict JSON a preStart hook may print on stdout. Version
// (corralContributionVersion) is required and must equal contributionVersion; the rest optional.
type contribution struct {
	Version    *int              `json:"corralContributionVersion"`
	Env        map[string]string `json:"env"`
	AgentNotes []string          `json:"agentNotes"`
	Status     []string          `json:"status"`
}

// parseContribution reads a preStart hook's stdout as the strict contribution interface. Empty
// stdout yields (nil, nil); any deviation fails with an error pointing the operator at stderr.
func (h *hooks) parseContribution(out *cappedBuffer, label string) (*contribution, error) {
	if out.overflow {
		return nil, contractViolation(label, fmt.Sprintf("output exceeded the %d-byte stdout capture limit", maxContribBytes))
	}
	raw := out.buf.Bytes()
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var c contribution
	if err := dec.Decode(&c); err != nil {
		return nil, contractViolation(label, fmt.Sprintf("expected a single JSON contribution object: %v", err))
	}
	if dec.More() {
		return nil, contractViolation(label, "unexpected trailing data after the JSON contribution object")
	}
	if c.Version == nil {
		return nil, contractViolation(label, `the required "corralContributionVersion" marker is missing`)
	}
	if *c.Version != contributionVersion {
		return nil, contractViolation(label, fmt.Sprintf("unsupported contribution version %d (this corral speaks version %d)", *c.Version, contributionVersion))
	}
	return &c, nil
}

func contractViolation(label, detail string) error {
	return fmt.Errorf("%s: stdout is reserved for the contribution interface — %s (prints and logs belong on stderr)", label, detail)
}

// validateContribution checks a parsed contribution before merge. Names and values come from a
// script's stdout, not Go code, so each is validated. Cross-provider/baseline collisions and
// reserved control markers are fenced in the engine's Apply instead.
func validateContribution(acc map[string]string, pc *contribution, label string) error {
	payload := 0
	for _, k := range sortedStringKeys(pc.Env) {
		if k == "" {
			return fmt.Errorf("%s: env contribution has an empty variable name", label)
		}
		if !spec.IsEnvName(k) {
			return fmt.Errorf("%s: env %q is not a valid environment variable name", label, k)
		}
		if _, dup := acc[k]; dup {
			return fmt.Errorf("%s: env %q was already contributed by an earlier session hook", label, k)
		}
		if strings.ContainsRune(pc.Env[k], 0) {
			return fmt.Errorf("%s: env %q has a NUL byte in its value", label, k)
		}
		payload += len(k) + len(pc.Env[k])
	}
	for _, s := range append(append([]string{}, pc.AgentNotes...), pc.Status...) {
		if strings.ContainsRune(s, 0) {
			return fmt.Errorf("%s: a contributed note has a NUL byte", label)
		}
		payload += len(s)
	}
	if payload > maxContribPayloadBytes {
		return fmt.Errorf("%s: contribution is %d bytes of env values and notes, over the %d-byte limit "+
			"corral can pass into the sandbox environment", label, payload, maxContribPayloadBytes)
	}
	return nil
}

// postSession returns the session-end closure: it runs the enabled postEnd hooks in lexical order,
// each exporting the outcome as CORRAL_AGENT_EXIT. Every enabled entry runs even if one fails
// (independent notifications, not a pipeline). Failures join warn-only.
//
// Each executable is hashed at closure-build time and again when the closure fires — the window a
// live in-sandbox agent could edit a workdir hook. A mismatch, unreadable, or vanished file skips
// that entry with an attributed warning; the rest run, and the next launch re-prompts the trust gate.
func (h *hooks) postSession(sess spec.Session) func(context.Context, spec.SessionExit) error {
	type launchHash struct {
		sum string
		err error
	}
	launch := map[string]launchHash{}
	for _, key := range sortedKeys(h.cfg.PostEnd) {
		if hk := h.cfg.PostEnd[key]; hk.IsEnabled() {
			sum, err := HashFile(ResolveExec(hk.Exec, sess.WorkDir))
			launch[key] = launchHash{sum: sum, err: err}
		}
	}
	return func(ctx context.Context, exit spec.SessionExit) error {
		exitVal := "aborted"
		if exit.Started {
			exitVal = strconv.Itoa(exit.Code)
		}
		var errs []error
		for _, key := range sortedKeys(h.cfg.PostEnd) {
			hk := h.cfg.PostEnd[key]
			if !hk.IsEnabled() {
				continue
			}
			label := "providers.hooks.postEnd." + key
			path := ResolveExec(hk.Exec, sess.WorkDir)
			lh := launch[key]
			if lh.err != nil {
				errs = append(errs, fmt.Errorf("%s: skipped — %s could not be read at launch (%v)", label, path, lh.err))
				continue
			}
			now, err := HashFile(path)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: skipped — %s is no longer readable (%v)", label, path, err))
				continue
			}
			if now != lh.sum {
				errs = append(errs, fmt.Errorf("%s: skipped — %s changed during the session; the next launch will re-prompt to approve the new content", label, path))
				continue
			}
			fmt.Fprintf(h.log, "running post-end session hook %s\n", label)
			cmd := h.command(ctx, sess, "postEnd", hk, os.Stdout, os.Stderr, "CORRAL_AGENT_EXIT="+exitVal)
			if err := describeRunError(h.run(cmd)); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", label, err))
			}
		}
		return errors.Join(errs...)
	}
}

func (h *hooks) surfacePreStart(key, label string, out *cappedBuffer) {
	output := out.buf.String()
	if strings.TrimSpace(output) == "" && !out.overflow {
		return
	}
	if h.present != nil {
		h.present("preStart", key, output, out.overflow)
		return
	}
	sep := ""
	if !strings.HasSuffix(output, "\n") {
		sep = "\n"
	}
	fmt.Fprintf(h.log, "output from pre-start session hook %s:\n%s%s", label, output, sep)
	if out.overflow {
		fmt.Fprintf(h.log, "… output truncated at %d bytes\n", maxStderrBytes)
	}
}

// command builds the *exec.Cmd for one session hook: exec'd directly (no shell, so the file is
// exactly what the trust gate hashed), cwd the session workdir, host env plus CORRAL_* vars.
// stdin is unwired — one-way hooks get EOF. No timeout; ctx cancellation still tears it down.
func (h *hooks) command(ctx context.Context, sess spec.Session, event string, hk Hook, stdout, stderr io.Writer, extraEnv ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, ResolveExec(hk.Exec, sess.WorkDir), hk.Args...)
	cmd.Dir = sess.WorkDir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = append(os.Environ(),
		"CORRAL_EVENT="+event,
		"CORRAL_AGENT="+h.agent,
		"CORRAL_SESSION_ID="+sess.ID,
		"CORRAL_WORKDIR="+sess.WorkDir,
	)
	cmd.Env = append(cmd.Env, extraEnv...)
	return cmd
}

// ResolveExec absolutizes a hook's executable against the session workdir. Every relative form is
// workdir-relative: a hook names a file, not a command, so there is no $PATH lookup. Exported so the
// trust gate hashes exactly the file this provider execs.
func ResolveExec(script, workdir string) string {
	if filepath.IsAbs(script) {
		return filepath.Clean(script)
	}
	return filepath.Join(workdir, script)
}

// HashFile returns the hex SHA-256 of the file's current content, exported so the trust gate and
// this provider's fire-time re-verify use one implementation.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func describeRunError(err error) error {
	if err != nil && errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w — is the script executable? (chmod +x)", err)
	}
	return err
}

// cappedBuffer accumulates output up to a byte cap. Writes past the cap are dropped and set
// overflow; Write reports the full length so the child never sees a short write or EPIPE.
type cappedBuffer struct {
	buf      bytes.Buffer
	cap      int
	overflow bool
}

// newCappedBuffer is a constructor, not a zero-value literal, so a cap-less buffer (which would
// overflow on every write and fail every contributing hook) is unconstructible.
func newCappedBuffer(cap int) *cappedBuffer { return &cappedBuffer{cap: cap} }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if room := b.cap - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
			b.overflow = true
		} else {
			b.buf.Write(p)
		}
	} else if len(p) > 0 {
		b.overflow = true
	}
	return len(p), nil
}

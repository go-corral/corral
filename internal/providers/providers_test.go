package providers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
	"github.com/go-corral/corral/internal/sandbox"
)

// fakeProvider is a configurable test double. dryRunErr models a credential-minter: when
// set, Mint fails only under dryRun=true (it cannot produce a contribution without its side
// effect), while a real Mint (dryRun=false) still returns contrib.
type fakeProvider struct {
	name      string
	available bool
	contrib   *Contribution
	mintErr   error
	dryRunErr error
	// partialContrib is returned alongside mintErr — the paired-teardown contract, where a
	// provider that already produced side effects hands the engine its PostSession while
	// still failing (see spec.Contribution.PostSession). nil = the usual (nil, err).
	partialContrib *Contribution
}

func (f *fakeProvider) Name() string                   { return f.name }
func (f *fakeProvider) Available(context.Context) bool { return f.available }
func (f *fakeProvider) Mint(_ context.Context, _ Session, dryRun bool) (*Contribution, error) {
	if dryRun && f.dryRunErr != nil {
		return nil, f.dryRunErr
	}
	if f.mintErr != nil {
		return f.partialContrib, f.mintErr
	}
	return f.contrib, nil
}

func cleanupRecorder(log *[]string, name string) func(context.Context) error {
	return func(context.Context) error {
		*log = append(*log, name)
		return nil
	}
}

func TestResolveCollectsStatusAsNotices(t *testing.T) {
	a := &fakeProvider{name: "gitlab", available: true, contrib: &Contribution{Status: []string{"minted token for g/r"}}}
	b := &fakeProvider{name: "kubernetes", available: true, contrib: &Contribution{Status: []string{"minted SA ns/x", "2 bindings"}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}})
	if err != nil {
		t.Fatal(err)
	}
	// Status lines are collected verbatim, in provider then declaration order, each
	// attributed to its provider (the banner labels the row with it).
	want := []Notice{
		{Provider: "gitlab", Text: "minted token for g/r"},
		{Provider: "kubernetes", Text: "minted SA ns/x"},
		{Provider: "kubernetes", Text: "2 bindings"},
	}
	if len(res.Notices) != len(want) {
		t.Fatalf("notices = %v, want %v", res.Notices, want)
	}
	for i, w := range want {
		if res.Notices[i] != w {
			t.Errorf("notice[%d] = %+v, want %+v", i, res.Notices[i], w)
		}
	}
}

// AgentNotes are the model-facing dual of Status: Resolve collects them attributed in
// provider order, and Apply hands them to the in-sandbox session-start hook as one
// newline-joined env var (sandbox.ProviderNotesEnvVar) of "- <provider>: <note>"
// markdown bullets — attributed for the model, self-delimiting for a human echo.
func TestResolveCollectsAgentNotesAndApplySetsEnv(t *testing.T) {
	a := &fakeProvider{name: "gitlab", available: true,
		contrib: &Contribution{AgentNotes: []string{"GITLAB_TOKEN holds a scoped token"}}}
	b := &fakeProvider{name: "home", available: true,
		contrib: &Contribution{AgentNotes: []string{"$HOME is sandbox-private"}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}})
	if err != nil {
		t.Fatal(err)
	}
	spec := sandbox.SandboxSpec{}
	if err := res.Apply(&spec); err != nil {
		t.Fatal(err)
	}
	want := "- gitlab: GITLAB_TOKEN holds a scoped token\n- home: $HOME is sandbox-private"
	if got := spec.SetEnv[sandbox.ProviderNotesEnvVar]; got != want {
		t.Errorf("%s = %q, want %q", sandbox.ProviderNotesEnvVar, got, want)
	}
}

// With no notes, Apply must not plant the marker at all: the in-sandbox hook treats
// its absence as "no provider notes" and injects the base sandbox note alone.
func TestApplyOmitsProviderNotesEnvWhenNone(t *testing.T) {
	a := &fakeProvider{name: "docker", available: true,
		contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/var/run/docker.sock"}}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}})
	if err != nil {
		t.Fatal(err)
	}
	spec := sandbox.SandboxSpec{}
	if err := res.Apply(&spec); err != nil {
		t.Fatal(err)
	}
	if v, ok := spec.SetEnv[sandbox.ProviderNotesEnvVar]; ok {
		t.Errorf("no AgentNotes must leave %s unset, got %q", sandbox.ProviderNotesEnvVar, v)
	}
}

// A provider Env entry must not be able to claim the notes marker: that would let it
// plant model-facing context outside the AgentNotes contract (and race the fold).
// Like every other env collision, it fails the launch closed.
func TestApplyRejectsProviderEnvClaimingNotesMarker(t *testing.T) {
	a := &fakeProvider{name: "gitlab", available: true,
		contrib: &Contribution{Env: map[string]string{sandbox.ProviderNotesEnvVar: "forged"}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}})
	if err != nil {
		t.Fatal(err)
	}
	spec := sandbox.SandboxSpec{}
	if err := res.Apply(&spec); err == nil {
		t.Fatalf("a provider Env claiming %s must fail Apply closed", sandbox.ProviderNotesEnvVar)
	}
}

// The backend-notes channel is the sibling model-facing marker and must be equally
// un-plantable by a provider Env — on every backend, including one that contributes no note
// (bwrap), where the key is absent from spec.SetEnv. An empty spec models exactly that bwrap
// case, so this guards the asymmetry the reservation closes.
func TestApplyRejectsProviderEnvClaimingBackendNotesMarker(t *testing.T) {
	a := &fakeProvider{name: "gitlab", available: true,
		contrib: &Contribution{Env: map[string]string{sandbox.BackendNotesEnvVar: "forged"}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}})
	if err != nil {
		t.Fatal(err)
	}
	spec := sandbox.SandboxSpec{}
	if err := res.Apply(&spec); err == nil {
		t.Fatalf("a provider Env claiming %s must fail Apply closed", sandbox.BackendNotesEnvVar)
	}
}

// corral's control markers must be equally un-plantable by a provider Env, and — unlike the
// notes channels — they are set conditionally by the launcher (the global-config pin only when a
// global config was loaded, CORRAL_BIN only for an agent with a policy extension). An empty spec
// models exactly the launch where each is absent, which is where an unclaimed name would be free
// for the taking. Planting one would steer the in-sandbox hook itself — the config file it
// re-reads per tool call, the agent dir it self-protects, the binary a policy extension
// re-invokes — so it must fail Apply closed. Matters most for a provider whose Env is authored
// outside the trust-approved config: a session hook's stdout contribution.
func TestApplyRejectsProviderEnvClaimingControlMarkers(t *testing.T) {
	for _, name := range []string{sandbox.SandboxEnvVar, sandbox.GlobalConfigEnvVar, sandbox.AgentEnvVar, sandbox.BinEnvVar} {
		t.Run(name, func(t *testing.T) {
			a := &fakeProvider{name: "hooks", available: true,
				contrib: &Contribution{Env: map[string]string{name: "/work/proj/evil.yml"}}}
			res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}})
			if err != nil {
				t.Fatal(err)
			}
			spec := sandbox.SandboxSpec{}
			err = res.Apply(&spec)
			if err == nil {
				t.Fatalf("a provider Env claiming %s must fail Apply closed", name)
			}
			if !strings.Contains(err.Error(), "reserved control marker") {
				t.Errorf("the error must name the reservation, got %v", err)
			}
			if _, planted := spec.SetEnv[name]; planted {
				t.Errorf("%s must never reach the spec", name)
			}
		})
	}
}

func TestCleanupLogsPerProviderWhenLogWriterSet(t *testing.T) {
	var log []string
	a := &fakeProvider{name: "gitlab", available: true, contrib: &Contribution{Cleanup: cleanupRecorder(&log, "a")}}
	b := &fakeProvider{name: "kubernetes", available: true, contrib: &Contribution{Cleanup: cleanupRecorder(&log, "b")}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}})
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	res.LogWriter = &buf
	_ = res.Cleanup(context.Background())

	out := buf.String()
	// LIFO: kubernetes torn down first, then gitlab — each named, none silent.
	for _, want := range []string{
		"corral: kubernetes: minted credentials torn down",
		"corral: gitlab: minted credentials torn down",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("teardown log missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "kubernetes") > strings.Index(out, "gitlab") {
		t.Errorf("teardown should report kubernetes (LIFO first) before gitlab:\n%s", out)
	}
}

func TestCleanupSilentWithoutLogWriter(t *testing.T) {
	var log []string
	a := &fakeProvider{name: "gitlab", available: true, contrib: &Contribution{Cleanup: cleanupRecorder(&log, "a")}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}})
	if err != nil {
		t.Fatal(err)
	}
	// No LogWriter set → cleanup still runs, just emits nothing (the dry-run / unwind path).
	_ = res.Cleanup(context.Background())
	if len(log) != 1 {
		t.Errorf("cleanup should still run without a LogWriter, ran %v", log)
	}
}

func TestCleanupFailureSurfacesHintWhenLogWriterSet(t *testing.T) {
	failing := &fakeProvider{name: "gitlab", available: true, contrib: &Contribution{
		CleanupHint: "the minted token may still be live until it expires on 2026-06-03 — revoke it manually",
		Cleanup:     func(context.Context) error { return errors.New("revoke token: 500") },
	}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: failing}})
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	res.LogWriter = &buf
	if err := res.Cleanup(context.Background()); err == nil {
		t.Fatal("a failing cleanup must still return its error for the launcher to log")
	}
	out := buf.String()
	if !strings.Contains(out, "gitlab: teardown FAILED") {
		t.Errorf("failure line must name the provider and that teardown failed:\n%s", out)
	}
	if !strings.Contains(out, "may still be live") || !strings.Contains(out, "revoke it manually") {
		t.Errorf("failure line must surface the residual-credential hint (risk + remedy):\n%s", out)
	}
}

func TestCleanupFailureFallsBackWithoutHint(t *testing.T) {
	// A contribution that registers a Cleanup but no CleanupHint still gets an explicit
	// warning (the generic fallback) rather than silence on a left-live credential.
	failing := &fakeProvider{name: "p", available: true, contrib: &Contribution{
		Cleanup: func(context.Context) error { return errors.New("boom") },
	}}
	res, _ := Resolve(context.Background(), Session{}, []Active{{Provider: failing}})
	var buf strings.Builder
	res.LogWriter = &buf
	_ = res.Cleanup(context.Background())
	out := buf.String()
	// Assert the exact fallback wording, not just the prefix — the generic line must still
	// name the residual-credential risk so an absent hint never degrades to a bare prefix.
	if !strings.Contains(out, "p: teardown FAILED — a minted credential may still be live until it expires on its own") {
		t.Errorf("a failed teardown without a hint must warn with the generic risk line:\n%s", out)
	}
}

func TestCleanupMixedSuccessFailureLIFO(t *testing.T) {
	// LIFO with one provider succeeding and one failing, LogWriter set: the success path
	// (torn down) and the failure path (teardown failed) must not cross-execute, both must be
	// reported in LIFO order, and the joined error must still propagate.
	var torn []string
	ok := &fakeProvider{name: "ok", available: true, contrib: &Contribution{Cleanup: cleanupRecorder(&torn, "ok")}}
	bad := &fakeProvider{name: "bad", available: true, contrib: &Contribution{
		CleanupHint: "the bad token may still be live — revoke it",
		Cleanup:     func(context.Context) error { return errors.New("revoke: 500") },
	}}
	// Declaration order [ok, bad] → cleanups [ok, bad] → LIFO tears down bad first, then ok.
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: ok}, {Provider: bad}})
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	res.LogWriter = &buf
	if err := res.Cleanup(context.Background()); err == nil {
		t.Fatal("a mixed cleanup with one failure must still return the joined error")
	}
	out := buf.String()
	failIdx := strings.Index(out, "bad: teardown FAILED")
	okIdx := strings.Index(out, "ok: minted credentials torn down")
	if failIdx < 0 || okIdx < 0 {
		t.Fatalf("both the failure and the success line must appear:\n%s", out)
	}
	if failIdx > okIdx {
		t.Errorf("LIFO: bad (registered last) must be reported before ok:\n%s", out)
	}
	// The success closure still ran exactly once despite the sibling failure.
	if len(torn) != 1 || torn[0] != "ok" {
		t.Errorf("the succeeding cleanup must run exactly once, ran %v", torn)
	}
}

func TestCleanupFailureSilentWithoutLogWriter(t *testing.T) {
	// The unwind/dry-run path (LogWriter nil): the error still propagates, nothing prints,
	// and a nil LogWriter must not panic.
	failing := &fakeProvider{name: "gitlab", available: true, contrib: &Contribution{
		CleanupHint: "x",
		Cleanup:     func(context.Context) error { return errors.New("revoke token: 500") },
	}}
	res, _ := Resolve(context.Background(), Session{}, []Active{{Provider: failing}})
	if err := res.Cleanup(context.Background()); err == nil {
		t.Fatal("the cleanup error must still propagate without a LogWriter")
	}
}

// --- session-end hooks (Contribution.PostSession) ---

// Resolve collects PostSession closures, and HasPostSession reports presence — true when a
// provider registers one, false when none do, and nil-receiver-safe.
func TestResolveCollectsPostSessionAndHasPostSession(t *testing.T) {
	withHook := &fakeProvider{name: "hooks", available: true, contrib: &Contribution{
		PostSession: func(context.Context, SessionExit) error { return nil },
	}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: withHook}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.HasPostSession() {
		t.Error("HasPostSession must be true when a provider registers a PostSession closure")
	}

	noHook := &fakeProvider{name: "docker", available: true, contrib: &Contribution{}}
	res2, err := Resolve(context.Background(), Session{}, []Active{{Provider: noHook}})
	if err != nil {
		t.Fatal(err)
	}
	if res2.HasPostSession() {
		t.Error("HasPostSession must be false with no PostSession closure")
	}

	var nilRes *Resolved
	if nilRes.HasPostSession() {
		t.Error("HasPostSession on a nil *Resolved must be false, not panic")
	}
}

// RunPostSession runs the hooks in declaration order (contrast Cleanup's LIFO), and hands
// each the SessionExit verbatim.
func TestRunPostSessionRunsInDeclarationOrderWithExit(t *testing.T) {
	var order []string
	var seen []SessionExit
	mk := func(name string) *fakeProvider {
		return &fakeProvider{name: name, available: true, contrib: &Contribution{
			PostSession: func(_ context.Context, e SessionExit) error {
				order = append(order, name)
				seen = append(seen, e)
				return nil
			},
		}}
	}
	a, b, c := mk("first"), mk("second"), mk("third")
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}, {Provider: c}})
	if err != nil {
		t.Fatal(err)
	}
	exit := SessionExit{Started: true, Code: 7, Signaled: true}
	if err := res.RunPostSession(context.Background(), exit); err != nil {
		t.Fatalf("RunPostSession: %v", err)
	}
	want := []string{"first", "second", "third"}
	if len(order) != 3 || order[0] != want[0] || order[1] != want[1] || order[2] != want[2] {
		t.Errorf("post-session order = %v, want %v (declaration order, NOT LIFO)", order, want)
	}
	// The exit struct is passed through unchanged to every hook.
	for i, e := range seen {
		if e != exit {
			t.Errorf("hook[%d] received exit %+v, want %+v", i, e, exit)
		}
	}
}

// A failing hook is attributed to its provider and joined; a succeeding sibling contributes
// nothing to the error, and every hook still runs despite an earlier one failing.
func TestRunPostSessionJoinsErrorsWithAttribution(t *testing.T) {
	a := &fakeProvider{name: "alpha", available: true, contrib: &Contribution{
		PostSession: func(context.Context, SessionExit) error { return errors.New("boom-a") },
	}}
	b := &fakeProvider{name: "bravo", available: true, contrib: &Contribution{
		PostSession: func(context.Context, SessionExit) error { return nil },
	}}
	c := &fakeProvider{name: "charlie", available: true, contrib: &Contribution{
		PostSession: func(context.Context, SessionExit) error { return errors.New("boom-c") },
	}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}, {Provider: c}})
	if err != nil {
		t.Fatal(err)
	}
	perr := res.RunPostSession(context.Background(), SessionExit{})
	if perr == nil {
		t.Fatal("RunPostSession must return the joined error when a hook fails")
	}
	msg := perr.Error()
	for _, want := range []string{"alpha", "boom-a", "charlie", "boom-c"} {
		if !strings.Contains(msg, want) {
			t.Errorf("joined error %q missing %q (each failing hook must be attributed)", msg, want)
		}
	}
	if strings.Contains(msg, "bravo") {
		t.Errorf("a succeeding hook must not appear in the joined error: %q", msg)
	}
}

// RunPostSession is idempotent: it clears its slice, so a second call is a no-op — the
// launcher's abort helper and its deferred teardown can both call it without a hook firing
// twice.
func TestRunPostSessionIsIdempotent(t *testing.T) {
	var calls int
	p := &fakeProvider{name: "hooks", available: true, contrib: &Contribution{
		PostSession: func(context.Context, SessionExit) error { calls++; return nil },
	}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: p}})
	if err != nil {
		t.Fatal(err)
	}
	_ = res.RunPostSession(context.Background(), SessionExit{})
	_ = res.RunPostSession(context.Background(), SessionExit{}) // second call must be a no-op
	if calls != 1 {
		t.Errorf("post-session hook ran %d times, want 1 (RunPostSession must be idempotent)", calls)
	}
}

// RunPostSession on a nil *Resolved is a safe no-op.
func TestRunPostSessionNilReceiverSafe(t *testing.T) {
	var res *Resolved
	if err := res.RunPostSession(context.Background(), SessionExit{}); err != nil {
		t.Errorf("RunPostSession on a nil *Resolved must be a no-op, got %v", err)
	}
}

// The fail-closed unwind fires PostSession first (declaration order, zero SessionExit =
// aborted) and still tears the cleanups down LIFO — paired teardown for a launch that
// failed after an earlier provider's pre-start hook ran.
func TestResolveUnwindFiresPostSessionBeforeCleanup(t *testing.T) {
	var events []string
	var gotExit SessionExit
	hookProv := &fakeProvider{name: "hooks", available: true, contrib: &Contribution{
		PostSession: func(_ context.Context, e SessionExit) error {
			events = append(events, "postsession")
			gotExit = e
			return nil
		},
		Cleanup: func(context.Context) error { events = append(events, "cleanup-hooks"); return nil },
	}}
	minted := &fakeProvider{name: "minted", available: true, contrib: &Contribution{
		Cleanup: func(context.Context) error { events = append(events, "cleanup-minted"); return nil },
	}}
	bad := &fakeProvider{name: "bad", available: true, mintErr: errors.New("kaboom")}

	res, err := Resolve(context.Background(), Session{}, []Active{
		{Provider: hookProv}, {Provider: minted}, {Provider: bad},
	})
	if err == nil {
		t.Fatal("expected fail-closed error")
	}
	if res != nil {
		t.Errorf("res must be nil on fail-closed, got %+v", res)
	}
	// PostSession (declaration order) runs before the LIFO cleanup unwind (minted then hooks).
	want := []string{"postsession", "cleanup-minted", "cleanup-hooks"}
	if len(events) != len(want) {
		t.Fatalf("unwind events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Fatalf("unwind events = %v, want %v (PostSession before LIFO cleanup)", events, want)
		}
	}
	if gotExit != (SessionExit{}) {
		t.Errorf("the unwind must pass a zero SessionExit (aborted), got %+v", gotExit)
	}
}

// paired teardown across a failing Mint. A provider whose Mint already ran host side effects
// before failing returns a partial Contribution alongside its error; the engine honors exactly
// its PostSession, so the abort the provider itself caused still fires the session-end hook —
// the case that otherwise breaks the pairing (the session-hooks provider's own preStart entry
// aborting the launch). Nothing else from that contribution may survive.
func TestResolveHonorsPostSessionFromFailedMint(t *testing.T) {
	var fired bool
	var gotExit = SessionExit{Started: true, Code: 9} // must be overwritten with the zero value
	bad := &fakeProvider{name: "hooks", available: true,
		mintErr: errors.New("providers.hooks.preStart.20-b: exit status 1"),
		partialContrib: &Contribution{
			PostSession: func(_ context.Context, e SessionExit) error { fired, gotExit = true, e; return nil },
			// Would be a launch-visible grant if it were honored — it must not be.
			Env: map[string]string{"LEAKED": "1"},
		}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: bad}})
	if err == nil {
		t.Fatal("a non-optional Mint error must still fail the launch closed")
	}
	if res != nil {
		t.Errorf("res must be nil on fail-closed, got %+v", res)
	}
	if !fired {
		t.Error("the unwind must fire the PostSession a failing Mint paired with its error")
	}
	if gotExit != (SessionExit{}) {
		t.Errorf("the unwind must pass a zero SessionExit (aborted), got %+v", gotExit)
	}
}

// The same for an optional provider: its Mint error downgrades to a skip-with-warning, but the
// side effects it already produced still get their session-end pairing at the END of the
// session (not in an unwind — the launch continues).
func TestResolveHonorsPostSessionFromFailedOptionalMint(t *testing.T) {
	var fired bool
	bad := &fakeProvider{name: "hooks", available: true, mintErr: errors.New("boom"),
		partialContrib: &Contribution{
			PostSession: func(context.Context, SessionExit) error { fired = true; return nil },
		}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: bad, Optional: true}})
	if err != nil {
		t.Fatalf("an optional Mint error must not fail the launch: %v", err)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("the skip must be warned, got %v", res.Warnings)
	}
	if !res.HasPostSession() {
		t.Fatal("the paired session-end hook must be collected even though the Mint failed")
	}
	if err := res.RunPostSession(context.Background(), SessionExit{Started: true}); err != nil {
		t.Fatal(err)
	}
	if !fired {
		t.Error("RunPostSession must run the paired hook")
	}
}

// ResolvePreview must not collect PostSession: a preview mints nothing and must never run
// a hook (the same reason it collects no cleanups).
func TestResolvePreviewIgnoresPostSession(t *testing.T) {
	p := &fakeProvider{name: "hooks", available: true, contrib: &Contribution{
		PostSession: func(context.Context, SessionExit) error { return nil },
	}}
	res, _, err := ResolvePreview(context.Background(), Session{}, []Active{{Provider: p}})
	if err != nil {
		t.Fatal(err)
	}
	if res.HasPostSession() {
		t.Error("ResolvePreview must not collect PostSession (a preview must never run a hook)")
	}
}

func TestResolveSkipsUnavailableOptional(t *testing.T) {
	p := &fakeProvider{name: "x", available: false}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: p, Optional: true}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.items) != 0 {
		t.Errorf("unavailable provider should contribute nothing, got %d items", len(res.items))
	}
	if len(res.Warnings) != 1 {
		t.Errorf("expected 1 warning for skipped provider, got %v", res.Warnings)
	}
}

// A required (non-optional) provider whose host prerequisite is absent must fail the
// launch closed — optional:false means the session must have the capability, so coming
// up silently without it would be a fail-open. It is the symmetric counterpart to the
// Mint-error case: an unavailable prerequisite and a Mint failure honor Optional identically.
func TestResolveFailClosedOnUnavailableRequired(t *testing.T) {
	p := &fakeProvider{name: "x", available: false}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: p}})
	if err == nil {
		t.Fatal("expected fail-closed error on a required unavailable provider")
	}
	if res != nil {
		t.Errorf("res should be nil on fail-closed, got %+v", res)
	}
}

func TestResolveFailClosedOnMintError(t *testing.T) {
	p := &fakeProvider{name: "boom", available: true, mintErr: errors.New("nope")}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: p}})
	if err == nil {
		t.Fatal("expected fail-closed error on non-optional Mint failure")
	}
	if res != nil {
		t.Errorf("res should be nil on fail-closed, got %+v", res)
	}
}

func TestResolveOptionalDowngradesToSkip(t *testing.T) {
	p := &fakeProvider{name: "opt", available: true, mintErr: errors.New("nope")}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: p, Optional: true}})
	if err != nil {
		t.Fatalf("optional provider should not fail the launch: %v", err)
	}
	if len(res.Warnings) != 1 {
		t.Errorf("expected a skip warning, got %v", res.Warnings)
	}
}

func TestResolveUnwindsLIFOOnFailClosed(t *testing.T) {
	var log []string
	good := &fakeProvider{name: "a", available: true, contrib: &Contribution{Cleanup: cleanupRecorder(&log, "a")}}
	good2 := &fakeProvider{name: "b", available: true, contrib: &Contribution{Cleanup: cleanupRecorder(&log, "b")}}
	bad := &fakeProvider{name: "c", available: true, mintErr: errors.New("kaboom")}

	_, err := Resolve(context.Background(), Session{}, []Active{
		{Provider: good}, {Provider: good2}, {Provider: bad},
	})
	if err == nil {
		t.Fatal("expected fail-closed error")
	}
	// a and b minted before c failed; cleanups must unwind LIFO: b then a.
	want := []string{"b", "a"}
	if len(log) != 2 || log[0] != want[0] || log[1] != want[1] {
		t.Errorf("cleanup order = %v, want %v", log, want)
	}
}

func TestCleanupRunsLIFOOnce(t *testing.T) {
	var log []string
	a := &fakeProvider{name: "a", available: true, contrib: &Contribution{Cleanup: cleanupRecorder(&log, "a")}}
	b := &fakeProvider{name: "b", available: true, contrib: &Contribution{Cleanup: cleanupRecorder(&log, "b")}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.HasCleanup() {
		t.Fatal("HasCleanup should be true with two cleanup closures")
	}
	_ = res.Cleanup(context.Background())
	_ = res.Cleanup(context.Background()) // idempotent
	want := []string{"b", "a"}
	if len(log) != 2 || log[0] != want[0] || log[1] != want[1] {
		t.Errorf("cleanup order = %v, want %v (and must not run twice)", log, want)
	}
}

func TestApplyMergesMountsAndEnv(t *testing.T) {
	p := &fakeProvider{name: "p", available: true, contrib: &Contribution{
		Mounts: []sandbox.Mount{{Src: "/sock", Dst: "/sock"}},
		Env:    map[string]string{"FOO": "bar"},
	}}
	res, _ := Resolve(context.Background(), Session{}, []Active{{Provider: p}})
	spec := &sandbox.SandboxSpec{SetEnv: map[string]string{"HOME": "/home/u"}}
	if err := res.Apply(spec); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0].Dst != "/sock" {
		t.Errorf("mount not applied: %+v", spec.Mounts)
	}
	if spec.SetEnv["FOO"] != "bar" || spec.SetEnv["HOME"] != "/home/u" {
		t.Errorf("env merge wrong: %v", spec.SetEnv)
	}
}

func TestApplyRejectsEnvCollisionWithBaseline(t *testing.T) {
	p := &fakeProvider{name: "p", available: true, contrib: &Contribution{
		Env: map[string]string{"HOME": "/evil"},
	}}
	res, _ := Resolve(context.Background(), Session{}, []Active{{Provider: p}})
	spec := &sandbox.SandboxSpec{SetEnv: map[string]string{"HOME": "/home/u"}}
	err := res.Apply(spec)
	if err == nil {
		t.Fatal("expected collision error for env HOME already in baseline")
	}
	if spec.SetEnv["HOME"] != "/home/u" {
		t.Errorf("baseline env must not be mutated on rejection, got %q", spec.SetEnv["HOME"])
	}
}

func TestApplyRejectsMountCollisionAcrossProviders(t *testing.T) {
	a := &fakeProvider{name: "a", available: true, contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/d"}}}}
	b := &fakeProvider{name: "b", available: true, contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/d"}}}}
	res, _ := Resolve(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}})
	spec := &sandbox.SandboxSpec{}
	if err := res.Apply(spec); err == nil {
		t.Fatal("expected collision error for duplicate mount target across providers")
	}
	if len(spec.Mounts) != 0 {
		t.Errorf("spec must not be half-mutated on rejection, got %d mounts", len(spec.Mounts))
	}
}

func TestApplyRejectsMountInsideBlockedPath(t *testing.T) {
	p := &fakeProvider{name: "sneaky", available: true, contrib: &Contribution{
		Mounts: []sandbox.Mount{{Src: "/home/u/.ssh/agent.sock"}},
	}}
	res, _ := Resolve(context.Background(), Session{}, []Active{{Provider: p}})
	spec := &sandbox.SandboxSpec{BlockedPaths: []string{"/home/u/.ssh"}}
	if err := res.Apply(spec); err == nil {
		t.Fatal("expected error: provider mount inside a blocked-path mask would be silently shadowed")
	}
}

func TestApplyAllowsOverlayInsideBlockedPath(t *testing.T) {
	// An Overlay mount is the explicit exception: it is meant to land inside a
	// blocked path (re-granting a vetted file atop the emptied dir), so Apply must
	// not reject it the way it rejects an ordinary shadowed mount.
	p := &fakeProvider{name: "ssh", available: true, contrib: &Contribution{
		Mounts: []sandbox.Mount{{Src: "/host/cfg", Dst: "/home/u/.ssh/config", ReadOnly: true, Overlay: true}},
	}}
	res, _ := Resolve(context.Background(), Session{}, []Active{{Provider: p}})
	spec := &sandbox.SandboxSpec{BlockedPaths: []string{"/home/u/.ssh"}}
	if err := res.Apply(spec); err != nil {
		t.Fatalf("overlay mount inside a blocked path must be allowed: %v", err)
	}
	if findMount(spec.Mounts, "/home/u/.ssh/config") == nil {
		t.Errorf("overlay mount should be applied: %+v", spec.Mounts)
	}
	// A non-overlay mount in the same spot is still rejected (regression guard).
	p2 := &fakeProvider{name: "bad", available: true, contrib: &Contribution{
		Mounts: []sandbox.Mount{{Src: "/host/x", Dst: "/home/u/.ssh/x"}},
	}}
	res2, _ := Resolve(context.Background(), Session{}, []Active{{Provider: p2}})
	if err := res2.Apply(&sandbox.SandboxSpec{BlockedPaths: []string{"/home/u/.ssh"}}); err == nil {
		t.Error("a non-overlay mount inside a blocked path must still be rejected")
	}
}

func TestResolveHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before Resolve runs

	p := &fakeProvider{name: "should-not-run", available: true, contrib: &Contribution{}}
	res, err := Resolve(ctx, Session{}, []Active{{Provider: p}})
	if err == nil {
		t.Fatal("a canceled context must fail closed")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled, got %v", err)
	}
	if res != nil {
		t.Errorf("res must be nil on fail-closed, got %+v", res)
	}
}

// The fail-closed unwind must run on a fresh, live context: the launch ctx may be
// the very cancellation that failed the resolve, and reusing it would no-op the
// network teardowns and leak the already-minted credentials.
func TestResolveUnwindUsesFreshContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	unwindErr := errors.New("cleanup never ran")
	minted := &fakeProvider{name: "minted", available: true, contrib: &Contribution{
		Cleanup: func(c context.Context) error {
			unwindErr = c.Err() // nil iff the unwind ctx is live
			return nil
		},
	}}

	// The second Mint cancels the launch ctx and fails — modeling a cancellation
	// landing mid-mint. The deferred unwind must still tear minted down.
	res, err := Resolve(ctx, Session{}, []Active{
		{Provider: minted},
		{Provider: &cancelAndFail{cancel: cancel}},
	})
	if err == nil || res != nil {
		t.Fatalf("expected fail-closed resolve, got res=%+v err=%v", res, err)
	}
	if unwindErr != nil {
		t.Errorf("the unwind must receive a live context, got ctx.Err()=%v", unwindErr)
	}
}

// Cross-phase attribution: a phase-B collision with a phase-A contribution (a
// paths grant, an env.set pin) must name the owning provider, not "baseline" —
// phase A's Resolved rides into phase B's Apply as prior.
func TestApplyAttributionSurvivesPhases(t *testing.T) {
	phaseA := func(t *testing.T) (*Resolved, *sandbox.SandboxSpec) {
		t.Helper()
		a := &fakeProvider{name: "paths", available: true, contrib: &Contribution{RWPaths: []string{"/data"}}}
		b := &fakeProvider{name: "env", available: true, contrib: &Contribution{EnvSet: []EnvEntry{{Name: "FOO", Value: "pinned"}}}}
		res, err := Resolve(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}})
		if err != nil {
			t.Fatalf("phase A resolve: %v", err)
		}
		spec := &sandbox.SandboxSpec{}
		if err := res.Apply(spec); err != nil {
			t.Fatalf("phase A apply: %v", err)
		}
		return res, spec
	}

	t.Run("minted env vs env.set", func(t *testing.T) {
		prior, spec := phaseA(t)
		m := &fakeProvider{name: "gitlab", available: true, contrib: &Contribution{Env: map[string]string{"FOO": "minted"}}}
		res, err := Resolve(context.Background(), Session{}, []Active{{Provider: m}})
		if err != nil {
			t.Fatal(err)
		}
		aerr := res.Apply(spec, prior)
		if aerr == nil || !strings.Contains(aerr.Error(), `already provided by env (env.set)`) {
			t.Errorf("collision must name the env.set owner, got: %v", aerr)
		}
	})

	t.Run("mount vs paths grant", func(t *testing.T) {
		prior, spec := phaseA(t)
		m := &fakeProvider{name: "docker", available: true, contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/data"}}}}
		res, err := Resolve(context.Background(), Session{}, []Active{{Provider: m}})
		if err != nil {
			t.Fatal(err)
		}
		aerr := res.Apply(spec, prior)
		if aerr == nil || !strings.Contains(aerr.Error(), `already provided by paths`) {
			t.Errorf("collision must name the paths provider, got: %v", aerr)
		}
	})

	t.Run("without prior the label degrades to baseline", func(t *testing.T) {
		_, spec := phaseA(t)
		m := &fakeProvider{name: "docker", available: true, contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/data"}}}}
		res, err := Resolve(context.Background(), Session{}, []Active{{Provider: m}})
		if err != nil {
			t.Fatal(err)
		}
		aerr := res.Apply(spec)
		if aerr == nil || !strings.Contains(aerr.Error(), "already provided by baseline") {
			t.Errorf("without prior the seed label applies, got: %v", aerr)
		}
	})
}

// cancelAndFail cancels the launch context inside Mint and then errors.
type cancelAndFail struct{ cancel context.CancelFunc }

func (c *cancelAndFail) Name() string                   { return "cancel-and-fail" }
func (c *cancelAndFail) Available(context.Context) bool { return true }
func (c *cancelAndFail) Mint(context.Context, Session, bool) (*Contribution, error) {
	c.cancel()
	return nil, errors.New("mint interrupted by cancellation")
}

// Two providers each contribute an overlay to the same blocked-path directory (e.g.
// ssh re-adding ~/.ssh/config while another re-adds ~/.ssh/known_hosts). Apply must
// accept both (distinct destinations) and emit both.
func TestApplyAllowsMultipleOverlaysInSameBlockedPath(t *testing.T) {
	p1 := &fakeProvider{name: "ssh-cfg", available: true, contrib: &Contribution{
		Mounts: []sandbox.Mount{{Src: "/host/config", Dst: "/home/u/.ssh/config", ReadOnly: true, Overlay: true}},
	}}
	p2 := &fakeProvider{name: "ssh-known", available: true, contrib: &Contribution{
		Mounts: []sandbox.Mount{{Src: "/host/known_hosts", Dst: "/home/u/.ssh/known_hosts", ReadOnly: true, Overlay: true}},
	}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: p1}, {Provider: p2}})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	spec := &sandbox.SandboxSpec{BlockedPaths: []string{"/home/u/.ssh"}}
	if err := res.Apply(spec); err != nil {
		t.Fatalf("two overlays on the same blocked dir must be allowed: %v", err)
	}
	for _, dst := range []string{"/home/u/.ssh/config", "/home/u/.ssh/known_hosts"} {
		if findMount(spec.Mounts, dst) == nil {
			t.Errorf("overlay %q should be applied: %+v", dst, spec.Mounts)
		}
	}
	// Two overlays at the same destination is still a collision (fail closed).
	dup := &fakeProvider{name: "dup", available: true, contrib: &Contribution{
		Mounts: []sandbox.Mount{{Src: "/host/other", Dst: "/home/u/.ssh/config", ReadOnly: true, Overlay: true}},
	}}
	res2, _ := Resolve(context.Background(), Session{}, []Active{{Provider: p1}, {Provider: dup}})
	if err := res2.Apply(&sandbox.SandboxSpec{BlockedPaths: []string{"/home/u/.ssh"}}); err == nil {
		t.Error("two overlays at the same destination must collide (fail closed)")
	}
}

func TestApplyRejectsEmptyMount(t *testing.T) {
	// A mount with neither Src nor Dst would key collisions on "" — fail closed.
	p := &fakeProvider{name: "empty", available: true, contrib: &Contribution{
		Mounts: []sandbox.Mount{{}},
	}}
	res, _ := Resolve(context.Background(), Session{}, []Active{{Provider: p}})
	spec := &sandbox.SandboxSpec{}
	if err := res.Apply(spec); err == nil {
		t.Fatal("expected error for a mount with empty source and destination")
	}
	if len(spec.Mounts) != 0 {
		t.Errorf("spec must not be mutated on rejection, got %d mounts", len(spec.Mounts))
	}
}

func TestResolvePreviewFoldsExpandsNamesAndSkips(t *testing.T) {
	// A previewable provider (Mint succeeds under dryRun → folded in), a credential-minter
	// (Mint refuses dryRun with an error → named, not expanded), and an unavailable provider
	// (warned). ResolvePreview must call Mint with dryRun=true for the available ones.
	prev := &fakeProvider{name: "home", available: true,
		contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/corral/home"}},
			Status: []string{"private $HOME"}, AgentNotes: []string{"$HOME is sandbox-private"}}}
	minter := &fakeProvider{name: "gitlab", available: true,
		contrib:   &Contribution{Env: map[string]string{"GITLAB_TOKEN": "secret"}},
		dryRunErr: errors.New("cannot mint without a live API call")}
	gone := &fakeProvider{name: "docker", available: false}

	res, notExpanded, err := ResolvePreview(context.Background(), Session{},
		[]Active{{Provider: prev}, {Provider: minter}, {Provider: gone, Optional: true}})
	if err != nil {
		t.Fatalf("ResolvePreview: %v", err)
	}

	// Previewable provider folded in, with its Status surfaced as a prefixed notice.
	spec := &sandbox.SandboxSpec{}
	if err := res.Apply(spec); err != nil {
		t.Fatalf("Apply preview: %v", err)
	}
	if len(spec.Mounts) != 1 || spec.Mounts[0].Src != "/corral/home" {
		t.Errorf("previewable provider mount must be folded into the spec: %+v", spec.Mounts)
	}
	if len(res.Notices) != 1 || res.Notices[0] != (Notice{Provider: "home", Text: "private $HOME"}) {
		t.Errorf("preview should surface the provider Status as an attributed notice, got %v", res.Notices)
	}
	// The previewable provider's AgentNotes fold into the previewed env exactly as a
	// real launch would set them (the dry-run profile stays faithful).
	if got := spec.SetEnv[sandbox.ProviderNotesEnvVar]; got != "- home: $HOME is sandbox-private" {
		t.Errorf("preview should fold AgentNotes into %s, got %q", sandbox.ProviderNotesEnvVar, got)
	}
	// The credential-minter (its dryRun Mint errored) is named for the caller, not expanded —
	// and its secret env never reached the spec.
	if len(notExpanded) != 1 || notExpanded[0] != "gitlab" {
		t.Errorf("a minter whose dryRun Mint errors must be reported as not-expanded, got %v", notExpanded)
	}
	if _, leaked := spec.SetEnv["GITLAB_TOKEN"]; leaked {
		t.Error("a not-expanded minter's env must never reach the previewed spec")
	}
	// The unavailable provider is a skip warning (as Resolve would record).
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "docker") {
		t.Errorf("unavailable provider should be a skip warning, got %v", res.Warnings)
	}
	// A preview mints nothing → no teardown.
	if res.HasCleanup() {
		t.Error("a preview must register no cleanups")
	}
}

// Mounts exposes the folded mounts without an Apply, in provider order; a nil Resolved (a preview
// that failed) yields none.
func TestResolvedMounts(t *testing.T) {
	a := &fakeProvider{name: "docker", available: true,
		contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/run/docker.sock"}, {Src: "/home/u/.docker", ReadOnly: true}}}}
	b := &fakeProvider{name: "ssh", available: true,
		contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/home/u/.ssh/config", ReadOnly: true}}}}
	res, _, err := ResolvePreview(context.Background(), Session{}, []Active{{Provider: a}, {Provider: b}})
	if err != nil {
		t.Fatalf("ResolvePreview: %v", err)
	}
	var got []string
	for _, m := range res.Mounts() {
		got = append(got, m.Src)
	}
	if want := "/run/docker.sock,/home/u/.docker,/home/u/.ssh/config"; strings.Join(got, ",") != want {
		t.Errorf("Mounts() = %q, want %q", got, want)
	}
	if (*Resolved)(nil).Mounts() != nil {
		t.Error("a nil Resolved must yield no mounts")
	}
}

// Dry-run parity: a required (non-optional) provider unavailable on this host must
// make ResolvePreview return an error — a real launch would fail closed there, so the
// preview must not print a profile the launch could never assemble. The probe stays
// side-effect-free (no Mint ran), preserving the dry-run guarantee.
func TestResolvePreviewFailsClosedOnUnavailableRequired(t *testing.T) {
	gone := &fakeProvider{name: "kubernetes", available: false}
	res, notExpanded, err := ResolvePreview(context.Background(), Session{}, []Active{{Provider: gone}})
	if err == nil {
		t.Fatal("expected an error for a required unavailable provider in preview")
	}
	if res != nil || notExpanded != nil {
		t.Errorf("preview must return nil results on fail-closed, got res=%+v notExpanded=%v", res, notExpanded)
	}
}

// findMount returns the first mount whose Dst equals dst, or nil.
func findMount(ms []sandbox.Mount, dst string) *sandbox.Mount {
	for i := range ms {
		if ms[i].Dst == dst {
			return &ms[i]
		}
	}
	return nil
}

// --- built-in contribution channels (block/aiignore/paths/env conversion) ---

// A deny channel contributed by an earlier provider must be visible when a later
// provider's mount is validated — a feature mount inside a config-contributed block
// fails closed exactly as it did when config blocks were baked into the spec.
func TestApplyDenyChannelBlocksLaterMount(t *testing.T) {
	blocker := &fakeProvider{name: "block", available: true,
		contrib: &Contribution{BlockedDirs: []string{"/data/secrets"}}}
	feature := &fakeProvider{name: "docker", available: true,
		contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/data/secrets/sock"}}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: blocker}, {Provider: feature}})
	if err != nil {
		t.Fatal(err)
	}
	spec := &sandbox.SandboxSpec{}
	if err := res.Apply(spec); err == nil || !strings.Contains(err.Error(), "blocked path") {
		t.Fatalf("mount inside a contributed block must fail closed, got %v", err)
	}
}

// An Overlay mount stays exempt from a contributed deny channel (same exception as
// spec-level blocks: overlays exist to re-grant vetted files on top of a mask).
func TestApplyDenyChannelAllowsOverlay(t *testing.T) {
	blocker := &fakeProvider{name: "block", available: true,
		contrib: &Contribution{BlockedDirs: []string{"/home/u/.ssh"}}}
	feature := &fakeProvider{name: "ssh", available: true,
		contrib: &Contribution{Mounts: []sandbox.Mount{{Src: "/home/u/.ssh/config", Overlay: true, ReadOnly: true}}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: blocker}, {Provider: feature}})
	if err != nil {
		t.Fatal(err)
	}
	spec := &sandbox.SandboxSpec{}
	if err := res.Apply(spec); err != nil {
		t.Fatalf("overlay on a contributed block must be allowed: %v", err)
	}
	if !containsString(spec.BlockedPaths, "/home/u/.ssh") {
		t.Errorf("contributed block missing from spec: %v", spec.BlockedPaths)
	}
}

// Deny channels merge append-unique with blocks already in the spec.
func TestApplyDenyChannelAppendUnique(t *testing.T) {
	blocker := &fakeProvider{name: "block", available: true,
		contrib: &Contribution{BlockedDirs: []string{"/dup", "/new"}, BlockedFiles: []string{"/f/.env"}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: blocker}})
	if err != nil {
		t.Fatal(err)
	}
	spec := &sandbox.SandboxSpec{BlockedPaths: []string{"/dup"}}
	if err := res.Apply(spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.BlockedPaths) != 2 || spec.BlockedPaths[0] != "/dup" || spec.BlockedPaths[1] != "/new" {
		t.Errorf("append-unique merge broken: %v", spec.BlockedPaths)
	}
	if len(spec.BlockedFiles) != 1 || spec.BlockedFiles[0] != "/f/.env" {
		t.Errorf("blocked files not applied: %v", spec.BlockedFiles)
	}
}

// RW/RO path grants compile to same-path Optional mounts (missing paths skipped at
// launch) and, unlike minted feature mounts, may duplicate a baseline mount
// target: re-exposing a baseline path is the operator's deliberate, linted call.
func TestApplyPathChannelsAreOptionalAndCollisionExempt(t *testing.T) {
	paths := &fakeProvider{name: "paths", available: true,
		contrib: &Contribution{RWPaths: []string{"/srv/work", "/usr"}, ROPaths: []string{"/etc/ssl"}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: paths}})
	if err != nil {
		t.Fatal(err)
	}
	spec := &sandbox.SandboxSpec{Mounts: []sandbox.Mount{{Src: "/usr", ReadOnly: true}}} // baseline already exposes /usr
	if err := res.Apply(spec); err != nil {
		t.Fatalf("a paths grant over a baseline mount must not fail closed: %v", err)
	}
	var got []sandbox.Mount
	for _, m := range spec.Mounts {
		if m.Src == "/srv/work" || (m.Src == "/usr" && m.Optional) || m.Src == "/etc/ssl" {
			got = append(got, m)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 granted mounts, got %+v", spec.Mounts)
	}
	for _, m := range got {
		if !m.Optional || m.Dst != "" || m.Overlay {
			t.Errorf("path grant must be same-path + optional + non-overlay: %+v", m)
		}
	}
	if got[2].Src != "/etc/ssl" || !got[2].ReadOnly {
		t.Errorf("ro grant must be read-only: %+v", got[2])
	}
}

// EnvSet overrides warn (never fail) and land in Resolved.Warnings for the pre-mint
// gate; a fresh name sets silently.
func TestApplyEnvSetWarnsOnOverride(t *testing.T) {
	env := &fakeProvider{name: "env", available: true,
		contrib: &Contribution{EnvSet: []spec.EnvEntry{{Name: "TERM", Value: "dumb"}, {Name: "FRESH", Value: "x"}}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: env}})
	if err != nil {
		t.Fatal(err)
	}
	sb := &sandbox.SandboxSpec{SetEnv: map[string]string{"TERM": "xterm"}}
	if err := res.Apply(sb); err != nil {
		t.Fatal(err)
	}
	if sb.SetEnv["TERM"] != "dumb" || sb.SetEnv["FRESH"] != "x" {
		t.Errorf("env.set application broken: %v", sb.SetEnv)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], `"TERM" overrides`) {
		t.Errorf("override must produce exactly one advisory warning, got %v", res.Warnings)
	}
	// The warning names only the variable — neither the pinned nor the overridden
	// value may ride a warning (they land in the banner and logs).
	for _, v := range []string{"dumb", "xterm"} {
		if strings.Contains(res.Warnings[0], v) {
			t.Errorf("override warning must stay value-free, got %q", res.Warnings[0])
		}
	}
}

// A minted Env var colliding with a config-pinned EnvSet name fails closed and is
// attributed to the env.set claimant.
func TestApplyMintedEnvCollidesWithEnvSet(t *testing.T) {
	env := &fakeProvider{name: "env", available: true,
		contrib: &Contribution{EnvSet: []spec.EnvEntry{{Name: "GITLAB_TOKEN", Value: "pinned"}}}}
	minter := &fakeProvider{name: "gitlab", available: true,
		contrib: &Contribution{Env: map[string]string{"GITLAB_TOKEN": "minted"}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: env}, {Provider: minter}})
	if err != nil {
		t.Fatal(err)
	}
	sb := &sandbox.SandboxSpec{}
	err = res.Apply(sb)
	if err == nil || !strings.Contains(err.Error(), "env.set") {
		t.Fatalf("minted env over a pinned env.set name must fail closed with attribution, got %v", err)
	}
}

// Apply must append provider notes across two phases (built-ins pre-gate, feature
// providers post-gate) — the second Apply must not clobber the first's notes.
func TestApplyAppendsNotesAcrossPhases(t *testing.T) {
	first := &fakeProvider{name: "aiignore", available: true,
		contrib: &Contribution{AgentNotes: []string{"phase-a note"}}}
	second := &fakeProvider{name: "docker", available: true,
		contrib: &Contribution{AgentNotes: []string{"phase-b note"}}}
	sb := &sandbox.SandboxSpec{}
	resA, err := Resolve(context.Background(), Session{}, []Active{{Provider: first}})
	if err != nil {
		t.Fatal(err)
	}
	if err := resA.Apply(sb); err != nil {
		t.Fatal(err)
	}
	resB, err := Resolve(context.Background(), Session{}, []Active{{Provider: second}})
	if err != nil {
		t.Fatal(err)
	}
	if err := resB.Apply(sb); err != nil {
		t.Fatal(err)
	}
	want := "- aiignore: phase-a note\n- docker: phase-b note"
	if got := sb.SetEnv[sandbox.ProviderNotesEnvVar]; got != want {
		t.Errorf("notes must accumulate across phases: got %q want %q", got, want)
	}
}

// containsString reports whether list has an element equal to s.
func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Re-setting a key to the value it already has is not an override — no warning.
func TestApplyEnvSetSameValueNoWarn(t *testing.T) {
	env := &fakeProvider{name: "env", available: true,
		contrib: &Contribution{EnvSet: []spec.EnvEntry{{Name: "TERM", Value: "xterm"}}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: env}})
	if err != nil {
		t.Fatal(err)
	}
	sb := &sandbox.SandboxSpec{SetEnv: map[string]string{"TERM": "xterm"}}
	if err := res.Apply(sb); err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 0 {
		t.Errorf("same-value set must not warn: %v", res.Warnings)
	}
}

// Override warnings surface in declaration order (deterministic gate output).
func TestApplyEnvSetWarningsOrdered(t *testing.T) {
	env := &fakeProvider{name: "env", available: true,
		contrib: &Contribution{EnvSet: []spec.EnvEntry{
			{Name: "B_VAR", Value: "x"}, {Name: "A_VAR", Value: "y"},
		}}}
	res, err := Resolve(context.Background(), Session{}, []Active{{Provider: env}})
	if err != nil {
		t.Fatal(err)
	}
	sb := &sandbox.SandboxSpec{SetEnv: map[string]string{"B_VAR": "1", "A_VAR": "2"}}
	if err := res.Apply(sb); err != nil {
		t.Fatal(err)
	}
	if len(res.Warnings) != 2 || !strings.Contains(res.Warnings[0], "B_VAR") || !strings.Contains(res.Warnings[1], "A_VAR") {
		t.Errorf("warnings must follow declaration order: %v", res.Warnings)
	}
}

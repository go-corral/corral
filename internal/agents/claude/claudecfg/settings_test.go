package claudecfg

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

var update = flag.Bool("update", false, "regenerate golden files")

const testBinary = "/opt/corral/bin/corral"

func goldenCheck(t *testing.T, name string, got []byte) {
	t.Helper()
	golden := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run `go test -update`): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("mismatch with %s:\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
	}
}

func TestSyncFreshGolden(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("fresh sync should report changed=true")
	}
	goldenCheck(t, "sync_fresh.golden", rendered)

	// File on disk must match the rendered output.
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(rendered) {
		t.Error("on-disk file differs from rendered output")
	}
}

func TestSyncMergeGolden(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// Pre-existing settings: an unrelated top-level key, a PostToolUse hook,
	// and a PreToolUse group with a user's own (non-corral) command hook plus an
	// http hook carrying a field corral doesn't model.
	pre := `{
  "model": "opus",
  "permissions": {"deny": ["Read(./.env)"]},
  "hooks": {
    "PostToolUse": [
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "prettier"}]}
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/audit.sh"},
          {"type": "http", "url": "https://example.test/hook", "timeout": 5}
        ]
      }
    ]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("merge into fresh settings should change the file")
	}
	goldenCheck(t, "sync_merge.golden", rendered)

	// Spot-check preservation that the golden also encodes.
	var parsed map[string]any
	if err := json.Unmarshal(rendered, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["model"] != "opus" {
		t.Error("unrelated top-level key not preserved")
	}
	if !strings.Contains(string(rendered), "audit.sh") {
		t.Error("user's own PreToolUse hook not preserved")
	}
	if !strings.Contains(string(rendered), "example.test") {
		t.Error("http hook (unmodeled fields) not preserved")
	}
	if !strings.Contains(string(rendered), "PostToolUse") {
		t.Error("other hook event not preserved")
	}
}

func TestSyncIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, changed, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary}); err != nil || !changed {
		t.Fatalf("first sync: changed=%v err=%v", changed, err)
	}
	rendered2, changed2, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if changed2 {
		t.Error("second identical sync must report changed=false")
	}
	// Exactly one corral entry.
	if n := strings.Count(string(rendered2), hookSubcommand); n != 1 {
		t.Errorf("expected exactly 1 corral hook entry, found %d", n)
	}
}

// SessionStart (the sandbox-note injector) is registered alongside PreToolUse, with
// no matcher so it fires on every source, and stays singular + idempotent across
// re-syncs (the generalized corral-entry detection recognizes it as corral's own).
func TestSyncRegistersSessionStartHook(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	rendered, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	s := string(rendered)
	if !strings.Contains(s, `"SessionStart"`) {
		t.Errorf("SessionStart hook not registered:\n%s", s)
	}
	if n := strings.Count(s, hookSubcommandSessionStart); n != 1 {
		t.Errorf("expected exactly 1 session-start entry, got %d", n)
	}
	// The PreToolUse enforcer must still be there exactly once.
	if n := strings.Count(s, hookSubcommand); n != 1 {
		t.Errorf("expected exactly 1 pre-tool-use entry, got %d", n)
	}

	// Re-sync is idempotent: no change, and neither hook is duplicated.
	rendered2, changed2, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if changed2 {
		t.Error("second identical sync must report changed=false")
	}
	if n := strings.Count(string(rendered2), hookSubcommandSessionStart); n != 1 {
		t.Errorf("re-sync duplicated the session-start entry, got %d", n)
	}
}

func TestSyncRepointBinaryReplacesOldEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/old/path/corral"}); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/new/path/corral"})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("repointing the binary should change the file")
	}
	s := string(rendered)
	if strings.Contains(s, "/old/path/corral") {
		t.Error("old corral entry not removed")
	}
	if !strings.Contains(s, "/new/path/corral") {
		t.Error("new corral entry not present")
	}
	if n := strings.Count(s, hookSubcommand); n != 1 {
		t.Errorf("expected exactly 1 corral entry after repoint, got %d", n)
	}
}

func TestSyncRejectsMalformedWithoutClobbering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	bad := []byte("{ this is not json")
	if err := os.WriteFile(path, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary}); err == nil {
		t.Fatal("expected error on malformed settings.json")
	}
	// Original file must be untouched.
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(bad) {
		t.Error("malformed file was modified; sync must not clobber on error")
	}
}

func TestSyncPreservesLookalikeUserHooks(t *testing.T) {
	// User hooks whose commands merely contain "corral" / "hook pre-tool-use"
	// substrings must not be misidentified as corral-owned and deleted.
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	pre := `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/corral-wrapper hook pre-tool-use audit"},
          {"type": "command", "command": "/opt/my-corral hook pre-tool-use"},
          {"type": "command", "command": "echo corral hook pre-tool-use done"},
          {"type": "command", "command": "env FOO=1 /usr/bin/corral hook pre-tool-use"},
          {"type": "command", "command": "nice -n 5 /usr/bin/corral hook pre-tool-use"},
          {"type": "command", "command": "/usr/bin/timeout 5 /opt/bin/corral hook pre-tool-use"},
          {"command": "/no/type/corral hook pre-tool-use"}
        ]
      }
    ]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	// Run sync twice; lookalikes must survive both rounds (idempotency too).
	for i := 0; i < 2; i++ {
		if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/opt/corral/bin/corral"}); err != nil {
			t.Fatalf("sync round %d: %v", i, err)
		}
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		"/usr/local/bin/corral-wrapper hook pre-tool-use audit", // trailing arg
		"/opt/my-corral hook pre-tool-use",                      // base name not "corral"
		"echo corral hook pre-tool-use done",                    // not a corral binary
		"env FOO=1 /usr/bin/corral hook pre-tool-use",           // wrapper prefix (Base() alone would match)
		"nice -n 5 /usr/bin/corral hook pre-tool-use",           // wrapper prefix
		"/usr/bin/timeout 5 /opt/bin/corral hook pre-tool-use",  // wrapper prefix
		"/no/type/corral hook pre-tool-use",                     // missing type field
	} {
		if !strings.Contains(s, want) {
			t.Errorf("user lookalike hook was clobbered (missing): %q\n%s", want, s)
		}
	}
	// Exactly one genuine corral entry, regardless of how many times we synced. Compare against
	// the JSON-encoded command (the file escapes the guard's inner quotes).
	wantCmd, err := marshalNoEscape(guardedCommand(testBinary, "hook pre-tool-use"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(s, string(wantCmd)); n != 1 {
		t.Errorf("expected exactly 1 corral entry, got %d\n%s", n, s)
	}
}

// TestGuardedCommandShape pins the shell structure that preserves fail-closed exit status.
func TestGuardedCommandShape(t *testing.T) {
	cmd := guardedCommand(testBinary, hookSubcommand)

	for _, want := range []string{
		`if [ -x "` + testBinary + `" ]; then`,        // existence guard, path quoted
		`exec "` + testBinary + `" ` + hookSubcommand, // exec: corral's exit status reaches Claude Code
		`elif [ -n "$CORRAL_SANDBOX" ]; then`,         // the in-sandbox arm
		`exit 2`,                                      // fail closed there
	} {
		if !strings.Contains(cmd, want) {
			t.Errorf("guarded command is missing %q:\n%s", want, cmd)
		}
	}
	// A `|| true` (or `&&` chain) would swallow corral's exit 2 and turn the gate into a no-op.
	for _, forbidden := range []string{"|| true", "||", "&&"} {
		if strings.Contains(cmd, forbidden) {
			t.Errorf("guarded command must not contain %q (it would swallow the fail-closed exit): %s", forbidden, cmd)
		}
	}
	// The command must be a no-op outside the sandbox: the only exit-2 path is behind the
	// marker test, so a foreign sandbox sees the `if` fall through (POSIX: status 0).
	if strings.Index(cmd, "elif") > strings.Index(cmd, "exit 2") {
		t.Error("exit 2 must come after the marker guard, never before it")
	}
}

// TestGuardedCommandHasNoStrayShellActiveChars: the command is interpolated into a
// double-quoted `sh` string, where `$` and a backtick stay active. Only the one intended `$`
// (the marker expansion) may appear, and no backtick at all — otherwise corral's own message
// or path would be expanded, or a command substitution would run, on every hook invocation.
func TestGuardedCommandHasNoStrayShellActiveChars(t *testing.T) {
	cmd := guardedCommand(testBinary, hookSubcommand)
	if strings.Contains(cmd, "`") {
		t.Errorf("guarded command contains a backtick (command substitution): %s", cmd)
	}
	if n := strings.Count(cmd, "$"); n != 1 {
		t.Errorf("guarded command must contain exactly one $ (the %s expansion), got %d: %s", sandbox.SandboxEnvVar, n, cmd)
	}
	if !strings.Contains(cmd, `"$`+sandbox.SandboxEnvVar+`"`) {
		t.Errorf("the only $ must be the marker expansion: %s", cmd)
	}
	// The message itself must be inert: it lands inside the same quoted string.
	if strings.ContainsAny(guardedMessage, "\"$`\\") {
		t.Errorf("guardedMessage carries a shell-active character: %q", guardedMessage)
	}
}

// TestGuardedCommandRoundTrip: what guardedCommand writes, parseGuardedCommand must read back
// for every subcommand — the property that keeps a re-sync idempotent instead of appending a
// duplicate beside each existing entry.
func TestGuardedCommandRoundTrip(t *testing.T) {
	for _, sub := range corralHookSubcommands {
		cmd := guardedCommand(testBinary, sub)
		bin, gotSub, ok := parseGuardedCommand(cmd)
		if !ok {
			t.Errorf("parseGuardedCommand rejected corral's own command for %q:\n%s", sub, cmd)
			continue
		}
		if bin != testBinary || gotSub != sub {
			t.Errorf("round-trip mismatch: got (%q, %q), want (%q, %q)", bin, gotSub, testBinary, sub)
		}
	}
	// A space-containing path (inert inside the quotes) must round-trip too.
	spaced := "/home/u/My Tools/corral"
	if bin, _, ok := parseGuardedCommand(guardedCommand(spaced, hookSubcommand)); !ok || bin != spaced {
		t.Errorf("space-containing path did not round-trip: got %q ok=%v", bin, ok)
	}
}

// TestParseGuardedCommandRejectsNearMisses: shapes that are not corral's registration must not
// be recognized as it — otherwise a sync would replace, and a removal delete, a user's own hook.
func TestParseGuardedCommandRejectsNearMisses(t *testing.T) {
	for name, cmd := range map[string]string{
		"tail swallows exit":   `if [ -x "/o/corral" ]; then exec "/o/corral" hook pre-tool-use; elif [ -n "$CORRAL_SANDBOX" ]; then echo "x" >&2; exit 2; fi || true`,
		"mismatched binaries":  `if [ -x "/o/corral" ]; then exec "/other/corral" hook pre-tool-use; elif [ -n "$CORRAL_SANDBOX" ]; then echo "x" >&2; exit 2; fi`,
		"base name not corral": `if [ -x "/o/my-corral" ]; then exec "/o/my-corral" hook pre-tool-use; elif [ -n "$CORRAL_SANDBOX" ]; then echo "x" >&2; exit 2; fi`,
		"unknown subcommand":   `if [ -x "/o/corral" ]; then exec "/o/corral" hook something-else; elif [ -n "$CORRAL_SANDBOX" ]; then echo "x" >&2; exit 2; fi`,
		"no exec":              `if [ -x "/o/corral" ]; then "/o/corral" hook pre-tool-use; elif [ -n "$CORRAL_SANDBOX" ]; then echo "x" >&2; exit 2; fi`,
		"different marker":     `if [ -x "/o/corral" ]; then exec "/o/corral" hook pre-tool-use; elif [ -n "$SOME_OTHER" ]; then echo "x" >&2; exit 2; fi`,
		"exit 0 not 2":         `if [ -x "/o/corral" ]; then exec "/o/corral" hook pre-tool-use; elif [ -n "$CORRAL_SANDBOX" ]; then echo "x" >&2; exit 0; fi`,
		"leading wrapper":      `env FOO=1 if [ -x "/o/corral" ]; then exec "/o/corral" hook pre-tool-use; elif [ -n "$CORRAL_SANDBOX" ]; then echo "x" >&2; exit 2; fi`,
	} {
		if _, _, ok := parseGuardedCommand(cmd); ok {
			t.Errorf("%s: parseGuardedCommand must NOT claim this command:\n%s", name, cmd)
		}
	}
}

// TestSyncMigratesBareRegistration ensures unguarded commands are replaced, not duplicated.
func TestSyncMigratesBareRegistration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// Bare corral commands plus a user hook that must survive.
	pre := `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/old/path/corral hook pre-tool-use", "timeout": 10}]},
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/home/u/audit.sh"}]}
    ],
    "PostToolUse": [{"matcher": "Bash|Grep|mcp__.*", "hooks": [{"type": "command", "command": "/old/path/corral hook post-tool-use", "timeout": 10}]}],
    "SessionStart": [{"hooks": [{"type": "command", "command": "/old/path/corral hook session-start", "timeout": 10}]}],
    "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "/old/path/corral hook user-prompt-submit", "timeout": 10}]}]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary}); err != nil || !changed {
		t.Fatalf("migration sync: changed=%v err=%v", changed, err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)

	// No bare corral command survives anywhere.
	if strings.Contains(s, "/old/path/corral hook") {
		t.Errorf("a legacy bare corral entry survived the migration:\n%s", s)
	}
	// Exactly one guarded entry per event, pointing at the new binary.
	for _, sub := range corralHookSubcommands {
		wantCmd, merr := marshalNoEscape(guardedCommand(testBinary, sub))
		if merr != nil {
			t.Fatal(merr)
		}
		if n := strings.Count(s, string(wantCmd)); n != 1 {
			t.Errorf("want exactly 1 guarded entry for %q, got %d\n%s", sub, n, s)
		}
	}
	// The user's own hook is untouched.
	if !strings.Contains(s, "/home/u/audit.sh") {
		t.Errorf("migration dropped the user's own hook:\n%s", s)
	}
	// Idempotent: a second run changes nothing at all.
	rendered2, changed2, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if changed2 {
		t.Errorf("second sync after migration reported changed:\n%s", rendered2)
	}
}

// TestRemoveStripsBothShapes removes guarded and bare corral commands without touching user hooks.
func TestRemoveStripsBothShapes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	otherGuarded := guardedCommand("/some/other/place/corral", hookSubcommand)
	pre := `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "*", "hooks": [
        {"type": "command", "command": ` + mustJSON(t, guardedCommand(testBinary, hookSubcommand)) + `, "timeout": 10},
        {"type": "command", "command": ` + mustJSON(t, otherGuarded) + `, "timeout": 10},
        {"type": "command", "command": "/legacy/corral hook pre-tool-use", "timeout": 10},
        {"type": "command", "command": "/home/u/mine.sh"}
      ]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("removal should have stripped corral's entries")
	}
	s := string(rendered)
	for _, gone := range []string{testBinary, "/some/other/place/corral", "/legacy/corral"} {
		if strings.Contains(s, gone) {
			t.Errorf("removal left a corral entry naming %q:\n%s", gone, s)
		}
	}
	if !strings.Contains(s, "/home/u/mine.sh") {
		t.Errorf("removal clobbered the user's own hook:\n%s", s)
	}
}

// mustJSON encodes v as a JSON string literal for embedding in a fixture.
func mustJSON(t *testing.T, v string) string {
	t.Helper()
	b, err := marshalNoEscape(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSyncRejectsUnsafeBinaryPath: paths that cannot be embedded safely in the persisted
// shell command must fail the sync loudly and leave the file untouched — never persist a
// registration that the shell would expand (or that the parse side cannot recognize back).
func TestSyncRejectsUnsafeBinaryPath(t *testing.T) {
	for _, tc := range []struct {
		name, binary string
	}{
		{"dollar", "/home/u$er/bin/corral"},
		{"backtick", "/home/u/`whoami`/corral"},
		{"quote", `/home/u"q/bin/corral`},
		{"backslash", `/home/u\q/bin/corral`},
		{"newline", "/home/u\nq/bin/corral"},
		{"control", "/home/u\x07q/bin/corral"},
		{"relative", "bin/corral"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "settings.json")
			pre := `{"permissions":{"allow":["Read(/tmp/**)"]}}`
			if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: tc.binary}); err == nil {
				t.Fatalf("Sync accepted unsafe binary path %q", tc.binary)
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != pre {
				t.Errorf("settings.json modified despite rejected binary path:\n%s", after)
			}
		})
	}
}

// TestSyncAcceptsSpaceInBinaryPath: a space is not shell-active inside the quoted command,
// so an install dir like "~/My Tools" must keep working.
func TestSyncAcceptsSpaceInBinaryPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/home/u/My Tools/corral"}); err != nil {
		t.Fatalf("Sync rejected a space-containing path: %v", err)
	}
}

func TestSyncAtomicWriteOverExisting(t *testing.T) {
	// A second sync that changes content must replace the file atomically and
	// leave valid JSON (regression guard for the atomicWrite path).
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/a/corral"}); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: "/b/corral"}); err != nil || !changed {
		t.Fatalf("repoint sync: changed=%v err=%v", changed, err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatalf("settings.json corrupt after atomic write: %v", err)
	}
	// No stray temp files left behind in the directory.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".corral-settings-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestSyncLeavesDenyUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	pre := `{"permissions":{"allow":["Read(/tmp/**)"],"deny":["Read(/custom/**)","Read(//home/u/.ssh/**)"]}}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("first sync registers hooks, so it must report changed=true")
	}
	s := string(rendered)
	// Every pre-existing permission entry survives verbatim — corral adds and removes nothing.
	for _, want := range []string{`Read(/tmp/**)`, `Read(/custom/**)`, `Read(//home/u/.ssh/**)`} {
		if !strings.Contains(s, want) {
			t.Errorf("existing permission %q must be preserved, missing in:\n%s", want, s)
		}
	}
	// corral writes no deny globs of its own.
	if strings.Contains(s, `Read(//home/u/.gnupg/**)`) || strings.Contains(s, `Write(//home/u/.ssh/**)`) {
		t.Errorf("corral must not add any deny glob:\n%s", s)
	}
	// Idempotent: a second sync changes nothing.
	_, changed2, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if changed2 {
		t.Error("a second sync over an already-synced file must be a no-op")
	}
}

// TestSyncMultipleRoundsLeaveDenyUntouched: repeated syncs (even after the user edits their
// own deny rules between runs) never alter the deny list — corral only ever touches hooks.
func TestSyncMultipleRoundsLeaveDenyUntouched(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	pre := `{"permissions":{"deny":["Read(/my/secret/**)"]}}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered1, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rendered1), `Read(/my/secret/**)`) {
		t.Errorf("user deny must survive the first sync:\n%s", rendered1)
	}

	// The user adds their own deny rule between syncs; corral must preserve it on the next run.
	grown := `{"permissions":{"deny":["Read(/my/secret/**)","Read(/another/**)"]}}`
	if err := os.WriteFile(path, []byte(grown), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered2, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	s2 := string(rendered2)
	for _, want := range []string{`Read(/my/secret/**)`, `Read(/another/**)`} {
		if !strings.Contains(s2, want) {
			t.Errorf("user deny %q must be preserved across syncs:\n%s", want, s2)
		}
	}
}

func TestSyncHandlesNullFields(t *testing.T) {
	// Degenerate-but-valid JSON (explicit nulls, or a null document) must be handled as
	// empty, not panic the merge (assignment to a nil map).
	for _, pre := range []string{
		`null`,
		`{"permissions": null}`,
		`{"hooks": null}`,
		`{"permissions": null, "hooks": null}`,
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "settings.json")
		if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
			t.Fatal(err)
		}
		rendered, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
		if err != nil {
			t.Fatalf("input %q: unexpected error %v", pre, err)
		}
		var v any
		if err := json.Unmarshal(rendered, &v); err != nil {
			t.Fatalf("input %q produced invalid JSON: %v", pre, err)
		}
		if !strings.Contains(string(rendered), hookSubcommand) {
			t.Errorf("input %q: hook not registered:\n%s", pre, rendered)
		}
	}
}

// TestRemoveFreshGolden pins the inverse of TestSyncFreshGolden: removing corral's hooks from a
// file corral alone wrote leaves an empty object — the "hooks" key goes too, since an empty hooks
// object would be a husk encoding nothing.
func TestRemoveFreshGolden(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary}); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("removing registered hooks should report changed=true")
	}
	goldenCheck(t, "remove_fresh.golden", rendered)

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != string(rendered) {
		t.Error("on-disk file differs from rendered output")
	}
}

// TestRemoveMergeGolden pins removal's conservatism on a file corral shares with the user: only
// corral's own entries go. It covers every structural case at once — a group corral owns alone
// (dropped), a group it shares with a user entry (kept, minus corral's entry), an event where
// corral was the only content (key deleted), an unrelated hook event, and a corral-shaped entry
// under an event corral never registers (Notification: user-authored by definition, so it must
// ride through verbatim).
func TestRemoveMergeGolden(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	pre := `{
  "model": "opus",
  "permissions": {"deny": ["Read(./.env)"]},
  "hooks": {
    "Notification": [
      {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/corral/bin/corral hook pre-tool-use"}]}
    ],
    "PostToolUse": [
      {"matcher": "Edit", "hooks": [{"type": "command", "command": "prettier"}]},
      {"matcher": "Bash|Grep|mcp__.*", "hooks": [{"type": "command", "command": "/opt/corral/bin/corral hook post-tool-use", "timeout": 10}]}
    ],
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/audit.sh"},
          {"type": "command", "command": "/opt/corral/bin/corral hook pre-tool-use", "timeout": 10},
          {"type": "http", "url": "https://example.test/hook", "timeout": 5}
        ]
      },
      {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/corral/bin/corral hook pre-tool-use", "timeout": 10}]}
    ],
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "/opt/corral/bin/corral hook session-start", "timeout": 10}]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("removing corral's entries from a merged file must report changed=true")
	}
	goldenCheck(t, "remove_merge.golden", rendered)

	// Spot-check what the golden encodes, so a mis-regenerated golden still fails loudly.
	s := string(rendered)
	for _, want := range []string{
		`"model": "opus"`,         // unrelated top-level key
		`Read(./.env)`,            // the permissions block corral never touches
		`/usr/local/bin/audit.sh`, // user entry in a group shared with corral
		`example.test`,            // http entry (fields corral doesn't model) in that group
		`prettier`,                // user entry under an event corral also registers
		`"Notification"`,          // an event corral never writes...
		`hook pre-tool-use"`,      // ...keeps its corral-shaped (user-authored) entry
	} {
		if !strings.Contains(s, want) {
			t.Errorf("removal clobbered user content (missing %q):\n%s", want, s)
		}
	}
	// corral's own registrations are gone: only the Notification lookalike may still name a
	// corral subcommand, and the two events corral alone occupied lost their keys.
	if n := strings.Count(s, hookSubcommand); n != 1 {
		t.Errorf("expected exactly 1 remaining (user-authored) pre-tool-use entry, got %d:\n%s", n, s)
	}
	for _, gone := range []string{hookSubcommandPostToolUse, hookSubcommandSessionStart, `"SessionStart"`} {
		if strings.Contains(s, gone) {
			t.Errorf("removal left %q behind:\n%s", gone, s)
		}
	}
}

// TestRemoveWithoutCorralHooksDoesNotRewrite pins the asymmetry with a regular sync: a removal
// that finds nothing of corral's leaves the file byte-identical instead of canonicalizing it. The
// fixture is deliberately non-canonical (4-space indent, unsorted keys), so a stray reformat-only
// rewrite from `changed = !bytes.Equal(...)` is detectable.
func TestRemoveWithoutCorralHooksDoesNotRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	pre := `{
    "model": "opus",
    "hooks": {
        "PreToolUse": [
            {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/audit.sh"}]}
        ]
    }
}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	_, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("a removal with no corral hooks to strip must report changed=false")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != pre {
		t.Errorf("removal must not rewrite (or reformat) a file it strips nothing from:\n--- got ---\n%s\n--- want ---\n%s", after, pre)
	}
}

// TestRemoveMissingFile: de-registering from a settings.json that does not exist is a silent
// no-op. In particular it must not create the file it was asked to clean up.
func TestRemoveMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "settings.json")
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatalf("removal on a missing file must not error: %v", err)
	}
	if changed {
		t.Error("removal on a missing file must report changed=false")
	}
	if len(rendered) != 0 {
		t.Errorf("removal on a missing file should render nothing, got %q", rendered)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("removal must not create the settings file (stat err = %v)", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
		t.Errorf("removal must not create the settings dir (stat err = %v)", err)
	}
}

// TestRemovePreservesLookalikeUserHooks is the removal-side twin of
// TestSyncPreservesLookalikeUserHooks: the same near-miss commands a sync must not strip must
// survive an explicit `--remove` too. Removal deletes corral's registration, never a user hook
// that merely reads like one.
func TestRemovePreservesLookalikeUserHooks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	pre := `{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {"type": "command", "command": "/usr/local/bin/corral-wrapper hook pre-tool-use audit"},
          {"type": "command", "command": "/opt/my-corral hook pre-tool-use"},
          {"type": "command", "command": "echo corral hook pre-tool-use done"},
          {"type": "command", "command": "env FOO=1 /usr/bin/corral hook pre-tool-use"},
          {"type": "command", "command": "nice -n 5 /usr/bin/corral hook pre-tool-use"},
          {"type": "command", "command": "/usr/bin/timeout 5 /opt/bin/corral hook pre-tool-use"},
          {"command": "/no/type/corral hook pre-tool-use"}
        ]
      }
    ]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	// Register corral's own hooks first, so removal has something real to strip alongside the
	// lookalikes (the interesting case: it must tell them apart, not just leave everything).
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary}); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("removal should have stripped corral's own registration")
	}
	s := string(rendered)
	for _, want := range []string{
		"/usr/local/bin/corral-wrapper hook pre-tool-use audit", // trailing arg
		"/opt/my-corral hook pre-tool-use",                      // base name not "corral"
		"echo corral hook pre-tool-use done",                    // not a corral binary
		"env FOO=1 /usr/bin/corral hook pre-tool-use",           // wrapper prefix (Base() alone would match)
		"nice -n 5 /usr/bin/corral hook pre-tool-use",           // wrapper prefix
		"/usr/bin/timeout 5 /opt/bin/corral hook pre-tool-use",  // wrapper prefix
		"/no/type/corral hook pre-tool-use",                     // missing type field
	} {
		if !strings.Contains(s, want) {
			t.Errorf("removal clobbered a user lookalike hook (missing): %q\n%s", want, s)
		}
	}
	if strings.Contains(s, testBinary) {
		t.Errorf("corral's own registration survived the removal:\n%s", s)
	}
}

// TestRemovePreservesPreExistingEmptyStructures: an empty matcher group ("hooks": []) and an
// empty top-level "hooks" object are user content. corral writes neither, so removal leaves
// both alone. Only a group corral itself emptied by stripping is dropped, and only a hooks map
// corral itself emptied loses its key.
func TestRemovePreservesPreExistingEmptyStructures(t *testing.T) {
	// An empty group sharing an event with corral's own group: the group survives, empty.
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	pre := `{
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": []},
      {"matcher": "*", "hooks": [{"type": "command", "command": "/opt/corral/bin/corral hook pre-tool-use", "timeout": 10}]}
    ]
  }
}`
	if err := os.WriteFile(path, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("removal should have stripped corral's group")
	}
	if s := string(rendered); !strings.Contains(s, `"matcher": "Bash"`) || !strings.Contains(s, `"hooks": []`) {
		t.Errorf("a pre-existing empty group must survive removal:\n%s", s)
	}

	// An empty top-level hooks object with nothing to strip: kept verbatim, file not rewritten.
	empty := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(empty, []byte(`{"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	rendered, changed, err = Sync(SyncOptions{SettingsPath: empty, Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error(`an empty "hooks" object holds nothing of corral's, so removal must report changed=false`)
	}
	if !strings.Contains(string(rendered), `"hooks": {}`) {
		t.Errorf("a pre-existing empty \"hooks\" object must not be deleted:\n%s", rendered)
	}
	if after, _ := os.ReadFile(empty); string(after) != `{"hooks":{}}` {
		t.Errorf("file must not be rewritten, got: %s", after)
	}
}

// TestRemoveDryRunDoesNotWrite: a dry-run removal reports the change and renders the stripped
// output, but the file on disk keeps its hooks.
func TestRemoveDryRunDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	synced, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	rendered, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("a dry-run removal with hooks present should report changed=true")
	}
	if strings.Contains(string(rendered), hookSubcommand) {
		t.Errorf("dry-run removal should render the stripped output:\n%s", rendered)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(synced) {
		t.Errorf("dry-run removal must leave the file untouched:\n%s", after)
	}
}

// TestRemoveIdempotent: removing twice is safe — the second run finds nothing left of corral's,
// reports changed=false, and does not rewrite the file.
func TestRemoveIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if _, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary}); err != nil {
		t.Fatal(err)
	}
	if _, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true}); err != nil || !changed {
		t.Fatalf("first removal: changed=%v err=%v", changed, err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := Sync(SyncOptions{SettingsPath: path, Remove: true}); err != nil || changed {
		t.Fatalf("second removal must be a no-op: changed=%v err=%v", changed, err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(second) != string(first) {
		t.Errorf("a second removal must not touch the file:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
}

// TestRemoveReRegisterRoundTrip: removal is reversible — `corral sync` after a `--remove`
// restores exactly the registration it stripped, so de-registering is never a one-way door.
func TestRemoveReRegisterRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	synced, _, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sync(SyncOptions{SettingsPath: path, Remove: true}); err != nil {
		t.Fatal(err)
	}
	again, changed, err := Sync(SyncOptions{SettingsPath: path, BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("re-syncing after a removal must report changed=true")
	}
	if string(again) != string(synced) {
		t.Errorf("re-sync should restore the original registration byte-for-byte:\n--- got ---\n%s\n--- want ---\n%s", again, synced)
	}
}

// TestRemoveRejectsMalformedWithoutClobbering: the removal path refuses a settings.json it
// cannot parse rather than rewriting what it could not fully read — same stance as sync.
func TestRemoveRejectsMalformedWithoutClobbering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	// Valid JSON object, but hooks.PreToolUse is not the array of groups it must be.
	bad := []byte(`{"hooks": {"PreToolUse": "not an array"}}`)
	if err := os.WriteFile(path, bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Sync(SyncOptions{SettingsPath: path, Remove: true}); err == nil {
		t.Fatal("expected an error on a hooks event of the wrong shape")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(bad) {
		t.Error("malformed file was modified; removal must not clobber on error")
	}
}

func TestRenderIsValidJSON(t *testing.T) {
	rendered, _, err := Sync(SyncOptions{SettingsPath: filepath.Join(t.TempDir(), "s.json"), BinaryPath: testBinary})
	if err != nil {
		t.Fatal(err)
	}
	var v any
	if err := json.Unmarshal(rendered, &v); err != nil {
		t.Fatalf("rendered output is not valid JSON: %v", err)
	}
}

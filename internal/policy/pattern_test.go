package policy

import (
	"errors"
	"io/fs"
	"runtime"
	"strings"
	"testing"
)

// evalOrSkip runs r.Evaluate and skips the (sub)test when canonicalize is denied
// lstat of the system ancestors it must walk — which happens only when the suite
// runs inside a nested corral sandbox that masks /home and /private/etc. The assertion
// is meaningful only where those paths are stat-able (CI Linux, or a dev box
// outside the sandbox, e.g. via scripts/m3-etc-verify.sh). A non-permission error
// stays fatal, so genuine fail-closed regressions still surface; production keeps
// using strict Canonicalize and correctly fails closed on this same EPERM.
func evalOrSkip(t *testing.T, r *PathPatternRule, ev *HookEvent) (Decision, bool) {
	t.Helper()
	d, matched, err := r.Evaluate(ev)
	if errors.Is(err, fs.ErrPermission) {
		t.Skipf("environment denies lstat needed by canonicalize (%v); run outside the sandbox", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return d, matched
}

func TestPathPatternRuleReadDenies(t *testing.T) {
	r := &PathPatternRule{}
	cases := []struct{ name, path string }{
		{"dotenv", "/home/u/project/.env"},
		{"dotenv-prod", "/home/u/project/.env.production"},
		{"envrc", "/home/u/.envrc"},
		{"pem", "/home/u/certs/server.pem"},
		{"key", "/home/u/certs/tls.key"},
		{"p12", "/home/u/bundle.p12"},
		{"gpg", "/home/u/secret.gpg"},
		{"netrc", "/home/u/.netrc"},
		{"etc-shadow", "/etc/shadow"},
		{"secret-named", "/home/u/cfg/credentials.json"},
		{"password-named", "/home/u/passwords.txt"},
		{"kdbx", "/home/u/vault.kdbx"},
		{"ssh-component-nonhome", "/srv/deploy/.ssh/id_rsa"},
		{"gnupg-component-nonhome", "/srv/.gnupg/secring.gpg"},
		{"kube-component-nonhome", "/srv/deploy/.kube/config"},
		{"azure-component", "/home/u/.azure/msal_token_cache.json"},
		{"gcloud-anchored", "/home/u/.config/gcloud/credentials.db"},
		{"git-credentials", "/home/u/.git-credentials"},
		{"git-credentials-xdg", "/home/u/.config/git/credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, matched := evalOrSkip(t, r, toolEvent(t, "Read", map[string]any{"file_path": tc.path}))
			if !matched || d.Action != Deny {
				t.Errorf("expected DENY reading %q; matched=%v", tc.path, matched)
			}
		})
	}
}

func TestPathPatternRuleReadAllows(t *testing.T) {
	r := &PathPatternRule{}
	cases := []string{
		"/home/u/project/main.go",
		"/home/u/project/README.md",
		"/etc/hosts",                  // under /etc but not a credential file (read)
		"/home/u/project/config.yaml", // not credential-named
		"/home/u/notes/cert-notes.md",
		"/home/u/certs/ca-certificates.crt", // public cert — not a secret
		"/home/u/project/.env.example",      // committed template
		"/home/u/project/gcloud/main.go",    // vendored gcloud/ dir — only .config/gcloud is a credential store
		"/home/u/project/kube/deploy.yaml",  // undotted kube/ dir — only .kube is
		"/home/u/.config/git/config",        // git config next to the credential store stays readable
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			_, matched := evalOrSkip(t, r, toolEvent(t, "Read", map[string]any{"file_path": p}))
			if matched {
				t.Errorf("expected ALLOW reading %q", p)
			}
		})
	}
}

func TestPathPatternRuleWriteGuards(t *testing.T) {
	r := &PathPatternRule{AgentConfigDir: "/home/u/.claude", Footprint: claudeFootprint(), AllFootprints: allTestFootprints()}
	cases := []struct{ name, tool, path string }{
		{"write-etc", "Write", "/etc/cron.d/job"},  // whole /etc is write-blocked
		{"edit-etc-noncred", "Edit", "/etc/hosts"}, // even a non-credential /etc file
		{"self-settings", "Edit", "/home/u/.claude/settings.json"},
		{"self-settings-local", "Edit", "/home/u/.claude/settings.local.json"},
		{"self-managed-settings", "Write", "/home/u/.claude/managed-settings.json"},
		{"self-hooks", "Write", "/home/u/.claude/hooks/x.sh"},
		{"write-pem", "Write", "/home/u/a.pem"},
		{"write-dotenv", "Write", "/home/u/svc/.env"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, matched := evalOrSkip(t, r, toolEvent(t, tc.tool, map[string]any{"file_path": tc.path}))
			if !matched || d.Action != Deny {
				t.Errorf("expected DENY %s %q; matched=%v", tc.tool, tc.path, matched)
			}
		})
	}
}

func TestPathPatternRuleSelfProtectFallbackComponent(t *testing.T) {
	// Even when the configured dir differs, a `.claude/settings.json` path is
	// self-protected via the defense-in-depth static path-segment scan (allFootprints).
	r := &PathPatternRule{AgentConfigDir: "/some/other/dir", AllFootprints: allTestFootprints()}
	d, matched := evalOrSkip(t, r, toolEvent(t, "Edit", map[string]any{"file_path": "/home/u/.claude/settings.json"}))
	if !matched || d.Action != Deny {
		t.Errorf("`.claude/settings.json` must be self-protected via fallback; matched=%v", matched)
	}
}

func TestPathPatternRuleWriteAllows(t *testing.T) {
	r := &PathPatternRule{AgentConfigDir: "/home/u/.claude"}
	cases := []struct{ tool, path string }{
		{"Write", "/home/u/project/app.go"},
		{"Edit", "/home/u/project/.vscode/settings.json"}, // not .claude → allowed
		{"Write", "/home/u/project/docs/guide.md"},
	}
	for _, tc := range cases {
		t.Run(tc.tool+":"+tc.path, func(t *testing.T) {
			_, matched := evalOrSkip(t, r, toolEvent(t, tc.tool, map[string]any{"file_path": tc.path}))
			if matched {
				t.Errorf("expected ALLOW %s %q", tc.tool, tc.path)
			}
		})
	}
}

func TestPathPatternRuleMultiEdit(t *testing.T) {
	r := &PathPatternRule{}
	ev := toolEvent(t, "MultiEdit", map[string]any{
		"file_path": "/home/u/svc/.env",
		"edits":     []any{map[string]any{"old_string": "a", "new_string": "b"}},
	})
	d, matched := evalOrSkip(t, r, ev)
	if !matched || d.Action != Deny {
		t.Errorf("MultiEdit of a .env must be denied; matched=%v", matched)
	}
}

func TestPathPatternRuleGlobDenies(t *testing.T) {
	r := &PathPatternRule{}
	cases := []struct {
		name  string
		tool  string
		input map[string]any
	}{
		{"glob-pem", "Glob", map[string]any{"pattern": "**/*.pem"}},
		{"glob-ssh-pattern", "Glob", map[string]any{"pattern": "~/.ssh/*"}},
		{"glob-ssh-path", "Glob", map[string]any{"pattern": "*", "path": "/home/u/.ssh"}},
		{"glob-env", "Glob", map[string]any{"pattern": "**/.env"}},
		{"glob-env-ext", "Glob", map[string]any{"pattern": "**/*.env"}},
		{"glob-kdbx", "Glob", map[string]any{"pattern": "**/*.kdbx"}},
		{"grep-aws-path", "Grep", map[string]any{"pattern": "key", "path": "/home/u/.aws"}},
		{"grep-glob-field", "Grep", map[string]any{"pattern": "key", "glob": "~/.ssh/*"}},
		{"grep-glob-env-ext", "Grep", map[string]any{"pattern": "key", "glob": "*.env"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, matched, err := r.Evaluate(toolEvent(t, tc.tool, tc.input))
			if err != nil {
				t.Fatal(err)
			}
			if !matched || d.Action != Deny {
				t.Errorf("expected DENY %s %v; matched=%v", tc.tool, tc.input, matched)
			}
		})
	}
}

func TestPathPatternRuleGlobAllows(t *testing.T) {
	r := &PathPatternRule{}
	cases := []map[string]any{
		{"pattern": "**/*.go"},
		{"pattern": "src/**/*.ts"},
		{"pattern": "*", "path": "/home/u/project"},
	}
	for _, in := range cases {
		t.Run(in["pattern"].(string), func(t *testing.T) {
			_, matched, err := r.Evaluate(toolEvent(t, "Glob", in))
			if err != nil {
				t.Fatal(err)
			}
			if matched {
				t.Errorf("expected ALLOW Glob %v", in)
			}
		})
	}
}

// On macOS /etc is a firmlink to /private/etc, so Canonicalize resolves an
// /etc target to /private/etc; the gate must still deny it. A matcher keyed only
// on the literal /etc/… form would miss the macOS-resolved path.
func TestPathPatternRuleMacFirmlinkEtc(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only: /etc is a firmlink to /private/etc on darwin")
	}
	r := &PathPatternRule{}
	// Reads of credential files under /etc — fed both conventionally and in the
	// already-resolved /private/etc form a symlinked workdir could yield.
	for _, p := range []string{"/etc/shadow", "/private/etc/shadow", "/etc/sudoers"} {
		d, matched := evalOrSkip(t, r, toolEvent(t, "Read", map[string]any{"file_path": p}))
		if !matched || d.Action != Deny {
			t.Errorf("expected DENY reading %q on macOS; matched=%v", p, matched)
		}
	}
	// The whole-/etc write block survives the firmlink, credential file or not.
	for _, p := range []string{"/etc/cron.d/job", "/private/etc/cron.d/job", "/etc/hosts"} {
		d, matched := evalOrSkip(t, r, toolEvent(t, "Write", map[string]any{"file_path": p}))
		if !matched || d.Action != Deny {
			t.Errorf("expected DENY writing %q on macOS; matched=%v", p, matched)
		}
	}
}

// evalGlob's tool_input decode error must propagate (fail closed), not be swallowed
// into an allow — the only error-returning path in the Glob/Grep branch.
func TestPathPatternRuleUnparseableGlobInput(t *testing.T) {
	r := &PathPatternRule{}
	for _, tool := range []string{"Glob", "Grep"} {
		// []byte is assignable to the json.RawMessage field without importing json.
		ev := &HookEvent{ToolName: tool, ToolInput: []byte(`"not-an-object"`)}
		if _, _, err := r.Evaluate(ev); err == nil {
			t.Errorf("unparseable %s tool_input must error (fail closed)", tool)
		}
	}
}

func TestPathPatternRuleIgnoresBash(t *testing.T) {
	r := &PathPatternRule{}
	_, matched, err := r.Evaluate(toolEvent(t, "Bash", map[string]any{"command": "cat /home/u/.env"}))
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Error("PathPatternRule must not match a Bash tool (the Bash gate handles it)")
	}
}

func TestClassifySensitiveUnit(t *testing.T) {
	deny := []string{
		"/x/.env", "/x/.env.local", "/x/.ENV", "/x/.envrc", // .env family, case-insensitive
		"/x/a.pem", "/x/b.key", "/x/c.p12", "/x/d.pfx", "/x/g.gpg", "/x/h.asc",
		"/x/.netrc", "/etc/sudoers", "/x/secrets.yaml", "/x/api_key.env",
		"/x/i.kdbx", "/x/login.keychain-db",
		"/home/u/.ssh/id_ed25519", "/home/u/.SSH/id_rsa", "/srv/.gnupg/x", // secret dirs, case-insensitive
	}
	if runtime.GOOS == "darwin" {
		// On macOS Canonicalize hands us the firmlink-resolved form; the classifier
		// must fold /private/etc back to /etc before the credential-file lookup.
		deny = append(deny, "/private/etc/shadow", "/private/etc/sudoers")
	}
	for _, p := range deny {
		if _, hit := classifySensitive(p); !hit {
			t.Errorf("classifySensitive(%q) should be sensitive", p)
		}
	}
	allow := []string{
		"/x/main.go", "/x/README.md", "/x/config.yaml", "/etc/hosts",
		"/x/certificate-guide.md", "/x/keyboard.txt", "/x/tokenizer.py",
		"/x/ca-certificates.crt", "/x/cert.cer", "/x/chain.der", // public certs, not secret
		"/x/.env.example", "/x/.env.sample", // committed templates
	}
	for _, p := range allow {
		if reason, hit := classifySensitive(p); hit {
			t.Errorf("classifySensitive(%q) should be benign, got %q", p, reason)
		}
	}
}

func TestSelfConfigMatch(t *testing.T) {
	cfg := "/home/u/.claude"
	deny := []string{
		"/home/u/.claude/settings.json",
		// All merged Claude settings files are kill switches (hooks block /
		// disableAllHooks), not just settings.json.
		"/home/u/.claude/settings.local.json",
		"/home/u/.claude/managed-settings.json",
		"/custom/cfg/settings.local.json",
		"/home/u/project/.claude/settings.local.json", // project-local override file
		"/home/u/.claude/hooks/x.sh",
		"/home/u/.claude", // the dir itself (rm target)
		"~/.claude/settings.json",
		"$HOME/.claude", // raw shell token
		"/custom/cfg/settings.json",
		"/custom/cfg/hooks/y.sh",
		// corral's own launcher config: writing one widens the sandbox on the next launch.
		"/home/u/project/.corral.yml",
		"/home/u/project/.corral.local.yml",
		"~/project/.corral.yml", // raw shell token
		"/home/u/.config/corral/config.yml",
		"$XDG_CONFIG_HOME/corral/config.yml", // raw token, …/corral/config.yml shape
	}
	for _, p := range deny {
		dir := cfg
		if strings.HasPrefix(p, "/custom") {
			dir = "/custom/cfg"
		}
		if _, ok := selfConfigMatch(p, selfProtect{configDir: dir, footprint: claudeFootprint(), allFootprints: allTestFootprints()}); !ok {
			t.Errorf("selfConfigMatch(%q) should match", p)
		}
	}
	allow := []string{
		"/home/u/.claude/.claude.json", // session state — must remain writable
		"/home/u/.claude/projects/x",
		"/home/u/project/.vscode/settings.json",
		"/home/u/project/main.go",
		"/home/u/project/config.yml",      // config.yml not under a corral/ dir — unrelated
		"/home/u/project/corral-notes.md", // not a sentinel name
	}
	for _, p := range allow {
		if reason, ok := selfConfigMatch(p, selfProtect{configDir: cfg, footprint: claudeFootprint(), allFootprints: allTestFootprints()}); ok {
			t.Errorf("selfConfigMatch(%q) must NOT match (got %q) — agent state stays writable", p, reason)
		}
	}
}

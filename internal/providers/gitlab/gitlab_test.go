package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
)

func TestGitlabAvailable(t *testing.T) {
	if New(Config{}, nil).Available(context.Background()) {
		t.Error("gitlab must be unavailable without a host GITLAB_TOKEN")
	}
	if !New(Config{}, map[string]string{"GITLAB_TOKEN": "glpat-xxx"}).Available(context.Background()) {
		t.Error("gitlab must be available when a host token is present")
	}
}

func TestGitlabContributionEnv(t *testing.T) {
	// Forwards the usual glab vars present on the host; never CI_* vars or the host's
	// admin token; the minted token always wins.
	g := &gitlab{
		hostEnv: map[string]string{
			"GITLAB_TOKEN":  "glpat-admin",
			"GL_HOST":       "gitlab.example.com",
			"REMOTE_ALIAS":  "upstream",
			"CI_API_V4_URL": "https://ci/api/v4", // CI var → excluded
			"CI_JOB_TOKEN":  "ci-job",            // CI var → excluded
			"UNRELATED":     "x",                 // not a glab var → excluded
		},
	}
	env := g.contributionEnv("glpat-minted")
	if env["GITLAB_TOKEN"] != "glpat-minted" {
		t.Errorf("minted token must win, got %q", env["GITLAB_TOKEN"])
	}
	if env["GL_HOST"] != "gitlab.example.com" || env["REMOTE_ALIAS"] != "upstream" {
		t.Errorf("present glab vars must be forwarded: %v", env)
	}
	for _, k := range []string{"CI_API_V4_URL", "CI_JOB_TOKEN", "UNRELATED"} {
		if _, ok := env[k]; ok {
			t.Errorf("%s must not be forwarded: %v", k, env)
		}
	}

	// providers.gitlab.host overrides GITLAB_HOST for the in-sandbox tooling.
	g2 := &gitlab{
		cfg:     Config{Host: "gitlab.corp.example"},
		hostEnv: map[string]string{"GITLAB_HOST": "gitlab.com"},
	}
	if env := g2.contributionEnv("t"); env["GITLAB_HOST"] != "gitlab.corp.example" {
		t.Errorf("config host must override forwarded GITLAB_HOST, got %q", env["GITLAB_HOST"])
	}
}

// gitlabRecorder is a fake GitLab API: it records the last request and returns a minted
// token on POST, 204 on DELETE. A mutex guards the fields against the server goroutine.
type gitlabRecorder struct {
	mu          sync.Mutex
	auth        string
	method      string
	escapedPath string
	body        map[string]any
}

func (rec *gitlabRecorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		rec.auth = r.Header.Get("PRIVATE-TOKEN")
		rec.method = r.Method
		rec.escapedPath = r.URL.EscapedPath()
		if r.Method == http.MethodGet { // GET /user — the personal-token path resolves the current user first
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "username": "realuser"})
			return
		}
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&rec.body)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 99, "token": "glpat-minted-xyz"})
			return
		}
		w.WriteHeader(http.StatusNoContent) // DELETE (revoke)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitlabMintAndRevoke(t *testing.T) {
	rec := &gitlabRecorder{}
	srv := rec.server(t)
	g := &gitlab{
		cfg: Config{
			Type:    "project",
			Project: "mygroup/myrepo",
			Scopes:  []string{"read_repository", "write_repository"},
			Role:    "maintainer", // → access_level 40
		},
		token: "glpat-host-admin",
		hostEnv: map[string]string{
			"GITLAB_TOKEN":     "glpat-host-admin", // admin cred — must not be forwarded
			"GITLAB_HOST":      "https://gitlab.example.com",
			"GITLAB_CLIENT_ID": "client-123",              // a usual glab var → forwarded
			"CI_API_V4_URL":    "https://ci-injected/api", // a CI var → must not be forwarded
		},
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}

	c, err := g.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	// The minted (scoped) token crosses in — never the host's admin token.
	if c.Env["GITLAB_TOKEN"] != "glpat-minted-xyz" {
		t.Errorf("GITLAB_TOKEN must be the minted token, got %q", c.Env["GITLAB_TOKEN"])
	}
	// The dev's present glab vars are forwarded verbatim...
	if c.Env["GITLAB_HOST"] != "https://gitlab.example.com" {
		t.Errorf("GITLAB_HOST should be forwarded from the host, got %q", c.Env["GITLAB_HOST"])
	}
	if c.Env["GITLAB_CLIENT_ID"] != "client-123" {
		t.Errorf("GITLAB_CLIENT_ID should be forwarded, got %q", c.Env["GITLAB_CLIENT_ID"])
	}
	// ...but CI_* vars are never forwarded (CI-injected, not a dev-machine var).
	if _, ok := c.Env["CI_API_V4_URL"]; ok {
		t.Errorf("CI_API_V4_URL must not be forwarded: %v", c.Env)
	}
	if len(c.Mounts) != 0 {
		t.Errorf("gitlab is env-only, must contribute no mounts: %v", c.Mounts)
	}
	if c.Cleanup == nil {
		t.Fatal("gitlab must register a revoke Cleanup")
	}
	// Status describes the mint for the banner — and must never carry the token value.
	if len(c.Status) != 1 {
		t.Fatalf("expected one Status line, got %v", c.Status)
	}
	if strings.Contains(c.Status[0], "glpat-minted-xyz") {
		t.Errorf("Status must not leak the minted token: %q", c.Status[0])
	}
	for _, want := range []string{"mygroup/myrepo", "read_repository", "maintainer", "expires"} {
		if !strings.Contains(c.Status[0], want) {
			t.Errorf("Status should mention %q: %q", want, c.Status[0])
		}
	}
	// The AgentNote tells the model what GITLAB_TOKEN is (kind/scopes/expiry) and carries
	// the glab quirk (`glab auth status` misreports env-token auth); it must never leak
	// the token value.
	if len(c.AgentNotes) != 1 {
		t.Fatalf("expected one AgentNotes line, got %v", c.AgentNotes)
	}
	if strings.Contains(c.AgentNotes[0], "glpat-minted-xyz") {
		t.Errorf("AgentNotes must not leak the minted token: %q", c.AgentNotes[0])
	}
	for _, want := range []string{"GITLAB_TOKEN", "project access token", "mygroup/myrepo", "read_repository", "maintainer", "expires", "glab auth status"} {
		if !strings.Contains(c.AgentNotes[0], want) {
			t.Errorf("AgentNotes should mention %q: %q", want, c.AgentNotes[0])
		}
	}
	// CleanupHint is surfaced only if revoke fails: it names the live-token risk + the
	// manual remedy, and (like Status) must never carry the token value.
	if c.CleanupHint == "" {
		t.Error("gitlab must set a CleanupHint for the no-Reaper revoke-failure case")
	}
	if strings.Contains(c.CleanupHint, "glpat-minted-xyz") {
		t.Errorf("CleanupHint must not leak the minted token: %q", c.CleanupHint)
	}
	for _, want := range []string{"may still be live", "revoke", "expires on"} {
		if !strings.Contains(c.CleanupHint, want) {
			t.Errorf("CleanupHint should mention %q: %q", want, c.CleanupHint)
		}
	}

	rec.mu.Lock()
	if rec.auth != "glpat-host-admin" {
		t.Errorf("PRIVATE-TOKEN = %q, want the host credential", rec.auth)
	}
	if !strings.Contains(rec.escapedPath, "mygroup%2Fmyrepo/access_tokens") {
		t.Errorf("project path not URL-encoded: %q", rec.escapedPath)
	}
	if lvl, _ := rec.body["access_level"].(float64); lvl != 40 {
		t.Errorf("access_level = %v, want 40", rec.body["access_level"])
	}
	if scopes, _ := rec.body["scopes"].([]any); len(scopes) != 2 {
		t.Errorf("scopes = %v, want 2", rec.body["scopes"])
	}
	if _, ok := rec.body["expires_at"].(string); !ok {
		t.Errorf("expires_at missing/!string: %v", rec.body["expires_at"])
	}
	if name, _ := rec.body["name"].(string); !strings.HasPrefix(name, "corral-alice-") {
		t.Errorf("token name = %q, want corral-alice-*", name)
	}
	rec.mu.Unlock()

	// Cleanup revokes by id.
	if err := c.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.method != http.MethodDelete {
		t.Errorf("cleanup must DELETE, got %q", rec.method)
	}
	if !strings.HasSuffix(rec.escapedPath, "/access_tokens/99") {
		t.Errorf("revoke path must target the token id: %q", rec.escapedPath)
	}
}

// type: personal mints a PAT via the admin endpoint POST /users/:id/personal_access_tokens,
// after resolving the host credential's own user via GET /user. The PAT is owned by that
// real user, so it sends no access_level; the minted token (never the host's) crosses in.
func TestGitlabMintPersonalToken(t *testing.T) {
	rec := &gitlabRecorder{}
	srv := rec.server(t)
	g := &gitlab{
		cfg: Config{
			Type:   "personal",
			Scopes: []string{"api"}, // opt into write so it can create issues/MRs
			Role:   "maintainer",    // must be ignored for a PAT (no per-project access_level)
		},
		token:   "glpat-host-admin",
		hostEnv: map[string]string{"GITLAB_TOKEN": "glpat-host-admin"},
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}

	c, err := g.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Env["GITLAB_TOKEN"] != "glpat-minted-xyz" {
		t.Errorf("GITLAB_TOKEN must be the minted token, got %q", c.Env["GITLAB_TOKEN"])
	}
	// Status names the resolved real user + host (not a project), never a role, never the token.
	if len(c.Status) != 1 {
		t.Fatalf("expected one Status line, got %v", c.Status)
	}
	for _, want := range []string{"personal access token", "realuser", "gitlab.example.com", "api", "expires"} {
		if !strings.Contains(c.Status[0], want) {
			t.Errorf("Status should mention %q: %q", want, c.Status[0])
		}
	}
	if strings.Contains(c.Status[0], "maintainer") {
		t.Errorf("a PAT has no project role — Status must not mention one: %q", c.Status[0])
	}
	if strings.Contains(c.Status[0], "glpat-minted-xyz") {
		t.Errorf("Status must not leak the minted token: %q", c.Status[0])
	}
	// The AgentNote carries the same facts as Status for the model (kind/scopes/expiry) and
	// adds the glab quirk; like Status it names no role and never the token value.
	if len(c.AgentNotes) != 1 {
		t.Fatalf("expected one AgentNotes line, got %v", c.AgentNotes)
	}
	for _, want := range []string{"GITLAB_TOKEN", "personal access token", "realuser", "gitlab.example.com", "api", "expires", "glab auth status"} {
		if !strings.Contains(c.AgentNotes[0], want) {
			t.Errorf("AgentNotes should mention %q: %q", want, c.AgentNotes[0])
		}
	}
	if strings.Contains(c.AgentNotes[0], "glpat-minted-xyz") {
		t.Errorf("AgentNotes must not leak the minted token: %q", c.AgentNotes[0])
	}

	rec.mu.Lock()
	if !strings.HasSuffix(rec.escapedPath, "/users/42/personal_access_tokens") {
		t.Errorf("PAT create must POST to /users/<id>/personal_access_tokens, got %q", rec.escapedPath)
	}
	if _, ok := rec.body["access_level"]; ok {
		t.Errorf("a PAT request must not send access_level: %v", rec.body)
	}
	if name, _ := rec.body["name"].(string); !strings.HasPrefix(name, "corral-alice-") {
		t.Errorf("token name = %q, want corral-alice-*", name)
	}
	rec.mu.Unlock()

	// Cleanup revokes the PAT by id at the personal endpoint.
	if err := c.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.method != http.MethodDelete {
		t.Errorf("cleanup must DELETE, got %q", rec.method)
	}
	if !strings.HasSuffix(rec.escapedPath, "/personal_access_tokens/99") {
		t.Errorf("revoke path must target the PAT id at the personal endpoint: %q", rec.escapedPath)
	}
}

// A non-admin host token can resolve GET /user but is rejected (403) by the admin
// PAT-create endpoint. That must fail closed, not silently fall back.
func TestGitlabMintPersonalRequiresAdmin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":42,"username":"realuser"}`))
			return
		}
		w.WriteHeader(http.StatusForbidden) // admin endpoint rejects a non-admin token
		_, _ = w.Write([]byte(`{"message":"403 Forbidden"}`))
	}))
	defer srv.Close()
	g := &gitlab{
		cfg:     Config{Type: "personal"},
		token:   "glpat-host",
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}
	if _, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false); err == nil {
		t.Fatal("a non-admin host token must fail closed when minting a PAT")
	}
}

func TestGitlabMintFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"403 Forbidden"}`))
	}))
	defer srv.Close()
	g := &gitlab{
		cfg:     Config{Project: "g/p"},
		token:   "glpat-host",
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}
	if _, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false); err == nil {
		t.Fatal("Mint must fail closed when the API rejects the request")
	}
}

// A POST response with id<=0 (malformed) must fail closed: a 0 id would build a
// revoke URL that 404s, letting cleanup "succeed" while the token stays live.
func TestGitlabMintRejectsInvalidTokenID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":0,"token":"glpat-minted"}`))
	}))
	defer srv.Close()
	g := &gitlab{
		cfg:     Config{Project: "g/p"},
		token:   "glpat-host",
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}
	if _, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false); err == nil {
		t.Fatal("Mint must fail closed on an invalid token id (cleanup would not revoke)")
	}
}

// When the revoke (DELETE) fails with a non-2xx, Cleanup must surface the error so the
// launcher can warn the operator that a token may still be live (it is not silent).
func TestGitlabRevokeFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":99,"token":"glpat-minted"}`))
			return
		}
		w.WriteHeader(http.StatusInternalServerError) // DELETE (revoke) fails
		_, _ = w.Write([]byte(`{"message":"500 Internal Server Error"}`))
	}))
	defer srv.Close()
	g := &gitlab{
		cfg:     Config{Type: "project", Project: "g/p"},
		token:   "glpat-host",
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}
	c, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := c.Cleanup(context.Background()); err == nil {
		t.Fatal("a failed revoke must return an error from Cleanup, not succeed silently")
	}
}

func TestGitlabProjectAutodetect(t *testing.T) {
	rec := &gitlabRecorder{}
	srv := rec.server(t)
	// A workdir whose origin remote points at the configured GitLab host.
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitcfg := "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@gitlab.example.com:auto/detected.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	if err := os.WriteFile(filepath.Join(work, ".git", "config"), []byte(gitcfg), 0o644); err != nil {
		t.Fatal(err)
	}
	g := &gitlab{
		cfg:     Config{Type: "project"}, // no explicit project → autodetect
		token:   "glpat-host",
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}
	if _, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s", WorkDir: work}, false); err != nil {
		t.Fatalf("autodetect Mint: %v", err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if !strings.Contains(rec.escapedPath, "auto%2Fdetected/access_tokens") {
		t.Errorf("autodetected project not used in request: %q", rec.escapedPath)
	}
}

func TestGitlabAutodetectHostMismatch(t *testing.T) {
	work := t.TempDir()
	_ = os.MkdirAll(filepath.Join(work, ".git"), 0o755)
	_ = os.WriteFile(filepath.Join(work, ".git", "config"),
		[]byte("[remote \"origin\"]\n\turl = git@github.com:other/repo.git\n"), 0o644)
	g := &gitlab{cfg: Config{}, token: "t", host: "gitlab.example.com", apiBase: "https://x", client: http.DefaultClient}
	if _, err := g.Mint(context.Background(), spec.Session{WorkDir: work}, false); err == nil {
		t.Fatal("an origin on a different host must not auto-resolve a project (fail closed)")
	}
}

func TestParseGitlabURL(t *testing.T) {
	for _, tc := range []struct {
		raw, host, project string
		wantErr            bool
	}{
		{raw: "git@gitlab.com:group/repo.git", host: "gitlab.com", project: "group/repo"},
		{raw: "https://gitlab.com/group/sub/repo.git", host: "gitlab.com", project: "group/sub/repo"},
		{raw: "https://gitlab.com/group/repo", host: "gitlab.com", project: "group/repo"},
		{raw: "ssh://git@gl.example.com:2222/group/repo.git", host: "gl.example.com", project: "group/repo"},
		{raw: "not a url", wantErr: true},
		// Malformed origins must fail closed, never panic. "user:tok@host/path" has a
		// colon before '@' but none after — the scp branch must not slice on index -1.
		{raw: "user:tok@gitlab.com/g/r.git", wantErr: true},
		{raw: "foo:bar@host/path", wantErr: true},
		// A double colon mis-parses into a leading-colon project — reject it.
		{raw: "git@gitlab.com::group/repo.git", wantErr: true},
	} {
		h, p, err := parseGitlabURL(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("%q: expected error", tc.raw)
			}
			continue
		}
		if err != nil || h != tc.host || p != tc.project {
			t.Errorf("parseGitlabURL(%q) = (%q,%q,%v), want (%q,%q,nil)", tc.raw, h, p, err, tc.host, tc.project)
		}
	}
}

func TestGitlabHelpers(t *testing.T) {
	if got := escapeProject("group/sub/repo"); got != "group%2Fsub%2Frepo" {
		t.Errorf("escapeProject = %q", got)
	}
	if got := escapeProject("12345"); got != "12345" {
		t.Errorf("escapeProject(id) = %q", got)
	}
	if got := resolveGitlabHost("", ""); got != "gitlab.com" {
		t.Errorf("resolveGitlabHost default = %q, want gitlab.com", got)
	}
	if got := resolveGitlabHost("https://gl.example.com/", ""); got != "gl.example.com" {
		t.Errorf("resolveGitlabHost must strip scheme/slash, got %q", got)
	}
	if got := resolveGitlabHost("", "self.gitlab.io"); got != "self.gitlab.io" {
		t.Errorf("resolveGitlabHost should fall back to env host, got %q", got)
	}
}

func TestGitlabHostPrecedence(t *testing.T) {
	if got := resolveGitlabHost("", ""); got != "gitlab.com" {
		t.Errorf("with nothing set, host must default to gitlab.com, got %q", got)
	}
	if got := resolveGitlabHost("", "env.gitlab.example"); got != "env.gitlab.example" {
		t.Errorf("env $GITLAB_HOST must be used, got %q", got)
	}
	if got := resolveGitlabHost("cfg.gitlab.example", "env.gitlab.example"); got != "cfg.gitlab.example" {
		t.Errorf("config host must win over env, got %q", got)
	}
}

// The host is never inferred from the workdir's git remote: with no config/env host set,
// it defaults to gitlab.com rather than parsing .git/config.
func TestNewIgnoresWorkdirRemote(t *testing.T) {
	g, ok := New(Config{}, map[string]string{"GITLAB_TOKEN": "glpat-x"}).(*gitlab)
	if !ok {
		t.Fatal("New did not return a *gitlab")
	}
	if g.host != "gitlab.com" {
		t.Errorf("host = %q, want gitlab.com (never inferred from a remote)", g.host)
	}
	// An explicit $GITLAB_HOST is used as before.
	g2 := New(Config{}, map[string]string{"GITLAB_TOKEN": "glpat-x", "GITLAB_HOST": "env.example"}).(*gitlab)
	if g2.host != "env.example" {
		t.Errorf("explicit GITLAB_HOST must be used, got %q", g2.host)
	}
}

// Without a derived host, GITLAB_HOST is injected only when providers.gitlab.host is set
// (explicit config); otherwise the sandbox inherits whatever $GITLAB_HOST the host env had.
func TestGitlabContributionEnvNoHostSynthesis(t *testing.T) {
	// No config host, no env host -> GITLAB_HOST not injected (defaults to gitlab.com
	// internally, but glab applies its own default).
	g := &gitlab{hostEnv: map[string]string{}}
	if _, ok := g.contributionEnv("t")["GITLAB_HOST"]; ok {
		t.Error("must not inject GITLAB_HOST when neither config nor env set it")
	}

	// Config host -> injected.
	g2 := &gitlab{cfg: Config{Host: "gitlab.corp.example"}, hostEnv: map[string]string{}}
	if env := g2.contributionEnv("t"); env["GITLAB_HOST"] != "gitlab.corp.example" {
		t.Errorf("config host must be injected, got %q", env["GITLAB_HOST"])
	}

	// Env host -> forwarded as-is (via gitlabForwardEnv).
	g3 := &gitlab{hostEnv: map[string]string{"GITLAB_HOST": "env.example"}}
	if env := g3.contributionEnv("t"); env["GITLAB_HOST"] != "env.example" {
		t.Errorf("env GITLAB_HOST must be forwarded, got %q", env["GITLAB_HOST"])
	}
}

// TestGitlabMintRejectsSideEffectFree guards the Provider contract: a credential-minter
// cannot mint without its side effect (a live API call), so Mint must fail loudly when
// asked for a side-effect-free contribution — and return before touching the network (here
// the client points at a server that fails the test if it is ever hit).
func TestGitlabMintRejectsSideEffectFree(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("a side-effect-free Mint must not make any API call")
	}))
	defer srv.Close()
	g := &gitlab{token: "glpat-host", host: "gitlab.example.com", apiBase: srv.URL, client: srv.Client()}

	if _, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, true); err == nil {
		t.Fatal("gitlab.Mint must reject dryRun=true (it cannot mint without an API call)")
	}
}

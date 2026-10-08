package gitlab

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
	// Forwards the usual glab vars present on the host; never CI_* vars or the host
	// token; the minted token always wins.
	g := &gitlab{
		hostEnv: map[string]string{
			"GITLAB_TOKEN":  "glpat-host",
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

// fakeGitlab is a fake GitLab API. It records every request and answers GET /user, project and
// group lookups (ids, keyed by the escaped path after /api/v4/; a missing key is a 404), the token
// create (createBody, default a fine-grained token), and the revoke (204). fail overrides the status
// for an escaped path. A mutex guards the fields against the server goroutine.
type fakeGitlab struct {
	mu         sync.Mutex
	reqs       []fakeRequest
	ids        map[string]int
	createBody string
	fail       map[string]int
}

type fakeRequest struct {
	method, path, query, auth string
	body                      map[string]any
}

const createPath = "/api/v4/user/personal_access_tokens"

func (f *fakeGitlab) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		req := fakeRequest{method: r.Method, path: r.URL.EscapedPath(), query: r.URL.RawQuery, auth: r.Header.Get("PRIVATE-TOKEN")}
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&req.body)
		}
		f.reqs = append(f.reqs, req)
		if status, ok := f.fail[req.path]; ok {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"message":"` + http.StatusText(status) + ` from fake"}`))
			return
		}
		switch {
		case r.Method == http.MethodGet && req.path == "/api/v4/user":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": 42, "username": "realuser"})
		case r.Method == http.MethodGet:
			id, ok := f.ids[strings.TrimPrefix(req.path, "/api/v4/")]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"404 Not found"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"id": id})
		case r.Method == http.MethodPost:
			w.WriteHeader(http.StatusCreated)
			body := f.createBody
			if body == "" {
				body = `{"id":99,"token":"glpat-minted-xyz","scopes":["granular"],"granular":true}`
			}
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(http.StatusNoContent) // DELETE (revoke)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeGitlab) provider(t *testing.T, cfg Config) *gitlab {
	t.Helper()
	srv := f.server(t)
	return &gitlab{
		cfg:     cfg,
		token:   "glpat-host",
		hostEnv: map[string]string{"GITLAB_TOKEN": "glpat-host"},
		host:    "gitlab.example.com",
		apiBase: srv.URL,
		client:  srv.Client(),
	}
}

func (f *fakeGitlab) requests() []fakeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fakeRequest(nil), f.reqs...)
}

// createRequest returns the body of the single token-create POST.
func (f *fakeGitlab) createRequest(t *testing.T) map[string]any {
	t.Helper()
	var bodies []map[string]any
	for _, r := range f.requests() {
		if r.method == http.MethodPost && r.path == createPath {
			bodies = append(bodies, r.body)
		}
	}
	if len(bodies) != 1 {
		t.Fatalf("want exactly one POST %s, got %d", createPath, len(bodies))
	}
	return bodies[0]
}

// selectedScopes returns the selected_memberships entries of the create request, JSON-encoded
// for comparison, and checks the fixed user entry comes last.
func (f *fakeGitlab) selectedScopes(t *testing.T) []string {
	t.Helper()
	scopes, _ := f.createRequest(t)["granular_scopes"].([]any)
	if len(scopes) == 0 {
		t.Fatal("create request has no granular_scopes")
	}
	last, _ := json.Marshal(scopes[len(scopes)-1])
	if string(last) != `{"access":"user","permissions":["read_user","read_personal_access_token"]}` {
		t.Errorf("last granular scope = %s, want the fixed user scope", last)
	}
	out := make([]string, 0, len(scopes)-1)
	for _, sc := range scopes[:len(scopes)-1] {
		b, _ := json.Marshal(sc)
		out = append(out, string(b))
	}
	return out
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func workdirWithOrigin(t *testing.T, origin string) string {
	t.Helper()
	work := t.TempDir()
	if err := os.MkdirAll(filepath.Join(work, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitcfg := "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = " + origin + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	if err := os.WriteFile(filepath.Join(work, ".git", "config"), []byte(gitcfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return work
}

// The minimal config mints a fine-grained token with the read-only default on the origin project.
// The whole request body is pinned: it must never carry legacy `scopes`, which GitLab before 19.2
// prefers over granular_scopes.
func TestGitlabMintMinimalConfig(t *testing.T) {
	f := &fakeGitlab{ids: map[string]int{"projects/org%2Fteam%2Frepo": 42}}
	g := f.provider(t, Config{})
	g.hostEnv = map[string]string{
		"GITLAB_TOKEN":     "glpat-host", // host cred — must not be forwarded
		"GITLAB_HOST":      "https://gitlab.example.com",
		"GITLAB_CLIENT_ID": "client-123",              // a usual glab var → forwarded
		"CI_API_V4_URL":    "https://ci-injected/api", // a CI var → must not be forwarded
	}
	work := workdirWithOrigin(t, "git@gitlab.example.com:org/team/repo.git")

	c, err := g.Mint(context.Background(), spec.Session{User: "alice", ID: "s1", WorkDir: work}, false)
	if err != nil {
		t.Fatal(err)
	}
	if c.Env["GITLAB_TOKEN"] != "glpat-minted-xyz" {
		t.Errorf("GITLAB_TOKEN must be the minted token, got %q", c.Env["GITLAB_TOKEN"])
	}
	if c.Env["GITLAB_HOST"] != "https://gitlab.example.com" || c.Env["GITLAB_CLIENT_ID"] != "client-123" {
		t.Errorf("present glab vars must be forwarded: %v", c.Env)
	}
	if _, ok := c.Env["CI_API_V4_URL"]; ok {
		t.Errorf("CI_API_V4_URL must not be forwarded: %v", c.Env)
	}
	if len(c.Mounts) != 0 {
		t.Errorf("gitlab is env-only, must contribute no mounts: %v", c.Mounts)
	}
	for _, r := range f.requests() {
		if r.auth != "glpat-host" {
			t.Errorf("%s %s: PRIVATE-TOKEN = %q, want the host credential", r.method, r.path, r.auth)
		}
	}

	body := f.createRequest(t)
	if _, ok := body["scopes"]; ok {
		t.Errorf("the create request must not carry legacy scopes: %v", body)
	}
	expires, _ := body["expires_at"].(string)
	if _, err := time.Parse("2006-01-02", expires); err != nil {
		t.Errorf("expires_at = %q, want a YYYY-MM-DD date", expires)
	}
	delete(body, "expires_at")
	var want map[string]any
	if err := json.Unmarshal([]byte(`{
		"name": "corral-alice-s1",
		"description": "corral session token",
		"granular_scopes": [
			{"access": "selected_memberships", "project_ids": [42], "permissions": `+mustJSON(t, PresetReadPermissions)+`},
			{"access": "user", "permissions": ["read_user", "read_personal_access_token"]}
		]
	}`), &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(body, want) {
		got, _ := json.Marshal(body)
		t.Errorf("create request body =\n%s\nwant the minimal fine-grained request", got)
	}

	if err := c.Cleanup(context.Background()); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	reqs := f.requests()
	if last := reqs[len(reqs)-1]; last.method != http.MethodDelete || last.path != "/api/v4/personal_access_tokens/99" {
		t.Errorf("cleanup must DELETE /api/v4/personal_access_tokens/99, got %s %s", last.method, last.path)
	}
}

func TestGitlabExpiresAt(t *testing.T) {
	late := time.Date(2026, 10, 8, 23, 30, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		now  time.Time
		days int
		want string
	}{
		{"one day late in the UTC day", late, 1, "2026-10-09"},
		{"seven days", late, 7, "2026-10-15"},
		{"non-UTC now uses the UTC date", late.In(time.FixedZone("UTC+2", 2*60*60)), 1, "2026-10-09"},
	} {
		if got := expiresAt(tc.now, tc.days); got != tc.want {
			t.Errorf("%s: expiresAt(%v, %d) = %q, want %q", tc.name, tc.now, tc.days, got, tc.want)
		}
	}
}

// The create request's expires_at follows tokenLifetimeDays.
func TestGitlabMintTokenLifetime(t *testing.T) {
	f := &fakeGitlab{ids: map[string]int{"projects/org%2Fapp": 42}}
	g := f.provider(t, Config{TokenLifetimeDays: new(7), TokenGrants: []Grant{{Project: "org/app"}}})
	before := expiresAt(time.Now(), 7)
	if _, err := g.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false); err != nil {
		t.Fatal(err)
	}
	after := expiresAt(time.Now(), 7)
	if expires, _ := f.createRequest(t)["expires_at"].(string); expires != before && expires != after {
		t.Fatalf("expires_at = %q, want %q (7 days after the current UTC date)", expires, after)
	}
}

// Several grants become one selected_memberships scope each, in config order, with project_ids or
// group_ids. Status and note name every target with its permissions and never a token value.
func TestGitlabMintSeveralGrants(t *testing.T) {
	f := &fakeGitlab{ids: map[string]int{"projects/org%2Fapp": 42, "groups/org%2Flibs": 7}}
	g := f.provider(t, Config{TokenGrants: []Grant{
		{Project: "org/app", Permissions: []string{"download_code", "push_code"}},
		{Group: "org/libs", Permissions: []string{"download_code"}},
	}})

	// No .git in the workdir: every grant names its target, so detection must not run.
	c, err := g.Mint(context.Background(), spec.Session{User: "alice", ID: "s1", WorkDir: t.TempDir()}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"access":"selected_memberships","permissions":["download_code","push_code"],"project_ids":[42]}`,
		`{"access":"selected_memberships","group_ids":[7],"permissions":["download_code"]}`,
	}
	if got := f.selectedScopes(t); !reflect.DeepEqual(got, want) {
		t.Errorf("selected scopes =\n%v\nwant\n%v", got, want)
	}
	for _, r := range f.requests() {
		if r.path == "/api/v4/groups/org%2Flibs" && r.query != "with_projects=false" {
			t.Errorf("group lookup query = %q, want with_projects=false", r.query)
		}
	}

	secrets := []string{"glpat-minted-xyz", "glpat-host"}
	if len(c.Status) != 1 || len(c.AgentNotes) != 1 {
		t.Fatalf("want one Status and one AgentNotes line, got %v / %v", c.Status, c.AgentNotes)
	}
	for _, want := range []string{"fine-grained personal access token", "realuser", "gitlab.example.com", "project org/app: download_code, push_code", "group org/libs: download_code", "expires"} {
		if !strings.Contains(c.Status[0], want) {
			t.Errorf("Status should mention %q: %q", want, c.Status[0])
		}
	}
	for _, want := range []string{"GITLAB_TOKEN", "fine-grained personal access token", "realuser", "project org/app: download_code, push_code", "group org/libs: download_code", "read_user", "read_personal_access_token", "expires", "403 Forbidden", "glab auth status"} {
		if !strings.Contains(c.AgentNotes[0], want) {
			t.Errorf("AgentNotes should mention %q: %q", want, c.AgentNotes[0])
		}
	}
	for _, want := range []string{"may still be live", "revoke", "expires on"} {
		if !strings.Contains(c.CleanupHint, want) {
			t.Errorf("CleanupHint should mention %q: %q", want, c.CleanupHint)
		}
	}
	for _, s := range secrets {
		for _, text := range []string{c.Status[0], c.AgentNotes[0], c.CleanupHint} {
			if strings.Contains(text, s) {
				t.Errorf("banner/note/hint must not carry a token value: %q", text)
			}
		}
	}
}

// The banner names each target's broadest preset plus the permissions beyond it; the agent note
// lists every permission.
func TestGitlabStatusNamesPresets(t *testing.T) {
	f := &fakeGitlab{ids: map[string]int{"projects/org%2Fapp": 42, "groups/org%2Flibs": 7, "projects/org%2Ftools": 8}}
	g := f.provider(t, Config{TokenGrants: []Grant{
		{Project: "org/app", Preset: PresetRead},
		{Project: "org/app", Preset: PresetWrite, Permissions: []string{"merge_merge_request"}},
		{Group: "org/libs"},
		{Project: "org/tools", Permissions: []string{"download_code"}},
	}})
	c, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s", WorkDir: t.TempDir()}, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "(project org/app: preset write + merge_merge_request; group org/libs: preset read; project org/tools: download_code; expires "
	if !strings.Contains(c.Status[0], want) {
		t.Errorf("Status = %q, want it to contain %q", c.Status[0], want)
	}
	if strings.Contains(c.AgentNotes[0], "preset") || !strings.Contains(c.AgentNotes[0], "read_wiki") {
		t.Errorf("AgentNotes must list every permission instead of presets: %q", c.AgentNotes[0])
	}
}

// Grants on the same target merge into one scope with the union of their permissions; GitLab
// rejects a second scope for a namespace already on the token.
func TestGitlabGrantMerging(t *testing.T) {
	origin := "git@gitlab.example.com:org/team/repo.git"
	for _, tc := range []struct {
		name    string
		grants  []Grant
		origin  string
		want    []string
		lookups map[string]int // escaped lookup path → expected GET count
	}{
		{
			name:   "path and numeric ID of one project",
			grants: []Grant{{Project: "org/app", Permissions: []string{"download_code"}}, {Project: "42", Permissions: []string{"push_code"}}},
			want:   []string{`{"access":"selected_memberships","permissions":["download_code","push_code"],"project_ids":[42]}`},
		},
		{
			name:   "targetless grant and the detected project named",
			grants: []Grant{{Permissions: []string{"push_code"}}, {Project: "org/team/repo", Permissions: []string{"download_code"}}},
			origin: origin,
			want:   []string{`{"access":"selected_memberships","permissions":["push_code","download_code"],"project_ids":[10]}`},
		},
		{
			name:    "same project from two layers is looked up once",
			grants:  []Grant{{Project: "org/app", Permissions: []string{"download_code"}}, {Project: "org/app", Permissions: []string{"push_code", "download_code"}}},
			want:    []string{`{"access":"selected_memberships","permissions":["download_code","push_code"],"project_ids":[42]}`},
			lookups: map[string]int{"/api/v4/projects/org%2Fapp": 1},
		},
		{
			name:   "project and its parent group stay separate",
			grants: []Grant{{Project: "org/app", Permissions: []string{"push_code"}}, {Group: "org", Permissions: []string{"download_code"}}},
			want: []string{
				`{"access":"selected_memberships","permissions":["push_code"],"project_ids":[42]}`,
				`{"access":"selected_memberships","group_ids":[1],"permissions":["download_code"]}`,
			},
		},
		{
			name:   "preset and a permission on the same project",
			grants: []Grant{{Project: "org/app", Preset: PresetRead}, {Project: "42", Permissions: []string{"push_code", "read_project"}}},
			want: []string{
				`{"access":"selected_memberships","permissions":` + mustJSON(t, append(slices.Clone(PresetReadPermissions), "push_code")) + `,"project_ids":[42]}`,
			},
		},
		{
			name:    "two targetless grants detect once",
			grants:  []Grant{{Permissions: []string{"download_code"}}, {Permissions: []string{"push_code"}}},
			origin:  origin,
			want:    []string{`{"access":"selected_memberships","permissions":["download_code","push_code"],"project_ids":[10]}`},
			lookups: map[string]int{"/api/v4/projects/org%2Fteam%2Frepo": 1},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeGitlab{ids: map[string]int{"projects/org%2Fapp": 42, "projects/42": 42, "projects/org%2Fteam%2Frepo": 10, "groups/org": 1}}
			g := f.provider(t, Config{TokenGrants: tc.grants})
			work := t.TempDir()
			if tc.origin != "" {
				work = workdirWithOrigin(t, tc.origin)
			}
			if _, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s", WorkDir: work}, false); err != nil {
				t.Fatal(err)
			}
			if got := f.selectedScopes(t); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("selected scopes =\n%v\nwant\n%v", got, tc.want)
			}
			for path, n := range tc.lookups {
				count := 0
				for _, r := range f.requests() {
					if r.method == http.MethodGet && r.path == path {
						count++
					}
				}
				if count != n {
					t.Errorf("GET %s ran %d times, want %d", path, count, n)
				}
			}
		})
	}
}

func TestGitlabResolveTarget(t *testing.T) {
	f := &fakeGitlab{
		ids:  map[string]int{"groups/org%2Fteam": 7, "projects/42": 42},
		fail: map[string]int{"/api/v4/projects/broken": http.StatusInternalServerError},
	}
	g := f.provider(t, Config{})
	ctx := context.Background()

	if id, err := g.resolveTarget(ctx, kindGroup, "org/team"); err != nil || id != 7 {
		t.Errorf("resolveTarget(group org/team) = %d, %v; want 7", id, err)
	}
	if id, err := g.resolveTarget(ctx, kindProject, "42"); err != nil || id != 42 {
		t.Errorf("resolveTarget(project 42) = %d, %v; want 42", id, err)
	}
	for _, tc := range []struct{ name, want string }{
		{"missing", "does not exist or the host GITLAB_TOKEN cannot see it"},
		{"broken", "500"},
	} {
		_, err := g.resolveTarget(ctx, kindProject, tc.name)
		if err == nil {
			t.Errorf("resolveTarget(project %s) must fail", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), `"`+tc.name+`"`) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("resolveTarget(project %s) error = %q, want it to name the target and %q", tc.name, err, tc.want)
		}
	}
	// A target that cannot be resolved stops the launch before any token is created.
	f2 := &fakeGitlab{}
	g2 := f2.provider(t, Config{TokenGrants: []Grant{{Project: "org/gone"}}})
	if _, err := g2.Mint(ctx, spec.Session{User: "u", ID: "s"}, false); err == nil || !strings.Contains(err.Error(), "org/gone") {
		t.Errorf("Mint with an unknown target = %v, want an error naming org/gone", err)
	}
	for _, r := range f2.requests() {
		if r.method == http.MethodPost {
			t.Error("no token may be created when a target cannot be resolved")
		}
	}
}

func TestGitlabOriginDetection(t *testing.T) {
	for _, tc := range []struct {
		name, origin string
		want         []string
	}{
		{name: "no origin remote", want: []string{"no origin remote", "providers.gitlab.grants"}},
		{name: "origin on another host", origin: "git@github.com:other/repo.git", want: []string{"github.com", "gitlab.example.com"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			work := t.TempDir()
			if tc.origin != "" {
				work = workdirWithOrigin(t, tc.origin)
			} else if err := os.MkdirAll(filepath.Join(work, ".git"), 0o755); err != nil {
				t.Fatal(err)
			} else if err := os.WriteFile(filepath.Join(work, ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			f := &fakeGitlab{}
			g := f.provider(t, Config{})
			_, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s", WorkDir: work}, false)
			if err == nil {
				t.Fatal("Mint must fail when the origin project cannot be detected")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q should mention %q", err, w)
				}
			}
		})
	}
}

// GitLab before 19.2 can answer with a legacy token. corral must revoke it and fail, never hand it
// to the session.
func TestGitlabMintRejectsLegacyToken(t *testing.T) {
	legacy := `{"id":99,"token":"glpat-legacy","scopes":["api"]}`
	f := &fakeGitlab{ids: map[string]int{"projects/org%2Fapp": 42}, createBody: legacy}
	g := f.provider(t, Config{TokenGrants: []Grant{{Project: "org/app"}}})
	_, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
	if err == nil || !strings.Contains(err.Error(), "not fine-grained") || strings.Contains(err.Error(), "glpat-legacy") {
		t.Fatalf("Mint = %v, want a secret-free 'not fine-grained' error", err)
	}
	reqs := f.requests()
	if last := reqs[len(reqs)-1]; last.method != http.MethodDelete || last.path != "/api/v4/personal_access_tokens/99" {
		t.Errorf("the legacy token must be revoked, last request was %s %s", last.method, last.path)
	}

	f2 := &fakeGitlab{
		ids:        map[string]int{"projects/org%2Fapp": 42},
		createBody: legacy,
		fail:       map[string]int{"/api/v4/personal_access_tokens/99": http.StatusInternalServerError},
	}
	g2 := f2.provider(t, Config{TokenGrants: []Grant{{Project: "org/app"}}})
	if _, err := g2.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false); err == nil || !strings.Contains(err.Error(), "may be live") {
		t.Fatalf("Mint with a failed revoke = %v, want an error saying the token may be live", err)
	}
}

func TestGitlabCreateErrorHints(t *testing.T) {
	const version = "GitLab 19.2 or later"
	for _, tc := range []struct {
		status        int
		want, notWant []string
	}{
		{status: http.StatusBadRequest, want: []string{"400", "from fake", version}},
		{status: http.StatusNotFound, want: []string{"404", "from fake", version, "fine-grained personal access tokens enabled", "member of every grant target", "project org/app", "group org"}},
		{status: http.StatusForbidden, want: []string{"403", "from fake"}, notWant: []string{version}},
		{status: http.StatusUnprocessableEntity, want: []string{"422", "from fake"}, notWant: []string{version}},
		{status: http.StatusInternalServerError, want: []string{"500", "from fake", "permission name this GitLab instance knows"}, notWant: []string{version}},
	} {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			f := &fakeGitlab{
				ids:  map[string]int{"projects/org%2Fapp": 42, "groups/org": 1},
				fail: map[string]int{createPath: tc.status},
			}
			g := f.provider(t, Config{TokenGrants: []Grant{{Project: "org/app"}, {Group: "org"}}})
			_, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
			if err == nil {
				t.Fatal("Mint must fail when the create request is rejected")
			}
			msg := err.Error()
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q should mention %q", msg, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(msg, w) {
					t.Errorf("error %q must not mention %q", msg, w)
				}
			}
			if strings.Index(msg, "from fake") > strings.Index(msg, "; the gitlab provider") && strings.Contains(msg, "; the gitlab provider") {
				t.Errorf("GitLab's message must come before the hint: %q", msg)
			}
		})
	}
}

func TestGitlabMintFailsClosed(t *testing.T) {
	f := &fakeGitlab{fail: map[string]int{"/api/v4/user": http.StatusForbidden}}
	g := f.provider(t, Config{TokenGrants: []Grant{{Project: "g/p"}}})
	if _, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false); err == nil {
		t.Fatal("Mint must fail closed when the API rejects the request")
	}
}

// A POST response with id<=0 (malformed) must fail closed: a 0 id would build a
// revoke URL that 404s, letting cleanup "succeed" while the token stays live.
func TestGitlabMintRejectsInvalidTokenID(t *testing.T) {
	f := &fakeGitlab{ids: map[string]int{"projects/g%2Fp": 1}, createBody: `{"id":0,"token":"glpat-minted","granular":true}`}
	g := f.provider(t, Config{TokenGrants: []Grant{{Project: "g/p"}}})
	_, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
	if err == nil || !strings.Contains(err.Error(), "invalid token id") {
		t.Fatalf("Mint = %v, want an invalid token id error (cleanup would not revoke)", err)
	}
}

// When the revoke (DELETE) fails with a non-2xx, Cleanup must surface the error so the
// launcher can warn the operator that a token may still be live (it is not silent).
func TestGitlabRevokeFailsClosed(t *testing.T) {
	f := &fakeGitlab{
		ids:  map[string]int{"projects/g%2Fp": 1},
		fail: map[string]int{"/api/v4/personal_access_tokens/99": http.StatusInternalServerError},
	}
	g := f.provider(t, Config{TokenGrants: []Grant{{Project: "g/p"}}})
	c, err := g.Mint(context.Background(), spec.Session{User: "u", ID: "s"}, false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := c.Cleanup(context.Background()); err == nil {
		t.Fatal("a failed revoke must return an error from Cleanup, not succeed silently")
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

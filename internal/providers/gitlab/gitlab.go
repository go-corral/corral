// Package gitlab implements the GitLab credential-minter provider: a short-lived fine-grained
// personal access token minted from the host $GITLAB_TOKEN, revoked on session exit.
package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/go-corral/corral/internal/providers/spec"
)

type gitlab struct {
	cfg     Config
	token   string // host $GITLAB_TOKEN — never forwarded into the sandbox
	hostEnv map[string]string
	host    string
	apiBase string // "https://"+host in production, overridden in tests
	client  *http.Client
}

// gitlabForwardEnv lists the glab connection/auth env vars forwarded into the sandbox when
// present on the host (the token is replaced by the minted one).
var gitlabForwardEnv = []string{"GITLAB_HOST", "GL_HOST", "GITLAB_CLIENT_ID", "REMOTE_ALIAS", "GIT_REMOTE_URL_VAR"}

// gitlabGlabCaveat rides every AgentNote: `glab auth status` only inspects glab's own config
// file, so env-var auth shows as "not logged in" even though glab commands and the API work.
const gitlabGlabCaveat = "`glab auth status` misreports GITLAB_TOKEN auth as unauthenticated; glab commands and the API work regardless."

const (
	kindProject = "project"
	kindGroup   = "group"
)

// New reads $GITLAB_TOKEN to mint from, resolves the instance from providers.gitlab.host, then
// $GITLAB_HOST/$GL_HOST, then gitlab.com. The host is never inferred from the workdir's git remote.
func New(cfg Config, hostEnv map[string]string) spec.Provider {
	host := resolveGitlabHost(cfg.Host, firstNonEmpty(hostEnv["GITLAB_HOST"], hostEnv["GL_HOST"]))
	return &gitlab{
		cfg:     cfg,
		token:   hostEnv["GITLAB_TOKEN"],
		hostEnv: hostEnv,
		host:    host,
		apiBase: "https://" + host,
		client:  &http.Client{Timeout: 15 * time.Second},
	}
}

func (g *gitlab) Name() string { return "gitlab" }

func (g *gitlab) Available(ctx context.Context) bool { return g.token != "" }

// Mint creates a fine-grained personal access token owned by the host credential's user through
// the self-service endpoint, which any user may call.
func (g *gitlab) Mint(ctx context.Context, sess spec.Session, dryRun bool) (*spec.Contribution, error) {
	if dryRun {
		return nil, spec.ErrNoDryRun("gitlab", "mint a scoped token without a live API call")
	}
	if g.token == "" {
		return nil, errors.New("gitlab: no host GITLAB_TOKEN to mint from")
	}
	_, username, err := g.currentUser(ctx)
	if err != nil {
		return nil, err
	}
	grants, err := g.resolveGrants(ctx, sess.WorkDir)
	if err != nil {
		return nil, err
	}
	expires := expiresTomorrow()
	// Never send legacy `scopes`: GitLab before 19.2 would ignore granular_scopes.
	body := map[string]any{
		"name":            g.tokenName(sess),
		"description":     "corral session token",
		"expires_at":      expires,
		"granular_scopes": granularScopes(grants),
	}
	tok, err := g.createToken(ctx, "/api/v4/user/personal_access_tokens", body)
	if err != nil {
		return nil, fmt.Errorf("gitlab: create fine-grained personal access token: %w%s", err, createHint(err, grants))
	}
	revoke := g.revokeCleanup(fmt.Sprintf("/api/v4/personal_access_tokens/%d", tok.ID))
	if !tok.Granular {
		if rerr := revoke(ctx); rerr != nil {
			return nil, fmt.Errorf("gitlab: GitLab created a token that is not fine-grained, and revoking it failed (%v); it may be live until it expires on %s — revoke it under %s (User settings → Access tokens)", rerr, expires, g.host)
		}
		return nil, errors.New("gitlab: GitLab created a token that is not fine-grained; corral revoked it. The gitlab provider needs GitLab 19.2 or later with fine-grained personal access tokens enabled")
	}
	return &spec.Contribution{
		Env: g.contributionEnv(tok.Token),
		Status: []string{fmt.Sprintf("minted fine-grained personal access token for %s on %s (%s; expires %s)",
			username, g.host, describeGrants(grants, true), expires)},
		AgentNotes: []string{fmt.Sprintf("GITLAB_TOKEN holds a fine-grained personal access token for %s on %s (%s; plus read_user and read_personal_access_token on the user's own account; expires %s). Requests outside these permissions return 403 Forbidden; do not retry them with other credentials. %s",
			username, g.host, describeGrants(grants, false), expires, gitlabGlabCaveat)},
		CleanupHint: fmt.Sprintf("the minted token may still be live until it expires on %s — revoke it under %s (User settings → Access tokens) if needed", expires, g.host),
		Cleanup:     revoke,
	}, nil
}

// expiresTomorrow is the minted token's expiry: GitLab's minimum granularity is a calendar day.
func expiresTomorrow() string {
	return time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")
}

// resolvedGrant is a grant whose target has a numeric ID. name is the target as first named in
// config (or detected), and preset the broadest preset among its grants, for status text.
type resolvedGrant struct {
	kind   string
	name   string
	id     int
	preset string
	perms  []string
}

// resolveGrants resolves each grant's target to its numeric ID and merges grants per target: GitLab
// silently drops unknown IDs and rejects a second scope for the same namespace.
func (g *gitlab) resolveGrants(ctx context.Context, workDir string) ([]resolvedGrant, error) {
	var (
		out      []resolvedGrant
		byTarget = map[string]int{} // kind+id → index in out
		ids      = map[string]int{} // kind+name as written → id
		detected string
	)
	for _, gr := range g.cfg.EffectiveGrants() {
		kind, name := kindProject, gr.Project
		if gr.Group != "" {
			kind, name = kindGroup, gr.Group
		}
		if name == "" {
			if detected == "" {
				p, err := detectProject(workDir, g.host)
				if err != nil {
					return nil, fmt.Errorf("gitlab: %w; set project or group in providers.gitlab.grants", err)
				}
				detected = p
			}
			name = detected
		}
		id, ok := ids[kind+"\x00"+name]
		if !ok {
			var err error
			if id, err = g.resolveTarget(ctx, kind, name); err != nil {
				return nil, err
			}
			ids[kind+"\x00"+name] = id
		}
		key := fmt.Sprintf("%s\x00%d", kind, id)
		i, ok := byTarget[key]
		if !ok {
			i = len(out)
			byTarget[key] = i
			out = append(out, resolvedGrant{kind: kind, name: name, id: id})
		}
		if p := gr.effectivePreset(); p == PresetWrite || out[i].preset == "" {
			out[i].preset = p
		}
		out[i].perms = appendUnique(out[i].perms, gr.EffectivePermissions())
	}
	return out, nil
}

// resolveTarget returns the numeric ID of a project or group given as a path or ID.
func (g *gitlab) resolveTarget(ctx context.Context, kind, name string) (int, error) {
	path := "/api/v4/projects/" + escapeProject(name)
	if kind == kindGroup {
		path = "/api/v4/groups/" + escapeProject(name) + "?with_projects=false"
	}
	resp, err := g.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return 0, fmt.Errorf("gitlab: look up %s %q: %w", kind, name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if !is2xx(resp.StatusCode) {
		return 0, fmt.Errorf("gitlab: look up %s %q: %s: it does not exist or the host GITLAB_TOKEN cannot see it", kind, name, gitlabError(resp))
	}
	var out struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("gitlab: decode %s %q: %w", kind, name, err)
	}
	return out.ID, nil
}

// userPermissions is the fixed user-level scope: read_user for GET /user (glab's current-user
// lookup), read_personal_access_token for GET /personal_access_tokens/self.
var userPermissions = []string{"read_user", "read_personal_access_token"}

// granularScopes builds one selected_memberships scope per target, then the user scope.
func granularScopes(grants []resolvedGrant) []map[string]any {
	scopes := make([]map[string]any, 0, len(grants)+1)
	for _, r := range grants {
		idsKey := "project_ids"
		if r.kind == kindGroup {
			idsKey = "group_ids"
		}
		scopes = append(scopes, map[string]any{
			"access":      "selected_memberships",
			idsKey:        []int{r.id},
			"permissions": r.perms,
		})
	}
	return append(scopes, map[string]any{"access": "user", "permissions": userPermissions})
}

// describeGrants lists each target with its permissions. byPreset names a target's preset instead of
// the permissions it holds.
func describeGrants(grants []resolvedGrant, byPreset bool) string {
	parts := make([]string, len(grants))
	for i, r := range grants {
		perms := strings.Join(r.perms, ", ")
		if byPreset && r.preset != "" {
			perms = "preset " + r.preset
			if extra := slices.DeleteFunc(slices.Clone(r.perms), func(p string) bool {
				return slices.Contains(presets[r.preset], p)
			}); len(extra) > 0 {
				perms += " + " + strings.Join(extra, ", ")
			}
		}
		parts[i] = fmt.Sprintf("%s %s: %s", r.kind, r.name, perms)
	}
	return strings.Join(parts, "; ")
}

// createHint names the requirements behind a rejected create call. It states requirements, not a
// diagnosed cause.
func createHint(err error, grants []resolvedGrant) string {
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		return ""
	}
	switch apiErr.status {
	case http.StatusBadRequest:
		return "; the gitlab provider needs GitLab 19.2 or later"
	case http.StatusNotFound:
		targets := make([]string, len(grants))
		for i, r := range grants {
			targets[i] = r.kind + " " + r.name
		}
		return fmt.Sprintf("; the gitlab provider needs GitLab 19.2 or later with fine-grained personal access tokens enabled, and the user must be a member of every grant target (%s)", strings.Join(targets, ", "))
	case http.StatusInternalServerError:
		// GitLab answers an unknown permission name with a generic 500.
		return "; every permission in providers.gitlab.grants must be a fine-grained permission name this GitLab instance knows"
	}
	return ""
}

func appendUnique(dst, src []string) []string {
	for _, s := range src {
		if !slices.Contains(dst, s) {
			dst = append(dst, s)
		}
	}
	return dst
}

func (g *gitlab) tokenName(sess spec.Session) string {
	return "corral-" + spec.SanitizeLabel(sess.User) + "-" + spec.SanitizeLabel(sess.ID)
}

func (g *gitlab) currentUser(ctx context.Context) (int, string, error) {
	resp, err := g.do(ctx, http.MethodGet, "/api/v4/user", nil)
	if err != nil {
		return 0, "", fmt.Errorf("gitlab: resolve current user: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if !is2xx(resp.StatusCode) {
		return 0, "", fmt.Errorf("gitlab: resolve current user: %s", gitlabError(resp))
	}
	var u struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return 0, "", fmt.Errorf("gitlab: decode current user: %w", err)
	}
	if u.ID <= 0 {
		return 0, "", errors.New("gitlab: server returned an invalid user id")
	}
	return u.ID, u.Username, nil
}

// apiError is a non-2xx GitLab response, keeping the status for createHint.
type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

type createdToken struct {
	ID       int    `json:"id"`
	Token    string `json:"token"`
	Granular bool   `json:"granular"`
}

// createToken POSTs a token-create request and returns the new token. A zero id would make the
// revoke URL a no-op (it 404s) and let cleanup "succeed" while the token stays live.
func (g *gitlab) createToken(ctx context.Context, path string, body any) (createdToken, error) {
	resp, err := g.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return createdToken{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if !is2xx(resp.StatusCode) {
		return createdToken{}, &apiError{status: resp.StatusCode, msg: gitlabError(resp)}
	}
	var out createdToken
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return createdToken{}, fmt.Errorf("decode token response: %w", err)
	}
	if out.Token == "" {
		return createdToken{}, errors.New("server returned an empty token")
	}
	if out.ID <= 0 {
		return createdToken{}, fmt.Errorf("server returned an invalid token id %d", out.ID)
	}
	return out, nil
}

func (g *gitlab) revokeCleanup(path string) func(context.Context) error {
	return func(ctx context.Context) error {
		r, err := g.do(ctx, http.MethodDelete, path, nil)
		if err != nil {
			return fmt.Errorf("gitlab: revoke token: %w", err)
		}
		defer func() { _ = r.Body.Close() }()
		if is2xx(r.StatusCode) || r.StatusCode == http.StatusNotFound {
			return nil
		}
		return fmt.Errorf("gitlab: revoke token: %s", gitlabError(r))
	}
}

func (g *gitlab) contributionEnv(mintedToken string) map[string]string {
	env := map[string]string{}
	for _, k := range gitlabForwardEnv {
		if v := g.hostEnv[k]; v != "" {
			env[k] = v
		}
	}
	if g.cfg.Host != "" {
		env["GITLAB_HOST"] = g.cfg.Host
	}
	env["GITLAB_TOKEN"] = mintedToken
	return env
}

func (g *gitlab) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("gitlab: marshal request body: %w", err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.apiBase+path, rdr)
	if err != nil {
		return nil, fmt.Errorf("gitlab: build request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", g.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return g.client.Do(req)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// resolveGitlabHost resolves the instance host: config > env ($GITLAB_HOST/$GL_HOST) > gitlab.com.
// The host is never inferred from the workdir's git remote — the operator must explicitly name the
// instance so the host token is never sent to a .git/config-derived destination.
func resolveGitlabHost(cfgHost, envHost string) string {
	h := firstNonEmpty(cfgHost, envHost)
	if h == "" {
		h = "gitlab.com"
	}
	h = strings.TrimPrefix(h, "https://")
	h = strings.TrimPrefix(h, "http://")
	return strings.TrimSuffix(h, "/")
}

// escapeProject encodes a project path/ID as a single URL path segment: GitLab identifies projects
// by URL-encoded path, so slashes become %2F.
func escapeProject(p string) string {
	return strings.ReplaceAll(url.PathEscape(p), "/", "%2F")
}

func is2xx(code int) bool { return code >= 200 && code < 300 }

// gitlabError renders a non-2xx response: status plus a capped body snippet (GitLab returns
// {"message": ...}). The response carries no secret (token creation failed).
func gitlabError(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if msg := strings.TrimSpace(string(b)); msg != "" {
		return resp.Status + " " + msg
	}
	return resp.Status
}

// detectProject derives the GitLab project path from the workdir's origin remote for a grant
// without a target. Requires the remote host to match the configured GitLab host.
func detectProject(workDir, host string) (string, error) {
	if workDir == "" {
		return "", errors.New("a grant has no target and there is no workdir to detect the origin project from")
	}
	data, err := os.ReadFile(filepath.Join(workDir, ".git", "config"))
	if err != nil {
		return "", fmt.Errorf("a grant has no target and the workdir git config is unreadable: %w", err)
	}
	originURL := parseOriginURL(string(data))
	if originURL == "" {
		return "", errors.New("a grant has no target and the workdir has no origin remote")
	}
	h, project, err := parseGitlabURL(originURL)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(h, host) {
		return "", fmt.Errorf("origin remote host %q does not match the GitLab host %q", h, host)
	}
	return project, nil
}

func parseOriginURL(cfg string) string {
	inOrigin := false
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			inOrigin = t == `[remote "origin"]`
			continue
		}
		if inOrigin && strings.HasPrefix(t, "url") {
			if i := strings.IndexByte(t, '='); i >= 0 {
				return strings.TrimSpace(t[i+1:])
			}
		}
	}
	return ""
}

// parseGitlabURL splits a git remote URL into host + project path, handling https, ssh:// and
// scp-like (git@host:group/repo.git) forms and stripping the .git suffix.
func parseGitlabURL(raw string) (host, project string, err error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "http://"), strings.HasPrefix(raw, "https://"), strings.HasPrefix(raw, "ssh://"):
		u, e := url.Parse(raw)
		if e != nil {
			return "", "", e
		}
		host = u.Hostname()
		project = strings.TrimPrefix(u.Path, "/")
	case strings.Contains(raw, "@") && strings.Contains(raw, ":"):
		at := strings.IndexByte(raw, '@')
		rest := raw[at+1:]
		colon := strings.IndexByte(rest, ':')
		if colon < 0 {
			return "", "", fmt.Errorf("unrecognized git remote URL %q", raw)
		}
		host = rest[:colon]
		project = rest[colon+1:]
	default:
		return "", "", fmt.Errorf("unrecognized git remote URL %q", raw)
	}
	project = strings.Trim(strings.TrimSuffix(project, ".git"), "/")
	if host == "" || project == "" || strings.Contains(project, ":") {
		return "", "", fmt.Errorf("could not parse a project from git remote URL %q", raw)
	}
	return host, project, nil
}

// Package gitlab implements the GitLab credential-minter provider: a scoped, short-lived
// personal/project access token minted from the host $GITLAB_TOKEN, revoked on session exit.
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

func (g *gitlab) Mint(ctx context.Context, sess spec.Session, dryRun bool) (*spec.Contribution, error) {
	if dryRun {
		return nil, spec.ErrNoDryRun("gitlab", "mint a scoped token without a live API call")
	}
	if g.token == "" {
		return nil, errors.New("gitlab: no host GITLAB_TOKEN to mint from")
	}
	if g.cfg.EffectiveType() == TypePersonal {
		return g.mintPersonal(ctx, sess)
	}
	return g.mintProject(ctx, sess)
}

// expiresTomorrow is the minted token's expiry: GitLab's minimum granularity is a calendar day.
func expiresTomorrow() string {
	return time.Now().UTC().AddDate(0, 0, 1).Format("2006-01-02")
}

func (g *gitlab) mintProject(ctx context.Context, sess spec.Session) (*spec.Contribution, error) {
	project := g.cfg.Project
	if project == "" {
		p, err := detectProject(sess.WorkDir, g.host)
		if err != nil {
			return nil, fmt.Errorf("gitlab: %w; set providers.gitlab.project", err)
		}
		project = p
	}
	esc := escapeProject(project)
	expires := expiresTomorrow()
	body := map[string]any{
		"name":         g.tokenName(sess),
		"scopes":       g.cfg.EffectiveScopes(),
		"access_level": g.cfg.EffectiveAccessLevel(),
		"expires_at":   expires,
	}
	id, token, err := g.createToken(ctx, "/api/v4/projects/"+esc+"/access_tokens", body)
	if err != nil {
		return nil, fmt.Errorf("gitlab: create project access token for %q: %w", project, err)
	}
	return &spec.Contribution{
		Env: g.contributionEnv(token),
		Status: []string{fmt.Sprintf("minted project access token for %s on %s (scopes: %s; role: %s; expires %s)",
			project, g.host, strings.Join(g.cfg.EffectiveScopes(), ", "), g.cfg.EffectiveRole(), expires)},
		AgentNotes: []string{fmt.Sprintf("GITLAB_TOKEN holds a project access token for %s on %s (scopes: %s; role: %s; expires %s). %s",
			project, g.host, strings.Join(g.cfg.EffectiveScopes(), ", "), g.cfg.EffectiveRole(), expires, gitlabGlabCaveat)},
		CleanupHint: fmt.Sprintf("the minted token for %s may still be live until it expires on %s — revoke it under the project's Settings → Access Tokens if needed", project, expires),
		Cleanup:     g.revokeCleanup(fmt.Sprintf("/api/v4/projects/%s/access_tokens/%d", esc, id)),
	}, nil
}

// mintPersonal mints a personal access token owned by the host credential's own user, so created
// objects attribute to that real user. Uses the admin endpoint POST /users/:id/personal_access_tokens,
// so the host $GITLAB_TOKEN must carry admin rights; a non-admin token gets a 403 and fails closed.
func (g *gitlab) mintPersonal(ctx context.Context, sess spec.Session) (*spec.Contribution, error) {
	uid, username, err := g.currentUser(ctx)
	if err != nil {
		return nil, err
	}
	expires := expiresTomorrow()
	body := map[string]any{
		"name":       g.tokenName(sess),
		"scopes":     g.cfg.EffectiveScopes(),
		"expires_at": expires,
	}
	id, token, err := g.createToken(ctx, fmt.Sprintf("/api/v4/users/%d/personal_access_tokens", uid), body)
	if err != nil {
		return nil, fmt.Errorf("gitlab: create personal access token (the host GITLAB_TOKEN needs admin rights to mint a PAT): %w", err)
	}
	return &spec.Contribution{
		Env: g.contributionEnv(token),
		Status: []string{fmt.Sprintf("minted personal access token for %s on %s (scopes: %s; expires %s)",
			username, g.host, strings.Join(g.cfg.EffectiveScopes(), ", "), expires)},
		AgentNotes: []string{fmt.Sprintf("GITLAB_TOKEN holds a personal access token for %s on %s (scopes: %s; expires %s). %s",
			username, g.host, strings.Join(g.cfg.EffectiveScopes(), ", "), expires, gitlabGlabCaveat)},
		CleanupHint: fmt.Sprintf("the minted personal access token may still be live until it expires on %s — revoke it under %s (User settings → Access tokens) if needed", expires, g.host),
		Cleanup:     g.revokeCleanup(fmt.Sprintf("/api/v4/personal_access_tokens/%d", id)),
	}, nil
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

// createToken POSTs a token-create request and returns the new token's id + value. A zero id
// would make the revoke URL a no-op (it 404s) and let cleanup "succeed" while the token stays live.
func (g *gitlab) createToken(ctx context.Context, path string, body any) (int, string, error) {
	resp, err := g.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if !is2xx(resp.StatusCode) {
		return 0, "", errors.New(gitlabError(resp))
	}
	var out struct {
		ID    int    `json:"id"`
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, "", fmt.Errorf("decode token response: %w", err)
	}
	if out.Token == "" {
		return 0, "", errors.New("server returned an empty token")
	}
	if out.ID <= 0 {
		return 0, "", fmt.Errorf("server returned an invalid token id %d", out.ID)
	}
	return out.ID, out.Token, nil
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
// instance so the admin token is never sent to a .git/config-derived destination.
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

// detectProject derives the GitLab project path from the workdir's origin remote when
// providers.gitlab.project is unset. Requires the remote host to match the configured GitLab host.
func detectProject(workDir, host string) (string, error) {
	if workDir == "" {
		return "", errors.New("no project configured and no workdir to auto-detect from")
	}
	data, err := os.ReadFile(filepath.Join(workDir, ".git", "config"))
	if err != nil {
		return "", fmt.Errorf("no project configured and cannot read the workdir git config: %w", err)
	}
	originURL := parseOriginURL(string(data))
	if originURL == "" {
		return "", errors.New("no project configured and the workdir has no origin remote")
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

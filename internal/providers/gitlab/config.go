package gitlab

import "fmt"

// Config configures the gitlab credential-minter: a scoped, short-lived personal or project
// access token minted outside the sandbox from a host credential ($GITLAB_TOKEN), injected as env
// (GITLAB_TOKEN/GITLAB_HOST). The minted token's effective power is the intersection of its Scopes,
// its Role, and the host credential's own role on the project (project tokens) or account (personal).
type Config struct {
	Enabled  bool `yaml:"enabled"`
	Optional bool `yaml:"optional"`
	// Host is the GitLab instance host (no scheme). Empty => $GITLAB_HOST/$GL_HOST, then gitlab.com.
	// Must be set explicitly for self-hosted instances — never inferred from .git/config.
	Host string `yaml:"host"`
	// Type: "personal" (default, admin host token required) or "project" (scoped to one project).
	Type string `yaml:"type"`
	// Project is the target project (path "group/repo" or numeric ID). Empty => auto-detected from
	// the workdir's origin remote. Used only by type: project.
	Project string `yaml:"project"`
	// Scopes are the minted token's scopes. Empty => read-only default (EffectiveScopes).
	Scopes []string `yaml:"scopes"`
	// Role caps the minted token's project role (guest|reporter|developer|maintainer|owner).
	// Empty => developer. Ignored by type: personal (a PAT carries the user's own access).
	Role string `yaml:"role"`
}

const (
	TypeProject  = "project"
	TypePersonal = "personal"
)

func (g Config) EffectiveType() string {
	if g.Type != "" {
		return g.Type
	}
	return TypePersonal
}

// DefaultScopes is the fail-safe default: read-only repository access plus read_api.
var DefaultScopes = []string{"read_repository", "read_api"}

var roles = map[string]int{
	"guest":      10,
	"reporter":   20,
	"developer":  30,
	"maintainer": 40,
	"owner":      50,
}

func (g Config) Grants() string {
	return fmt.Sprintf("scoped GitLab %s access token (env: GITLAB_TOKEN + forwarded glab vars)", g.EffectiveType())
}

func (g Config) EffectiveScopes() []string {
	if len(g.Scopes) > 0 {
		return g.Scopes
	}
	return append([]string(nil), DefaultScopes...)
}

func (g Config) EffectiveAccessLevel() int {
	if lvl, ok := roles[g.Role]; ok {
		return lvl
	}
	return roles["developer"]
}

func (g Config) EffectiveRole() string {
	if g.Role != "" {
		return g.Role
	}
	return "developer"
}

// Validate checks the bounded fields (the GitLab server validates scopes + project access at Mint).
func (g Config) Validate() error {
	if g.Type != "" && g.Type != TypeProject && g.Type != TypePersonal {
		return fmt.Errorf("providers.gitlab.type: %q is not a token type (project|personal)", g.Type)
	}
	// A personal access token has no per-project role; accepting `role` with type: personal would
	// silently ignore it, so reject the combination.
	if g.EffectiveType() == TypePersonal && g.Role != "" {
		return fmt.Errorf("providers.gitlab.role is set but type defaults to personal; a personal access token has no project role — remove role, or set type: project")
	}
	if g.Role != "" {
		if _, ok := roles[g.Role]; !ok {
			return fmt.Errorf("providers.gitlab.role: %q is not a GitLab role (guest|reporter|developer|maintainer|owner)", g.Role)
		}
	}
	return nil
}

package gitlab

import "testing"

func TestGitlabDefaultsApplyInCode(t *testing.T) {
	g := Config{}
	if s := g.EffectiveScopes(); len(s) != 2 || s[0] != "read_repository" || s[1] != "read_api" {
		t.Errorf("default scopes = %v, want [read_repository read_api] (read-only)", s)
	}
	if g.EffectiveAccessLevel() != 30 {
		t.Errorf("default role must map to 30 (developer), got %d", g.EffectiveAccessLevel())
	}
	if g.EffectiveType() != TypePersonal {
		t.Errorf("default type must be %q, got %q", TypePersonal, g.EffectiveType())
	}
	g = Config{Scopes: []string{"api"}, Role: "maintainer", Type: "project"}
	if s := g.EffectiveScopes(); len(s) != 1 || s[0] != "api" {
		t.Errorf("explicit scopes must win, got %v", s)
	}
	if g.EffectiveAccessLevel() != 40 {
		t.Errorf("explicit role (maintainer=40) must win: %+v", g)
	}
	if g.EffectiveType() != TypeProject {
		t.Errorf("explicit type must win, got %q", g.EffectiveType())
	}
}

func TestGitlabEffectiveRoleDefault(t *testing.T) {
	g := Config{}
	if got := g.EffectiveRole(); got != "developer" {
		t.Errorf("Config{}.EffectiveRole() = %q, want 'developer'", got)
	}
}

func TestGitlabEffectiveRoleExplicit(t *testing.T) {
	for _, role := range []string{"guest", "reporter", "developer", "maintainer", "owner"} {
		g := Config{Role: role}
		if got := g.EffectiveRole(); got != role {
			t.Errorf("Config{Role: %q}.EffectiveRole() = %q, want %q", role, got, role)
		}
	}
}

// EffectiveAccessLevel maps every valid role name to its numeric level.
func TestGitlabRolesMapping(t *testing.T) {
	expected := map[string]int{
		"guest":      10,
		"reporter":   20,
		"developer":  30,
		"maintainer": 40,
		"owner":      50,
	}
	for role, level := range expected {
		g := Config{Role: role}
		if got := g.EffectiveAccessLevel(); got != level {
			t.Errorf("Config{Role: %q}.EffectiveAccessLevel() = %d, want %d", role, got, level)
		}
	}
}

package gitlab

import (
	"fmt"
	"slices"
)

// Config configures the gitlab credential-minter. The token holds only the permissions its grants
// name, on the targets they name.
type Config struct {
	Enabled  bool `yaml:"enabled"`
	Optional bool `yaml:"optional"`
	// Host is the GitLab instance host (no scheme). Empty => $GITLAB_HOST/$GL_HOST, then gitlab.com.
	// Must be set explicitly for self-hosted instances — never inferred from .git/config.
	Host string `yaml:"host"`
	// TokenGrants empty => the read preset on the origin project. The default stays in code because
	// YAML lists merge additively.
	TokenGrants []Grant `yaml:"grants"`
}

// Grant is one target with its permissions. At most one of Project and Group (path or numeric ID);
// neither => the project detected from the workdir's origin remote.
type Grant struct {
	Project string `yaml:"project"`
	Group   string `yaml:"group"`
	// Preset is PresetRead, PresetWrite, or empty.
	Preset string `yaml:"preset"`
	// Permissions are GitLab fine-grained permission names, added to the preset.
	Permissions []string `yaml:"permissions"`
}

const (
	PresetRead  = "read"
	PresetWrite = "write"
)

// PresetReadPermissions is the fail-safe default: read-only REST, GraphQL, and Git access.
var PresetReadPermissions = []string{
	"read_project",
	"read_group",
	"download_code",
	"read_code",
	"read_repository",
	"read_commit",
	"read_branch",
	"read_repository_tag",
	"read_protected_branch",
	"read_protected_tag",
	"read_approval_rule",
	"read_push_rule",
	"read_merge_request",
	"read_work_item",
	"read_label",
	"use_global_search",
	"read_pipeline",
	"read_pipeline_schedule",
	"read_job",
	"read_job_artifact",
	"read_ci_config",
	"read_runner",
	"read_environment",
	"read_deployment",
	"read_release",
	"read_container_repository",
	"read_package",
	"read_wiki",
}

// PresetWritePermissions adds the development loop to PresetReadPermissions.
var PresetWritePermissions = slices.Concat(PresetReadPermissions, []string{
	"push_code",
	"create_branch",
	"create_commit",
	"create_merge_request",
	"update_merge_request",
	"create_work_item",
	"update_work_item",
	"create_pipeline",
	"update_pipeline",
	"run_job",
	"update_job",
})

// Every preset name must exist in GitLab 19.2: GitLab fails the whole create on an unknown name.
var presets = map[string][]string{
	PresetRead:  PresetReadPermissions,
	PresetWrite: PresetWritePermissions,
}

func (g Config) Grants() string {
	return "scoped GitLab fine-grained personal access token (env: GITLAB_TOKEN + forwarded glab vars)"
}

func (g Config) EffectiveGrants() []Grant {
	if len(g.TokenGrants) > 0 {
		return g.TokenGrants
	}
	return []Grant{{}}
}

func (gr Grant) effectivePreset() string {
	if gr.Preset == "" && len(gr.Permissions) == 0 {
		return PresetRead
	}
	return gr.Preset
}

func (gr Grant) EffectivePermissions() []string {
	return appendUnique(slices.Clone(presets[gr.effectivePreset()]), gr.Permissions)
}

// Validate checks the grants. GitLab validates targets and permission names at Mint.
func (g Config) Validate() error {
	for i, gr := range g.TokenGrants {
		if gr.Project != "" && gr.Group != "" {
			return fmt.Errorf("providers.gitlab.grants[%d]: set at most one of project or group (got project %q and group %q); use one grant per target", i, gr.Project, gr.Group)
		}
		if _, ok := presets[gr.Preset]; gr.Preset != "" && !ok {
			return fmt.Errorf("providers.gitlab.grants[%d].preset: unknown preset %q; use %s or %s", i, gr.Preset, PresetRead, PresetWrite)
		}
	}
	return nil
}

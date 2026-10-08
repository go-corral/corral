package gitlab

import (
	"slices"
	"strings"
	"testing"
)

func TestGitlabDefaultsApplyInCode(t *testing.T) {
	grants := Config{}.EffectiveGrants()
	if len(grants) != 1 || grants[0].Project != "" || grants[0].Group != "" {
		t.Fatalf("empty config must yield one targetless grant, got %+v", grants)
	}
	perms := grants[0].EffectivePermissions()
	want := []string{
		"read_project", "read_group", "download_code", "read_code", "read_repository",
		"read_commit", "read_branch", "read_repository_tag", "read_protected_branch",
		"read_protected_tag", "read_approval_rule", "read_push_rule", "read_merge_request",
		"read_work_item", "read_label", "use_global_search", "read_pipeline",
		"read_pipeline_schedule", "read_job", "read_job_artifact", "read_ci_config", "read_runner",
		"read_environment", "read_deployment", "read_release", "read_container_repository",
		"read_package", "read_wiki",
	}
	if !slices.Equal(perms, want) {
		t.Errorf("default permissions = %v, want %v (read-only)", perms, want)
	}
	perms[0] = "push_code"
	if PresetReadPermissions[0] != "read_project" {
		t.Error("mutating the effective permissions must not change PresetReadPermissions")
	}
}

// The read preset is the fail-safe default and must stay read-only; the write preset extends it.
func TestGitlabPresetContents(t *testing.T) {
	for _, p := range PresetReadPermissions {
		if !strings.HasPrefix(p, "read_") && !strings.HasPrefix(p, "download_") && !strings.HasPrefix(p, "use_") {
			t.Errorf("read preset holds %q, which is not a read permission", p)
		}
	}
	if !slices.Equal(PresetWritePermissions[:len(PresetReadPermissions)], PresetReadPermissions) {
		t.Error("the write preset must start with the read preset")
	}
	for name, perms := range presets {
		if len(appendUnique(nil, perms)) != len(perms) {
			t.Errorf("preset %s lists a permission twice", name)
		}
	}
}

func TestGitlabPresets(t *testing.T) {
	for _, tc := range []struct {
		name  string
		grant Grant
		want  []string
	}{
		{name: "no preset, no permissions", grant: Grant{}, want: PresetReadPermissions},
		{name: "read preset", grant: Grant{Preset: PresetRead}, want: PresetReadPermissions},
		{name: "write preset", grant: Grant{Preset: PresetWrite}, want: PresetWritePermissions},
		{
			name:  "permissions add to the preset",
			grant: Grant{Preset: PresetRead, Permissions: []string{"read_variable"}},
			want:  append(slices.Clone(PresetReadPermissions), "read_variable"),
		},
		{
			name:  "a permission already in the preset is not repeated",
			grant: Grant{Preset: PresetWrite, Permissions: []string{"push_code", "merge_merge_request"}},
			want:  append(slices.Clone(PresetWritePermissions), "merge_merge_request"),
		},
		{
			name:  "permissions without a preset replace the default",
			grant: Grant{Permissions: []string{"download_code", "push_code"}},
			want:  []string{"download_code", "push_code"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.grant.EffectivePermissions(); !slices.Equal(got, tc.want) {
				t.Errorf("EffectivePermissions() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGitlabExplicitGrantsWin(t *testing.T) {
	g := Config{TokenGrants: []Grant{
		{Project: "org/app", Permissions: []string{"download_code", "push_code"}},
		{Group: "org/libs"},
	}}
	grants := g.EffectiveGrants()
	if len(grants) != 2 || grants[0].Project != "org/app" || grants[1].Group != "org/libs" {
		t.Fatalf("explicit grants must win, got %+v", grants)
	}
	if p := grants[0].EffectivePermissions(); !slices.Equal(p, []string{"download_code", "push_code"}) {
		t.Errorf("explicit permissions must win, got %v", p)
	}
	if p := grants[1].EffectivePermissions(); !slices.Equal(p, PresetReadPermissions) {
		t.Errorf("a grant without permissions must get the default, got %v", p)
	}
}

func TestGitlabGrantsText(t *testing.T) {
	if got := (Config{}).Grants(); !strings.Contains(got, "fine-grained personal access token") {
		t.Errorf("Grants() = %q, want it to name a fine-grained personal access token", got)
	}
}

func TestGitlabTokenLifetimeDays(t *testing.T) {
	if got := (Config{}).EffectiveTokenLifetimeDays(); got != 1 {
		t.Errorf("Config{}.EffectiveTokenLifetimeDays() = %d, want 1", got)
	}
	if got := (Config{TokenLifetimeDays: new(7)}).EffectiveTokenLifetimeDays(); got != 7 {
		t.Errorf("EffectiveTokenLifetimeDays() with 7 = %d, want 7", got)
	}
}

func TestGitlabValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr []string
	}{
		{name: "empty config", cfg: Config{}},
		{name: "targetless grant", cfg: Config{TokenGrants: []Grant{{Permissions: []string{"push_code"}}}}},
		{name: "project and group grants", cfg: Config{TokenGrants: []Grant{{Project: "org/app"}, {Group: "org"}}}},
		{name: "presets", cfg: Config{TokenGrants: []Grant{{Preset: PresetRead}, {Group: "org", Preset: PresetWrite}}}},
		{name: "lifetime 1 day", cfg: Config{TokenLifetimeDays: new(1)}},
		{
			name:    "lifetime 0 days",
			cfg:     Config{TokenLifetimeDays: new(0)},
			wantErr: []string{"providers.gitlab.tokenLifetimeDays", "0", "at least 1"},
		},
		{
			name:    "unknown preset",
			cfg:     Config{TokenGrants: []Grant{{Preset: PresetRead}, {Preset: "admin"}}},
			wantErr: []string{"providers.gitlab.grants[1].preset", `"admin"`, "read", "write"},
		},
		{
			name:    "two targets in one grant",
			cfg:     Config{TokenGrants: []Grant{{Project: "org/app"}, {Project: "org/app", Group: "org"}}},
			wantErr: []string{"providers.gitlab.grants[1]", "project", "group"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if len(tt.wantErr) == 0 {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatal("Validate() = nil, want an error")
			}
			for _, w := range tt.wantErr {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q", err, w)
				}
			}
		})
	}
}

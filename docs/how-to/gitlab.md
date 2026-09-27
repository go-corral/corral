# Set up GitLab credentials

The GitLab provider uses the host's `GITLAB_TOKEN` to create a fine-grained personal access token through the GitLab API outside the sandbox. It sets the new token as `GITLAB_TOKEN` in the session, forwards relevant `glab` connection variables, and revokes the token when the session ends. The host token is never forwarded.

The session token:

- belongs to your GitLab user, so GitLab attributes API actions and pushes to you.
- holds only the permissions you grant, on the projects and groups you name.
- expires after one day, GitLab's minimum expiry granularity.

## Requirements

- GitLab 19.2 or later, with fine-grained personal access tokens enabled. On gitlab.com they're available on every tier.
- Your user is a member of every project and group the token targets.

The provider needs no administrator rights.

## Set the host credential

Export a host token in the shell that starts corral:

```sh
export GITLAB_TOKEN=...
```

The host token is one of:

- A legacy personal access token with the `api` scope.
- A fine-grained personal access token. At the user level it needs `create_personal_access_token`, `revoke_personal_access_token`, `read_user`, and `read_personal_access_token`. For each target, it needs `read_project` or `read_group` plus every permission the session token requests, on that project or group or on a parent group. GitLab refuses to create a session token with permissions the host token lacks.

For a self-hosted instance, also set the host explicitly through `providers.gitlab.host`, `GITLAB_HOST`, or `GL_HOST`. Config takes precedence over the environment. If none is set, corral uses `gitlab.com`. corral does not infer the instance from the Git remote.

## Grant read access to the current project

The minimal config is:

```yaml
providers:
  gitlab:
    enabled: true
```

corral detects the project from `origin` and grants it the `read` preset:

```text
read_project, read_group, download_code, read_code, read_repository, read_commit,
read_branch, read_repository_tag, read_protected_branch, read_protected_tag,
read_approval_rule, read_push_rule, read_merge_request, read_work_item, read_label,
use_global_search, read_pipeline, read_pipeline_schedule, read_job, read_job_artifact,
read_ci_config, read_runner, read_environment, read_deployment, read_release,
read_container_repository, read_package, read_wiki
```

They support clone and pull over HTTPS, and reading files, commits, branches, tags, merge requests, issues, pipelines, job logs and artifacts, environments, releases, packages, container images, and the wiki through the REST API. `read_code` adds the GraphQL `Repository` and `Commit` types. `read_pipeline_schedule` includes the values of pipeline schedule variables.

Detection works when the session workdir is the root of a regular checkout and its `origin` belongs to the configured GitLab host. Detection reads `<workdir>/.git/config`; it does not walk up from a subdirectory or follow the `.git` file used by a linked worktree. Name the project in a grant in those cases.

## Grant more access

`grants` lists the projects and groups the session token reaches, each with its own permissions. A grant names one `project` or one `group`, as a path or a numeric ID. A grant without a target applies to the project detected from `origin`.

A grant takes its permissions from a `preset`, a `permissions` list, or both:

- `preset: read` grants the read-only permissions listed above.
- `preset: write` adds the development loop to `read`: `push_code`, `create_branch`, `create_commit`, `create_merge_request`, `update_merge_request`, `create_work_item`, `update_work_item`, `create_pipeline`, `update_pipeline`, `run_job`, and `update_job`. The session can push, open and edit merge requests and issues, and start, retry, and cancel pipelines and jobs.
- `permissions` adds GitLab permission names to the preset. Without a preset, the grant holds only the listed names.
- A grant with neither gets the `read` preset.

This example lets the session work on the current project, read every project in the `org/libs` group, and read `org/tools` and open issues there:

```yaml
providers:
  gitlab:
    enabled: true
    grants:
      - preset: write
      - group: org/libs
      - project: org/tools
        preset: read
        permissions: [create_work_item]
```

A group grant also covers the group's subgroups and their projects. Grant the narrowest target the session needs.

Grants for the same project or group combine their permissions, also across config layers. For example, the global config grants read access to a shared group:

```yaml
providers:
  gitlab:
    grants:
      - group: org/libs
```

A project's `.corral.yml` then enables the provider and grants write access to its own project:

```yaml
providers:
  gitlab:
    enabled: true
    grants:
      - preset: write
```

Once any layer sets `grants`, corral no longer adds the default grant on the `origin` project. Add a grant without a target to keep access to it, as above.

corral also grants `read_user` and `read_personal_access_token` on your own account, so `glab` can look up the current user and the session can inspect its token. `read_personal_access_token` also lets the session list the names, permissions, expiry, and last-used IP addresses of your other personal access tokens, never their values. corral adds no other permission.

### Choose permissions

The presets cover most sessions. To add to a preset or build a list from scratch, pick permissions by task:

| Session task | Permissions |
| --- | --- |
| Clone, fetch, and pull over HTTPS | `download_code` |
| Read files, commits, and branches through the API | `read_repository`, `read_commit`, `read_branch` |
| Push commits | `push_code` |
| Create branches through the API | `create_branch` |
| Read merge requests | `read_merge_request` |
| Open and edit merge requests | `create_merge_request`, `update_merge_request` |
| Read issues and epics | `read_work_item` |
| Open and edit issues | `create_work_item`, `update_work_item` |
| Read pipelines and job logs | `read_pipeline`, `read_job` |
| Start pipelines and retry jobs | `create_pipeline`, `run_job` |
| Merge merge requests | `merge_merge_request` |

GitLab documents which REST endpoints each permission covers in [fine-grained token permissions for the REST API](https://docs.gitlab.com/auth/tokens/fine_grained_access_tokens_rest/). corral passes permission names to GitLab unchanged. GitLab answers a name it doesn't know with `500 Internal Server Error` and creates no token. GitLab adds permission names in new releases and renames or removes some, so a name from a newer release fails on an older instance. Every name in the presets exists in GitLab 19.2.

Some `glab` commands use the GraphQL API, which fine-grained tokens don't fully cover. If a `glab` command fails with `401` or `403` although the permission is granted, call the REST endpoint through `glab api` instead.

## Verify the session

Launch a new session, then run:

```sh
glab api user
glab api personal_access_tokens/self
git ls-remote "https://oauth2:${GITLAB_TOKEN}@gitlab.com/group/repository.git"
```

`glab api user` returns your user. `glab api personal_access_tokens/self` describes the session token: its corral name, permissions, and expiry, not the host token. `git ls-remote` lists the branches of a project with `download_code`. A request that needs a permission the token doesn't hold returns `403 Forbidden`.

`glab auth status` may report that no account is logged in because corral supplies the credential through `GITLAB_TOKEN` rather than the `glab` credential store. Use the commands above to verify the token.

The startup banner lists each target with its preset and any permissions beyond it, or with its permissions when it has no preset, for example `project org/app: preset write + merge_merge_request`. The session note lists every permission. Both show the token's expiry, never the token value.

## Fix common failures

- **Creating the token returns `400 Bad Request`:** the instance runs a GitLab version older than 19.2. Upgrade GitLab, or set `optional: true` only if the session can continue without GitLab access.
- **Creating the token returns `404 Not Found`:** fine-grained personal access tokens are turned off on the instance, or your user is not a member of a target. The error lists the targets.
- **Creating the token returns `403 Forbidden`:** the host token is a fine-grained token that lacks `create_personal_access_token` or a requested permission. Add the missing permissions to the host token, or use a legacy token with the `api` scope.
- **`project "..." not found` or `group "..." not found`:** the target does not exist, or the host token can't see it. Check the path or numeric ID.
- **`set project or group in providers.gitlab.grants`:** corral could not detect a matching GitLab `origin`. Name the project or group in the grant.
- **Creating the token returns `500 Internal Server Error`:** the instance doesn't know a permission name in `permissions`, for example because of a typo or because a newer GitLab release introduced it. Check each name against GitLab's permission list linked above for the instance's version.

For all fields and defaults, see [`providers.gitlab`](../reference/config.md#providersgitlab).

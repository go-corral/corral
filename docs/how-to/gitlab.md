# Set up GitLab credentials

The GitLab provider uses the host's `GITLAB_TOKEN` to create a scoped token through
the GitLab API outside the sandbox. It sets the new token as `GITLAB_TOKEN` in the
session, forwards relevant `glab` connection variables, and revokes the token when the
session ends. The host token is never forwarded.

Choose the token type before configuring the provider:

| | Personal token | Project token |
| --- | --- | --- |
| Config value | `personal` (default) | `project` |
| Token owner | Your GitLab user | A `project_<id>_bot` user |
| Host token needs | GitLab administrator rights | `api` scope and Maintainer or Owner in the project |
| Access | Your user access, limited by token scopes | One project, limited by scopes and `role` |
| Use when | Actions must be attributed to your user | Project-scoped automation is sufficient |

Both token types expire after one day, GitLab's minimum expiry granularity, and
corral revokes them on normal session exit.

## Set the host credential

Export a host token in the shell that starts corral:

```sh
export GITLAB_TOKEN=...
```

For a self-hosted instance, also set the host explicitly through
`providers.gitlab.host`, `GITLAB_HOST`, or `GL_HOST`. Config takes precedence over
the environment. If none is set, corral uses `gitlab.com`. corral does not infer the
instance from the Git remote.

## Create a personal token

Personal is the default token type, so the minimal config is:

```yaml
providers:
  gitlab:
    enabled: true
```

corral uses GitLab's administrator endpoint
`POST /users/:id/personal_access_tokens` to create a personal access token for the host
token's user. The host `GITLAB_TOKEN` must therefore carry administrator
rights. GitLab's non-admin self-service endpoint permits only the `k8s_proxy` and
`self_rotate` scopes; rotating the token instead would revoke the host credential corral
needs to preserve. The session token inherits the user's project access but is limited
by its scopes. `project` is ignored for personal tokens, while `role` is rejected.

The default scopes are read-only:

```text
read_repository, read_api
```

They support clone, pull, and reading API resources. If the session must create or
modify issues, merge requests, or other API resources, set only the required write
scope. GitLab's `api` scope provides API write access:

```yaml
providers:
  gitlab:
    enabled: true
    scopes: [api]
```

## Create a project token

A project token uses `POST /projects/:id/access_tokens`, avoids the administrator
requirement, and limits the identity to one project:

```yaml
providers:
  gitlab:
    enabled: true
    type: project
```

corral can detect the project from `origin` when the session workdir is the root of a
regular checkout and its remote belongs to the configured GitLab host. Detection reads
`<workdir>/.git/config`; it does not walk up from a subdirectory or follow the `.git`
file used by a linked worktree. Set the project explicitly in those cases:

```yaml
providers:
  gitlab:
    enabled: true
    type: project
    project: group/repository
```

The host token needs `api` scope and Maintainer or Owner access to the project.
The session token's project role defaults to `developer`. Set `role` only when the
session needs a different project role. Valid values are `guest`, `reporter`,
`developer`, `maintainer`, and `owner`.

A `role` is invalid for personal tokens because a personal token uses the user's
existing project roles.

GitLab may send expiry notifications whenever corral creates a project access
token. Frequent sessions can therefore produce notification noise.

## Verify the session

Launch a new session, then query the API:

```sh
glab api user
glab api personal_access_tokens/self  # personal tokens: inspect name, scopes, and expiry
```

The second command should describe the short-lived, corral-named session token rather
than the host credential. `glab auth status` may report that no account is logged in
because corral supplies the credential through `GITLAB_TOKEN` rather than the `glab`
credential store. Use the API commands above to verify the token.

The startup banner and session note report the session token's type, scopes, project
role where applicable, and expiry without printing the token value.

## Fix common failures

- **Creating a personal token returns `403`:** The host token is not an administrator
  token. Use a project token, supply an administrator token, or set `optional: true`
  only if the session can continue without GitLab access.
- **`set providers.gitlab.project`:** corral could not detect a matching GitLab
  `origin`. Set `project: group/repository` for the project token.
- **Creating a project token returns `403` or `404`:** Check that the host token has
  `api` scope, can access the project, and has a role allowed to create project access
  tokens.

For all fields and defaults, see
[`providers.gitlab`](../reference/config.md#providersgitlab).

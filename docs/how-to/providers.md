# Set up providers

Use a provider when the session needs host access that is not in the default
filesystem. Enable only what the task needs.

| Provider      | What it adds                                               |
| ------------- | ---------------------------------------------------------- |
| SSH           | [The host SSH agent and selected SSH configuration](#ssh)  |
| Docker        | [The host Docker daemon](#docker)                          |
| Home          | [A persistent private home](#home)                         |
| Kubernetes    | [A temporary Kubernetes credential](kubernetes.md)         |
| GitLab        | [A temporary GitLab token](gitlab.md)                      |
| Session hooks | [Host scripts before or after a session](session-hooks.md) |

The built-in `block`, `aiignore`, `paths`, `env`, and `notes` providers are documented in the [configuration reference](../reference/config.md#providers).

Before launching, check the effective settings and host prerequisites:

```sh
corral validate
corral doctor
```

`corral run --dry-run` shows providers that add fixed paths or environment settings.
It does not create temporary credentials or run session hooks. The preview therefore
marks Kubernetes, GitLab, and hooks as available only during a real launch.

## SSH

The SSH provider forwards `SSH_AUTH_SOCK` and mounts a read-only view of
`~/.ssh/config`, its included files, and `known_hosts`. Private keys remain masked;
the host agent performs signing. If a gpg-agent keeps its SSH socket under the masked
`~/.gnupg` directory, corral exposes only that socket at the path SSH clients expect;
the rest of the directory stays masked.

> [!warning]
> The forwarded agent can authenticate to any destination allowed by its loaded
> keys. Enable it only for sessions that need SSH authentication.

On the host, start an SSH agent and load the required key. Then enable the
provider:

```yaml
providers:
  ssh:
    enabled: true
```

Launch a new session and verify from inside the sandbox:

```sh
ssh-add -l
ssh -T git@example.com
```

Replace `example.com` with the host you need. If `ssh-add -l` cannot reach an
agent, confirm that `SSH_AUTH_SOCK` is set in the shell that runs `corral run`. To start
a new host agent and load a key, run `eval "$(ssh-agent)"` followed by `ssh-add` before
launching corral.

The provider can read SSH configuration through symlinks and `Include` directives,
but it refuses files that resolve into another always-blocked directory such as
`~/.gnupg` or `~/.aws`.

## Docker

The Docker provider mounts the host daemon socket read-write and `~/.docker`
read-only.

> [!warning]
> The host Docker socket gives root-equivalent control of the host. A container can
> mount host paths outside corral's filesystem sandbox. Enable it only when the task
> requires the host daemon.

Enable the provider:

```yaml
providers:
  docker:
    enabled: true
```

The host Docker daemon must be running at its default socket, and the user running
corral must be able to access it. Launch a new session and verify:

```sh
docker info
```

By default, a missing socket stops the launch. If the session can safely continue
without Docker, add `optional: true` under `docker` to skip it with a warning.

## Home

The home provider is enabled by default, so it needs no config. corral sets `$HOME`
to a persistent private directory, `~/.cache/corral/home-<hash>` by default, with one
directory per agent config directory. `corral validate` prints the resolved path. It
links only host paths that the filesystem baseline, selected agent, or another provider
already allows. This includes Git config such as `~/.gitconfig`, the active agent's
state, and explicit `providers.paths` entries.

Anything else written under `$HOME` stays in the private directory. npm, Go, pip, uv,
yarn, and pnpm caches therefore persist between sessions without changing the matching
paths in your host home.

To share another host path, grant only that path:

```yaml
providers:
  paths:
    ro: [~/.config/example]
```

Use `rw` instead of `ro` only when the sandbox must modify it. Always-blocked
paths are never linked into the private home.

To select a different persistent private home, set only `path`:

```yaml
providers:
  home:
    path: ~/.cache/corral/work-home
```

To opt out of home isolation:

```yaml
providers:
  home:
    enabled: false
```

With home isolation disabled, writes to granted paths under the host home affect
the host directly. Always-blocked directories remain masked.

For path defaults and config-directory keying, see
[`providers.home`](../reference/config.md#providershome).

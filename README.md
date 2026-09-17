# corral

[![release](https://img.shields.io/github/v/release/go-corral/corral)](https://github.com/go-corral/corral/releases)
[![CI](https://github.com/go-corral/corral/actions/workflows/ci.yml/badge.svg)](https://github.com/go-corral/corral/actions/workflows/ci.yml)
![platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)
![license](https://img.shields.io/badge/license-MIT-blue)

> Sandbox a coding agent ([Claude Code](https://docs.claude.com/en/docs/claude-code) by
> default) and enforce security policy on every tool call it makes.

corral [/kəˈræl/, kuh-RAL (US) or kuh-RAAL (UK)] combines two controls:

1. **The OS sandbox** starts from a filesystem allowlist (bubblewrap on Linux,
   Seatbelt on macOS). `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`,
   `~/.config/gcloud`, and `~/.azure` are always masked, regardless of config.
2. **The policy hook** checks every tool call and prompt. It blocks destructive
   commands and secret reads and writes, then records each decision in an audit log.

The filesystem restrictions still apply when an agent action does not pass through a
hook. For hooked actions, corral can also check the command, path, or content involved.

```text
you ─ corral run ─▶ ┌─────────── sandbox ────────────┐
                    │ deny-by-default filesystem;    │
                    │ ~/.ssh, ~/.aws, … masked       │
                    │                                │
                    │ Claude Code / pi               │
                    │    │ every tool call & prompt  │
                    │    ▼                           │
                    │ policy hook ── allow / block ──┼─▶ audit log
                    └────────────────────────────────┘
```

corral protects against accidental data loss and credential exposure. Preventing a
malicious operator from bypassing their own sandbox is outside the
[threat model](docs/explanation/threat-model.md).

## Why corral

A filesystem sandbox can hide a host resource or mount it, but some development tasks
need narrower access. corral's **providers** handle those cases:

- **Kubernetes** creates a per-session ServiceAccount token for configured or
  administrator-provisioned RBAC. The host identity used to request it stays outside the
  sandbox.
- **GitLab** creates a scoped, short-lived token from the host credential and revokes it
  on normal exit. The host token does not enter the sandbox.
- **SSH** forwards the agent socket and selected read-only SSH configuration. Private
  keys stay masked.
- **Home** supplies a persistent, sandbox-private `$HOME` for caches and other agent
  state. It is enabled by default.
- **Session hooks** run approved host executables before or after a session.
- **Docker** mounts the host daemon socket when you explicitly enable it. This gives the
  session root-equivalent control of the host.

At startup, corral tells you and the agent which providers are active. For temporary
credentials, this includes the scope and expiry.

## Install

1. Download the [release archive](https://github.com/go-corral/corral/releases) for
   your platform (Linux or macOS, `amd64` or `arm64`).
2. Verify its SHA-256 checksum.
3. Put `corral` on your `PATH`.

Then run:

```sh
corral doctor   # verify the install and environment
```

Full steps: the [install guide](docs/how-to/install.md). `corral update` upgrades in place.

### Install with the Claude Code helper

This repository is also a **Claude Code plugin marketplace**. Its `corral-helper` skill
can install and configure corral or diagnose a block. When the session can run the
required commands, the helper runs them for you:

```text
claude plugin marketplace add --scope user https://github.com/go-corral/corral.git
claude plugin install --scope user corral-helper@corral
```

Then ask: _"set up corral on this machine"_, _"let the sandboxed claude write to
~/work"_, _"why did the sandbox block this command?"_

## Quick start

```sh
corral sync                  # register the hook in Claude's settings.json
corral run -- <claude args>  # launch claude inside the sandbox
corral run --dry-run --      # print the exact sandbox command without launching
```

To make corral the default for Claude Code, add `alias claude='corral run --'`.
For pi, use `corral sync pi` and `corral run pi`; see the
[agent reference](docs/reference/agents.md).

## Commands

| Command     | Use it to                                                                      |
| ----------- | ------------------------------------------------------------------------------ |
| `run`       | Start the selected agent inside the sandbox.                                   |
| `sync`      | Update the selected agent's corral integration.                                |
| `doctor`    | Check the sandbox backend, agents, providers, config, and integration.         |
| `validate`  | Report config validity, sources, and selected settings, with path-grant trees. |
| `gc`        | Find and remove provider resources left by a crashed session.                  |
| `update`    | Upgrade the corral binary.                                                     |
| `uninstall` | Preview or remove state managed by corral.                                     |
| `version`   | Print the build version.                                                       |

See every flag and default in the [command reference](docs/reference/commands.md).

## Configuration

corral reads config files in this order:

1. `~/.config/corral/config.yml`: global settings
2. `.corral.yml`: project settings, normally committed
3. `.corral.local.yml`: per-user project settings; add it to `.gitignore`

You do not need a config file to use the defaults. Repository config requires
interactive content approval before the first real `run` or `sync`, and again after its
content changes. Add only the settings your task requires, for example:

```yaml
providers:
  paths:
    rw: [~/work/cache]
  ssh:
    enabled: true
```

Every key, its default, and the merge rules: the
[configuration reference](docs/reference/config.md).

## Uninstall

Run `corral uninstall` to preview the state corral manages. Add `--apply` to remove it
with confirmation at each step. See [Uninstall corral](docs/how-to/uninstall.md).

## Documentation

Full docs live in [`docs/`](docs) ([index](docs/README.md)):

- [Install guide](docs/how-to/install.md) covers download, verification, and initial
  setup. [Upgrading](docs/how-to/upgrade.md) uses one command.
- [Configuration reference](docs/reference/config.md) lists every key, type, default,
  and precedence rule.
- [Provider setup](docs/how-to/providers.md) covers SSH, Docker, and private-home setup.
  [Kubernetes](docs/how-to/kubernetes.md) and [GitLab](docs/how-to/gitlab.md) have
  dedicated guides.
- [Session hooks](docs/how-to/session-hooks.md) run host setup and cleanup around a
  session.
- [Agents](docs/reference/agents.md) explains how to select and operate Claude Code or
  pi.
- [Security and threat model](docs/explanation/threat-model.md) states corral's
  guarantees and limits.
- [Troubleshooting & FAQ](docs/how-to/troubleshooting.md) covers blocked commands,
  provider failures, and the audit log.
- [CONTRIBUTING.md](CONTRIBUTING.md) covers development setup, golden-file review, and
  cross-platform verification.

## License

[MIT](LICENSE) © Mathias Merscher, Nicolai Rybnikar

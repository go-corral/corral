# corral documentation

Start with the [project README](../README.md) for installation, the command set,
and a first sandboxed session. Use the pages below when you need to configure a
provider, look up an interface, diagnose a failure, or understand a security decision.

## How-to

| Doc                                                | Task                                                                              |
| -------------------------------------------------- | --------------------------------------------------------------------------------- |
| [Install corral](how-to/install.md)                | Download, verify, put on `PATH`, wire up the agent.                               |
| [Upgrade corral](how-to/upgrade.md)                | `corral update`, the manual fallback, the launch-time check.                      |
| [Uninstall corral](how-to/uninstall.md)            | Run `corral uninstall`, then remove the binary and config by hand.                |
| [Provider setup](how-to/providers.md)              | Choose a provider; set up SSH, Docker, or the private home.                       |
| [Kubernetes credentials](how-to/kubernetes.md)     | Configure managed or pre-provisioned RBAC and verify the session identity.        |
| [GitLab credentials](how-to/gitlab.md)             | Choose a token type, configure the host credential, and verify the session token. |
| [Set up session hooks](how-to/session-hooks.md)    | Configure host scripts, verify them, and recover from failures.                   |
| [Troubleshooting & FAQ](how-to/troubleshooting.md) | Blocked commands, provider failures, reading the audit log.                       |

## Reference

| Doc                                                   | Contents                                                        |
| ----------------------------------------------------- | --------------------------------------------------------------- |
| [Configuration](reference/config.md)                  | Every config key: type, default, valid values, merge rules.    |
| [Commands](reference/commands.md)                     | Every command and flag.                                         |
| [Agents](reference/agents.md)                         | Claude Code vs pi: selection, enforcement, state, and settings. |
| [Session-hooks contract](reference/hooks-contract.md) | Execution, environment, stdio, the contribution schema.         |
| [Audit-log format](reference/audit-log.md)            | The record fields and what is logged verbatim.                  |
| [Sandbox baseline](reference/sandbox-permissions.md)  | The compiled deny-by-default filesystem allowlist (generated).  |

## Explanation

| Doc                                                     | Question it answers                                          |
| ------------------------------------------------------- | ------------------------------------------------------------ |
| [Security & threat model](explanation/threat-model.md)  | What corral guarantees, and what is out of scope.            |
| [Repository config approval](explanation/trust-gate.md) | Why config and hook executables require content approval.    |
| [How corral works](explanation/design.md)               | The launcher, policy hook, providers, and agent integration. |

## For contributors

- [CONTRIBUTING.md](../CONTRIBUTING.md): dev setup, golden-file review, the
  cross-platform manual-verification convention.
- [contributors/architecture.md](contributors/architecture.md): the architecture
  reference: locked decisions, per-package design, the rewrite-trap checklist.

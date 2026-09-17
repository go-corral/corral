# Contributing to corral

**You must understand your code.** If you cannot explain what your change does and how it interacts with the sandbox, the hook, and the invariants, the PR will be closed.

Using an AI agent to write code is fine. Submitting generated code you have not read and cannot defend is not.

## Issues

Keep an issue short, concrete, and worth reading.

- If it does not fit on one screen, it is too long.
- Write in your own voice. If you must post generated text, label it as generated.
- State the bug or request clearly, with the corral version (`corral version`), the OS, and the agent.
- For a sandbox or hook bug, include the generated command (`corral run --dry-run`) and, for hook decisions, the relevant lines of the [audit log](docs/reference/audit-log.md).
- Explain why it matters.
- If you want to implement the change yourself, say so.

Unclear reports, duplicates, and issues that ignore this guide may be closed without discussion.

## Before you submit a PR

To run the prose lint (`make vale`) before each commit, install [pre-commit](https://pre-commit.com/) and enable the repository hooks:

```sh
pre-commit install
```

### Checks that must pass

```sh
make fmt vet lint vale
make test
```

### Commits and PRs

- PR titles are Conventional Commits: PRs are squash-merged, so the PR title becomes the commit on `main`, and release-please parses them for the changelog entries. Reference the issue number where there is one, for example `feat(sandbox): … (#17)`.
- One concern per PR. Split unrelated changes.
- Do not edit `CHANGELOG.md` or `.release-please-manifest.json`; the release PR maintains both. The plugin version in `plugins/corral-helper/.claude-plugin/plugin.json` is bumped the same way.
- Dependency bumps arrive via Dependabot; do not open manual bump PRs unless a bump is blocked.

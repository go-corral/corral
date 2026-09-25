# Agent rules

## Conversations

- Use simple, clear and concise language. Avoid jargon and fluff.
- No fluff or filler text, use technical, direct language
- No emojis in commits, issues, PR comments, or code
- Small examples or visualizations are always better than dense, abstract summaries

## Architecture

`docs/explanation/design.md` and `docs/explanation/threat-model.md` explain how Corral is designed. Read them before non-trivial work.

- Corrals hook enforcer runs on every tool call and must stay light. Heavy logic belongs in the launcher.
- Hooks must fail on any error, bad input, or unknown events.
- The threat model is accidents and footguns, not a malicious operator defeating their own sandbox. Protecting the user from their own mistake → warn-and-allow plus opt-out.
- `internal/*/testdata/*.golden` files contain reference profiles, a fix must not change the output without review.

## Code Quality

- A comment is only necessary when it explains something that's not derivable from the code or adds additional context. If a reader could write it from the code alone, omit it.
- Do not document what code does not do, just what it does.
- No history, no cross-file promises.
- After changing code, run `make fmt vet lint vale` and `make test`

## Documentation

- Documents contain only actionable content. Superseded content is removed.
- Run `make vale` to check docs after modifications.

## Sync the corral-helper plugin

`plugins/corral-helper/` is a Claude Code plugin whose skill references are mostly symlinks into `docs/`. When making changes to the plugin or documentation:

- A new doc under `docs/` needs a symlink under `plugins/corral-helper/skills/corral/references/` and a pointer in `SKILL.md`.
- A changed command, flag, default, or provider behavior needs updates to `SKILL.md` and `references/agent.md`, plus the plugin/marketplace metadata when names change.
- A change to `SKILL.md`, a reference, or the layout needs `plugins/corral-helper/README.md` updated.

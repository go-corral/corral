# Changelog

## [0.24.0](https://github.com/go-corral/corral/compare/v0.23.0...v0.24.0) (2026-10-05)

This release comes with a few larger changes:

- The **GitLab provider** now only supports fine-grained personal access tokens with configurable scopes. This combines all the possibilities of the legacy tokens without the restrictions.
- The **Kubernetes provider** can now be configured to connect to multiple clusters at once, so that the agent session can interact with all configured clusters simply by changing the kubeconfig context.
- Corral will now stay running alongside the sandbox, exposing an RPC socket. This socket is used to delegate all hook evaluations, making it harder to manipulate the Corral config from inside the session. This also allows to move the audit log into a dedicated directory outside of the sandbox, completely removing it from the agents readable and writable filesystem. This change will be part of the next release.

### ⚠ BREAKING CHANGES

- **gitlab:** the gitlab provider mints only fine-grained personal access tokens and needs GitLab 19.2 or later. providers.gitlab.type, scopes, role, and project are removed; configure access through providers.gitlab.grants. A config with only `enabled: true` now gets read-only access to the project in the workdir's origin remote.

### Features

- **gc:** check every declared kubernetes cluster ([#47](https://github.com/go-corral/corral/issues/47)) ([0bde9ea](https://github.com/go-corral/corral/commit/0bde9ea08244b2cb3a6fdeab8c3d00b2dd609377))
- **gitlab:** mint fine-grained personal access tokens ([#33](https://github.com/go-corral/corral/issues/33)) ([ef5c50b](https://github.com/go-corral/corral/commit/ef5c50b34b98dd6c8dfcce1d86a56b61df89083e))
- **hooks:** log events and evaluate hook events in a sidecar ([#40](https://github.com/go-corral/corral/issues/40)) ([bf467b0](https://github.com/go-corral/corral/commit/bf467b0686c894b73b9eff2c23928430ba2bb45f))
- **kubernetes:** declare clusters in a map with inherited defaults ([#44](https://github.com/go-corral/corral/issues/44)) ([f65a4c4](https://github.com/go-corral/corral/commit/f65a4c496ca016cb6f0edb158debdd44a9901f86))
- **kubernetes:** support multiple clusters in sessions ([#46](https://github.com/go-corral/corral/issues/46)) ([46d15eb](https://github.com/go-corral/corral/commit/46d15eb0f8d1631e200617419d94da205dce068a))
- **policy:** detect Cloudflare tokens ([#48](https://github.com/go-corral/corral/issues/48)) ([22931ce](https://github.com/go-corral/corral/commit/22931ce98acda1c53a241acf071155ff2400d449)), closes [#42](https://github.com/go-corral/corral/issues/42)
- **trust:** require approval for kubeconfigs in sandbox-writable locations ([#45](https://github.com/go-corral/corral/issues/45)) ([c55e6ac](https://github.com/go-corral/corral/commit/c55e6ac79946d4cb41efe9151ab6c4f7c1ca9a3a))

### Bug Fixes

- **hooks:** apply profiles when executing hooks ([#35](https://github.com/go-corral/corral/issues/35)) ([8467504](https://github.com/go-corral/corral/commit/8467504d367302c796d75cf52a032b1904fe6d24))

## [0.23.0](https://github.com/go-corral/corral/compare/v0.22.0...v0.23.0) (2026-09-25)

### Features

- **notes:** add notes provider for static agent notes ([#32](https://github.com/go-corral/corral/issues/32)) ([194cfed](https://github.com/go-corral/corral/commit/194cfed8754422b3ee3855de57f94f9b6797d8cb))
- **policy:** detect AI provider API keys ([#25](https://github.com/go-corral/corral/issues/25)) ([0491031](https://github.com/go-corral/corral/commit/049103116fa602843fbf2913ae28a6a55a4d6371))
- **policy:** detect Atlassian API tokens ([#24](https://github.com/go-corral/corral/issues/24)) ([3e69ae7](https://github.com/go-corral/corral/commit/3e69ae7708337e96027f3a1e7a8ab53046ab30b8))
- **policy:** detect GitLab tokens ([#28](https://github.com/go-corral/corral/issues/28)) ([faaea30](https://github.com/go-corral/corral/commit/faaea30f66b2830f0686e2dd91c9c89ab483d15c))
- **policy:** detect infrastructure service tokens ([#26](https://github.com/go-corral/corral/issues/26)) ([3a2d74c](https://github.com/go-corral/corral/commit/3a2d74cd5df0bab4a1746ca0bc932fedc1258dd0))
- **policy:** detect more AWS key prefixes and Bedrock API keys ([#30](https://github.com/go-corral/corral/issues/30)) ([3f933ac](https://github.com/go-corral/corral/commit/3f933ac4204924d4713de3d83a4a6ba07be75496))
- **policy:** detect package registry tokens ([#27](https://github.com/go-corral/corral/issues/27)) ([e897ee9](https://github.com/go-corral/corral/commit/e897ee925d99852d80f7c54300085cd8b5c4975f))
- **policy:** detect SaaS API tokens ([#29](https://github.com/go-corral/corral/issues/29)) ([4657e6e](https://github.com/go-corral/corral/commit/4657e6e771c3026d039491976009232893aa7c17))

## [0.22.0](https://github.com/go-corral/corral/compare/v0.21.0...v0.22.0) (2026-09-24)

### ⚠ BREAKING CHANGES

- **agents:** disable Claude Code agent view by default ([#22](https://github.com/go-corral/corral/issues/22))

### Features

- **agents:** disable Claude Code agent view by default ([#22](https://github.com/go-corral/corral/issues/22)) ([3544f71](https://github.com/go-corral/corral/commit/3544f71a6a9c2452e5163fd4ccd8fd204211ceaf))
- **cli:** redesign the doctor report ([#19](https://github.com/go-corral/corral/issues/19)) ([8eddfe0](https://github.com/go-corral/corral/commit/8eddfe0c464ac138d739fb60d4b9469f874347cd))
- **cli:** redesign the remaining cli subcommands (sync, gc, update and uninstall) ([#21](https://github.com/go-corral/corral/issues/21)) ([9e97d82](https://github.com/go-corral/corral/commit/9e97d82890b7a22452fcbc22216c12f07cb2c82a))
- **cli:** redesign the run banner ([#18](https://github.com/go-corral/corral/issues/18)) ([cabbb56](https://github.com/go-corral/corral/commit/cabbb569124764d68ca6b2e5f69be2d38fed4937))
- **cli:** redesign the validate report ([#20](https://github.com/go-corral/corral/issues/20)) ([b8b1061](https://github.com/go-corral/corral/commit/b8b10614e3f9dfcff337b51a3fc1c44f489921b5))

### Bug Fixes

- **audit:** persist the log file path in the sandbox env ([#16](https://github.com/go-corral/corral/issues/16)) ([8495ff8](https://github.com/go-corral/corral/commit/8495ff8428554e92a6ac68a26d1e0fc918bc45f8))
- **providers:** warn when a providers.block entry does not exist ([#13](https://github.com/go-corral/corral/issues/13)) ([5f20f05](https://github.com/go-corral/corral/commit/5f20f05f15abda2c04101116ce36b7e9b1d1578a))

## 0.21.0 (2026-09-17)

### Features

- initial public release ([192a06a](https://github.com/go-corral/corral/commit/192a06af798c94dff1dd078f03292c0bd7f3da44))

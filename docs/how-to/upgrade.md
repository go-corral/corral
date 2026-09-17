# Upgrade corral

```sh
corral update          # download, verify, and install the latest release
corral update --check  # report whether a newer version exists
```

`corral update` verifies the downloaded archive against the release's SHA-256
checksums and replaces the binary in place after a prompt; a mismatch aborts
without touching the installed binary. `--yes` skips the prompt and is required
non-interactively. `--timeout <duration>` changes the overall deadline for the
release check and download (default: `1m30s`).

If the binary's directory is not writable, as with a root-owned
`/usr/local/bin`, install the new binary manually with the required privileges. Follow
the download and verification steps in the [install guide](install.md#install).

If the repository is private, set `GITHUB_TOKEN` (or `GH_TOKEN`) in the environment
before running `corral update` (or before a launch whose update check should reach the
server); a public repository needs no token.

corral also checks for a newer release once a day at launch. When an update is
available, the launch banner prints an advisory notice but does not prompt unless another
warning requires confirmation. Disable this check with
[`update.checkOnStart: false`](../reference/config.md#update).

Re-run `corral sync` after an upgrade if the release notes say the hook
registration changed.

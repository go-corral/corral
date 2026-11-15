# Install corral

corral is a single static binary for Linux and macOS (`amd64`, `arm64`). Each
[release](https://github.com/go-corral/corral/releases) includes a SHA-256 checksums file.

## Install

1. From the [Releases page](https://github.com/go-corral/corral/releases), download the archive for your
   platform and the checksums file `corral_<version>_SHA256SUMS`.
2. Verify the checksum:

   ```sh
   sha256sum --ignore-missing -c corral_<version>_SHA256SUMS      # Linux
   shasum -a 256 --ignore-missing -c corral_<version>_SHA256SUMS  # macOS
   ```

3. Unpack and put the binary on your `PATH`:

   ```sh
   tar -xzf corral_<version>_linux_amd64.tar.gz corral
   install -m 0755 corral ~/.local/bin/corral
   ```

The macOS binaries are unsigned. If Gatekeeper blocks the first run, remove the
quarantine attribute with `xattr -d com.apple.quarantine ~/.local/bin/corral`. Do this
only after you have verified the downloaded binary.

## Set up

If no agent is specified, the default Claude Code will be used.

1. Run `corral doctor claude`. Check that it finds the sandbox backend and `claude` binary.
2. Run `corral sync claude` to register the policy hooks in `~/.claude/settings.json`.
3. Run `corral doctor`. Check that nothing needs attention.
4. Start a session with `corral run claude -- <claude args>`.

To see what the sandbox will enforce before launching, run `corral validate`.

To upgrade later: [upgrade corral](upgrade.md).

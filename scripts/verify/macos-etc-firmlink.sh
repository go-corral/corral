#!/usr/bin/env bash
# macos-etc-firmlink.sh — verify the macOS /etc→/private/etc firmlink fix in the M3
# hook policy engine (internal/policy).
#
# Run this on a REAL Mac, OUTSIDE any sandbox. The dev sandbox blocks `lstat` on
# /private/etc and /home, which makes internal/policy's Canonicalize() (and hence
# every path-rule test) fail with "operation not permitted" — an ENVIRONMENT
# limitation, not a code failure. Outside the sandbox those lstats succeed and the
# suite exercises the real firmlink resolution this fix targets.
#
# What it checks:
#   - `go vet ./internal/policy/` is clean.
#   - The full internal/policy test suite passes, INCLUDING:
#       TestPathPatternRuleMacFirmlinkEtc  (new) — /etc/shadow & /etc/cron.d/...
#         are denied even though Canonicalize resolves them to /private/etc/...
#       TestPathPatternRuleReadDenies/etc-shadow, TestPathPatternRuleWriteGuards/*
#         — the pre-existing cases that USED to fail on macOS (the documented gap).
#
# Nothing here mutates your system: it only builds into repo-local caches
# (.gopath/.gocache) and runs tests. Use --dry-run to print every step instead of
# running it.
#
# Usage:
#   scripts/verify/macos-etc-firmlink.sh [--dry-run]

set -euo pipefail

DRY_RUN=false
for arg in "$@"; do
	case "$arg" in
	--dry-run) DRY_RUN=true ;;
	*)
		echo "unknown argument: $arg" >&2
		echo "usage: scripts/verify/macos-etc-firmlink.sh [--dry-run]" >&2
		exit 2
		;;
	esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

run() {
	if $DRY_RUN; then
		echo "DRY-RUN: $*"
	else
		echo "+ $*"
		"$@"
	fi
}

cd "$REPO_ROOT"

# Repo-local caches so the build never touches ~/Library/Caches (matches the
# documented sandbox build env; harmless outside it too).
export GOPATH="$REPO_ROOT/.gopath" GOCACHE="$REPO_ROOT/.gocache" GOTOOLCHAIN=local CGO_ENABLED=0

echo "== M3 /etc firmlink fix verification =="
echo "repo: $REPO_ROOT"
echo "GOOS check: this must run on darwin (uname: $(uname -s))"
echo

run go vet ./internal/policy/
run go test ./internal/policy/ -v -run 'TestPathPatternRuleMacFirmlinkEtc|TestPathPatternRuleReadDenies|TestPathPatternRuleWriteGuards|TestLogicalSysPath|TestClassifySensitiveUnit'

echo
echo "== full internal/policy suite (catch any regression) =="
run go test ./internal/policy/

echo
if $DRY_RUN; then
	echo "DRY-RUN complete — no commands were executed."
else
	echo "PASS: /etc and /private/etc targets are denied; no regressions."
fi

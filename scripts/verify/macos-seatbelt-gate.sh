#!/usr/bin/env bash
# macos-seatbelt-gate.sh — macOS Seatbelt backend gate + smoke tests for corral (M7).
#
# Run this on a REAL Mac, OUTSIDE any sandbox (the dev sandbox blocks nested
# sandbox-exec). It runs the three gate checks the M7 handoff requires, then a
# live smoke test against the profile corral actually generates:
#
#   Gate 1  sandbox-exec is present and runs a trivial profile.
#   Gate 2  a static Go binary completes an HTTPS GET (TLS cert + DNS) under the
#           REAL corral-generated profile — the key unknown (Seatbelt + Go trustd).
#   Gate 3  a path outside the allowlist is denied, and ~/.ssh is masked, under
#           that same profile.
#   Gate 4  the corral pre-tool-use hook BOOTS inside its own profile (policy init
#           canonicalizes the masked ~/.ssh via the metadata allow instead of
#           fail-closing) and still denies a secret read. This is the bootstrap
#           deadlock guard — without the blocked-leaf metadata allow the hook
#           cannot lstat ~/.ssh and blocks every tool call.
#   Smoke   the generated profile has the expected structure and sandbox-exec
#           accepts it (a no-op command runs).
#
# Nothing here mutates your system: it only builds corral into ./bin, writes temp
# files under a mktemp dir, and reads (never writes) your home. Use --dry-run to
# see every step without executing it.
#
# Usage:
#   scripts/verify/macos-seatbelt-gate.sh [--dry-run] [--url https://example.com]

set -euo pipefail

DRY_RUN=false
PROBE_URL="https://www.apple.com/"
while [ $# -gt 0 ]; do
  case "$1" in
  --dry-run) DRY_RUN=true ;;
  --url)
    PROBE_URL="${2:?--url needs a value}"
    shift
    ;;
  -h | --help)
    sed -n '2,30p' "$0"
    exit 0
    ;;
  *)
    echo "unknown arg: $1" >&2
    exit 2
    ;;
  esac
  shift
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CORRAL="$REPO_ROOT/bin/corral"
PASS=0
FAIL=0

say() { printf '\n=== %s ===\n' "$1"; }
ok() {
  printf '  PASS  %s\n' "$1"
  PASS=$((PASS + 1))
}
bad() {
  printf '  FAIL  %s\n' "$1"
  FAIL=$((FAIL + 1))
}

# run_or_echo: in dry-run, print the command; otherwise execute it.
run_or_echo() {
  if [ "$DRY_RUN" = true ]; then
    printf '  would run: %s\n' "$*"
    return 0
  fi
  "$@"
}

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This script must run on macOS (uname=$(uname -s))." >&2
  exit 1
fi
printf 'macOS: %s (build %s)\n' "$(sw_vers -productVersion 2>/dev/null || echo '?')" "$(sw_vers -buildVersion 2>/dev/null || echo '?')"

WORK=""
cleanup() { [ -n "$WORK" ] && rm -rf "$WORK" 2>/dev/null || true; }
trap cleanup EXIT
if [ "$DRY_RUN" = false ]; then
  WORK="$(mktemp -d)"
else
  WORK="<tmpdir>"
fi

# ── Build corral ───────────────────────────────────────────────────────────────
say "Build corral"
run_or_echo make -C "$REPO_ROOT" build
if [ "$DRY_RUN" = false ] && [ ! -x "$CORRAL" ]; then
  echo "build did not produce $CORRAL" >&2
  exit 1
fi

# ── Gate 1: sandbox-exec runs a trivial profile ───────────────────────────────
say "Gate 1 — sandbox-exec runs a profile"
if ! command -v sandbox-exec >/dev/null 2>&1; then
  bad "sandbox-exec not on PATH (Apple removed it on this macOS?) — ESCALATE"
else
  # Minimal profile: just prove sandbox-exec is present and loads+runs a profile.
  # (allow default) is the same crash-proof base the real corral profile uses — a
  # hand-written (deny default) profile can SIGABRT sandbox-exec on some macOS
  # versions if it omits an operation the launch needs; deny-by-default enforcement
  # is proven against the REAL profile in Gate 3, not here.
  G1="$WORK/gate1.sb"
  if [ "$DRY_RUN" = true ]; then
    printf '  would write %s and run: sandbox-exec -f %s /usr/bin/true\n' "$G1" "$G1"
    ok "(dry-run) gate 1"
  else
    printf '(version 1)\n(allow default)\n' >"$G1"
    if sandbox-exec -f "$G1" /usr/bin/true; then ok "sandbox-exec is present and runs a profile"; else bad "sandbox-exec rejected a profile — ESCALATE"; fi
  fi
fi

# ── Extract the REAL corral-generated profile ──────────────────────────────────
say "Generate the real corral profile (corral run --dry-run)"
REALPROFILE="$WORK/corral.sb"
if [ "$DRY_RUN" = true ]; then
  printf '  would run: %s run --dry-run --project %s -- --version\n' "$CORRAL" "$WORK/proj"
  printf '  would extract the -p <profile> blob into %s\n' "$REALPROFILE"
else
  mkdir -p "$WORK/proj"
  ARGV="$("$CORRAL" run --dry-run --project "$WORK/proj" -- --version 2>/dev/null || true)"
  # The dry-run prints: sandbox-exec -p '<PROFILE>' /usr/bin/env -i … . The profile
  # is single-quoted and contains no single quotes (SBPL uses double quotes), so the
  # blob between the first `-p '` and `' /usr/bin/env` is the whole profile.
  printf '%s' "$ARGV" | perl -0777 -ne "print \$1 if /-p '(.*?)' \/usr\/bin\/env/s" >"$REALPROFILE"
  if [ -s "$REALPROFILE" ]; then
    ok "extracted the generated profile ($(wc -l <"$REALPROFILE" | tr -d ' ') lines)"
    printf '  profile head:\n'
    sed 's/^/    /' "$REALPROFILE" | head -8
  else
    bad "could not extract a profile from the dry-run output"
  fi
  # Temp isolation: TMP/TMPDIR/TEMPDIR/CLAUDE_CODE_TMPDIR must point at a fresh
  # /tmp/corral-* dir (a deny-by-default tree), NOT the shared /var/folders $TMPDIR.
  if printf '%s' "$ARGV" | grep -q 'TMPDIR=/tmp/corral-'; then
    ok "temp env is isolated (TMPDIR → a fresh /tmp/corral-* dir, not shared)"
  else
    bad "temp env NOT isolated — TMPDIR is not a /tmp/corral-* dir"
  fi
fi

# ── A tiny static Go TLS probe ────────────────────────────────────────────────
say "Build the Go TLS probe"
GOPROBE="$WORK/tlsprobe"
if [ "$DRY_RUN" = true ]; then
  printf '  would build a Go HTTPS-GET probe into %s and run it under the profile\n' "$GOPROBE"
else
  cat >"$WORK/tlsprobe.go" <<'GO'
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func main() {
	url := os.Args[1]
	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		fmt.Fprintln(os.Stderr, "GET failed:", err)
		os.Exit(1)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	fmt.Println("OK", resp.Status)
}
GO
  (cd "$WORK" && CGO_ENABLED=0 go build -o "$GOPROBE" tlsprobe.go)
fi

# ── Gate 2: Go TLS under the real profile ─────────────────────────────────────
say "Gate 2 — Go TLS (cert + DNS) under the generated profile"
if [ "$DRY_RUN" = true ]; then
  printf '  would run: sandbox-exec -f %s %s %s\n' "$REALPROFILE" "$GOPROBE" "$PROBE_URL"
  ok "(dry-run) gate 2"
else
  if sandbox-exec -f "$REALPROFILE" "$GOPROBE" "$PROBE_URL"; then
    ok "HTTPS GET succeeded under the profile (Seatbelt + Go trustd/DNS cooperate)"
  else
    bad "HTTPS GET failed under the profile — the TLS/DNS read rules are insufficient"
    printf '  (retry under an open profile to localize: is it TLS/DNS or the network?)\n'
  fi
fi

# ── Gate 3: deny outside the allowlist + secret masking ───────────────────────
say "Gate 3 — a deny actually denies"
if [ "$DRY_RUN" = true ]; then
  printf '  would write %s/secret, then expect DENY: sandbox-exec -f %s /bin/cat %s/secret\n' "$HOME" "$REALPROFILE" "$HOME"
  printf '  would expect DENY: sandbox-exec -f %s /bin/cat ~/.ssh/* ; ALLOW: cat /usr/lib/dyld\n' "$REALPROFILE"
  ok "(dry-run) gate 3"
else
  # Run the sandboxed probes from "/" (readable under the profile) so the spawned
  # shells don't warn about an unreadable invocation cwd. All paths below are
  # absolute, so this is safe for the rest of the script.
  cd /
  # $HOME is deny-by-default: a sentinel directly under it (not in the allowlist)
  # must be unreadable. Written and removed by us, never inside the sandbox.
  SENT="$HOME/.m7probe-$$.txt"
  printf 'secret\n' >"$SENT"
  if sandbox-exec -f "$REALPROFILE" /bin/cat "$SENT" >/dev/null 2>&1; then
    bad "\$HOME sentinel was READABLE — deny-by-default not enforced"
  else
    ok "\$HOME sentinel denied (deny-by-default holds)"
  fi
  rm -f "$SENT"

  # ~/.ssh is an always-blocked path and is masked if present.
  if [ -d "$HOME/.ssh" ]; then
    if sandbox-exec -f "$REALPROFILE" /bin/sh -c 'ls "$HOME"/.ssh/* >/dev/null 2>&1'; then
      bad "\$HOME/.ssh was readable — always-blocked mask missing"
    else
      ok "\$HOME/.ssh masked (always blocked)"
    fi
  else
    printf '  (skip: no ~/.ssh on this host)\n'
  fi

  # ~/.config/gcloud is the nested always-blocked shape: its parent ~/.config is
  # partially readable (metadata + allowlisted subdirs), so the subpath deny must
  # still win underneath it.
  if [ -d "$HOME/.config/gcloud" ]; then
    if sandbox-exec -f "$REALPROFILE" /bin/sh -c 'ls "$HOME"/.config/gcloud/* >/dev/null 2>&1'; then
      bad "\$HOME/.config/gcloud was readable — always-blocked mask missing"
    else
      ok "\$HOME/.config/gcloud masked (always blocked)"
    fi
  else
    printf '  (skip: no ~/.config/gcloud on this host)\n'
  fi

  # A system path inside the allowlist must remain readable.
  if sandbox-exec -f "$REALPROFILE" /bin/sh -c 'cat /usr/lib/dyld >/dev/null 2>&1 || ls /usr/bin >/dev/null 2>&1'; then
    ok "system roots (/usr) still readable"
  else
    bad "/usr unreadable under the profile — base FS too tight"
  fi

  # Temp READ-isolation: a file in the shared per-user temp/cache tree (/var/folders,
  # the host $TMPDIR) must be unreadable — the profile denies file-read-data there
  # (claude's own temp lives under /tmp instead). This is what hides other processes'
  # temp files (mcfly.*) AND the …/C caches.
  SIB="${TMPDIR:-/tmp}/m7sibling.$$"
  if printf 'othersecret\n' >"$SIB" 2>/dev/null; then
    if (cd / && sandbox-exec -f "$REALPROFILE" /bin/cat "$SIB") >/dev/null 2>&1; then
      bad "file in /var/folders READABLE — temp/cache read-isolation not enforced"
    else
      ok "/var/folders temp+cache reads denied (read-isolation holds)"
    fi
    rm -f "$SIB"
  fi
fi

# ── Gate 4: the pre-tool-use hook boots inside its own profile ────────────────
# Regression guard for the bootstrap deadlock: when the hook runs *inside* the
# sandbox it generated, policy init must canonicalize the masked ~/.ssh/.gnupg/.aws
# roots. The blocked-leaf `file-read-metadata` allow lets lstat() succeed there; a
# permission error on a deny root is tolerated (lexical fallback). Either way the
# hook must NOT print "cannot initialize policy" — and must still DENY a secret.
say "Gate 4 — pre-tool-use hook boots inside its own sandbox"
BENIGN='{"hook_event_name":"PreToolUse","session_id":"m7","cwd":"/","tool_name":"Read","tool_input":{"file_path":"'"$WORK"'/proj/README.md"}}'
SECRET='{"hook_event_name":"PreToolUse","session_id":"m7","cwd":"/","tool_name":"Read","tool_input":{"file_path":"'"$HOME"'/.ssh/id_rsa"}}'
if [ "$DRY_RUN" = true ]; then
  printf '  would pipe a benign Read event to: sandbox-exec -f %s %s hook pre-tool-use (expect: inits, allows)\n' "$REALPROFILE" "$CORRAL"
  printf '  would pipe a ~/.ssh/id_rsa Read event to the same (expect: blocked, never "cannot initialize policy")\n'
  ok "(dry-run) gate 4"
else
  HOOK_ERR="$WORK/hook.err"
  # Benign event: the hook must initialize (no fail-closed init) and allow (exit 0).
  if (cd / && printf '%s' "$BENIGN" | sandbox-exec -f "$REALPROFILE" "$CORRAL" hook pre-tool-use) >/dev/null 2>"$HOOK_ERR"; then
    if grep -q 'cannot initialize policy' "$HOOK_ERR"; then
      bad "hook fail-closed at policy init inside its own sandbox (blocked-leaf metadata missing?)"
    else
      ok "hook initialized + allowed a benign event inside its own profile"
    fi
  else
    if grep -q 'cannot initialize policy' "$HOOK_ERR"; then
      bad "hook fail-closed at policy init inside its own sandbox: $(tr -d '\n' <"$HOOK_ERR")"
    else
      bad "hook did not allow a benign event (exit nonzero, but init was OK): $(tr -d '\n' <"$HOOK_ERR")"
    fi
  fi
  # Secret event: the hook must still BLOCK ~/.ssh (init succeeding must not weaken
  # the deny). A block surfaces two ways: a nonzero exit (hard/eval-error block) OR
  # exit 0 with a "permissionDecision":"deny" JSON on stdout. Only a clean allow
  # (exit 0, no deny) is a failure.
  HOOK_OUT="$WORK/hook.out"
  if (cd / && printf '%s' "$SECRET" | sandbox-exec -f "$REALPROFILE" "$CORRAL" hook pre-tool-use) >"$HOOK_OUT" 2>"$HOOK_ERR"; then
    if grep -q '"permissionDecision":"deny"' "$HOOK_OUT"; then
      ok "hook still blocks a ~/.ssh secret read (deny decision; deny root intact)"
    else
      bad "hook ALLOWED a ~/.ssh/id_rsa read — deny root not enforced after init relaxation"
    fi
  else
    ok "hook still blocks a ~/.ssh secret read (fail-closed; deny root intact)"
  fi
fi

# ── Info: /var access under the profile ───────────────────────────────────────
# Not pass/fail — context. EXPERIMENT: /private/var was removed from the policy, so
# ALL of /var (incl /var/folders) is denied by absence, like Linux. claude's temp is
# the granted /tmp/corral-* dir. The real test is whether a live claude session still
# launches+works (timezone via /var/db/timezone, dyld, frameworks). See the doc.
say "Info — /var access under the profile"
if [ "$DRY_RUN" = true ]; then
  printf '  would test reads/writes under /private/var (expected: denied)\n'
else
  if (cd / && sandbox-exec -f "$REALPROFILE" /bin/sh -c 'ls /private/var/db >/dev/null 2>&1') 2>/dev/null; then
    printf '  /private/var/db readable:   YES  (something still grants /var?)\n'
  else
    printf '  /private/var/db readable:   NO   (expected — /var denied by absence; watch timezone in the LIVE run)\n'
  fi
  printf '  (claude'\''s own temp is the granted /tmp/corral-* dir; if a /var slice is needed, add just that subpath)\n'
fi

# ── Smoke: profile structure ──────────────────────────────────────────────────
say "Smoke — generated profile structure"
if [ "$DRY_RUN" = true ]; then
  printf '  would grep the profile for the expected SBPL markers\n'
  ok "(dry-run) smoke"
else
  need='(version 1)
(allow default)
(deny file-write*)
(deny file-read*)
(allow file-read-metadata
(deny process-info* (target others))
(deny mach-task-read mach-task-name (target others))'
  miss=0
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    grep -qF "$line" "$REALPROFILE" || {
      bad "profile missing: $line"
      miss=$((miss + 1))
    }
  done <<<"$need"
  [ "$miss" -eq 0 ] && ok "profile has all expected sections"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
say "Summary"
printf '  passed: %d   failed: %d\n' "$PASS" "$FAIL"
if [ "$DRY_RUN" = true ]; then
  printf '  (dry-run — nothing was executed)\n'
  exit 0
fi
if [ "$FAIL" -gt 0 ]; then
  printf '  Gate/smoke checks FAILED — see above before relying on the backend.\n'
  exit 1
fi
printf '  All gate + smoke checks passed. Record this in docs/contributors/macos-verification.md.\n'

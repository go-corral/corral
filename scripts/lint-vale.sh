#!/bin/sh
set -eu

: "${VALE:=vale}"

# Whole-file exclusions live here, not in .vale.ini: Vale unions BasedOnStyles
# across every matching section, so a per-file `BasedOnStyles =` cannot subtract
# the [*.md] styles. The walk glob is the only reliable way to skip a file.
#
# Skipped: local state and dependencies, generated or historical prose (CHANGELOG,
# the sandbox-permissions reference), and the plugin
# reference symlinks, which are linted at their canonical docs/ targets. agent.md
# is the only real file under references/, so the walk skips that directory and the
# second pass lints it on its own (a walk applies the glob to explicit paths too).
EXCLUDE='!{.git/**,.gopath/**,.gocache/**,.vale/**,.claude/**,.skill-eval-workspace/**,scratchpad/**,bin/**,dist/**,vendor/**,node_modules/**,**/CHANGELOG.md,docs/reference/sandbox-permissions.md,plugins/corral-helper/skills/corral/references/*/*}'
"$VALE" --glob="$EXCLUDE" --output=line .

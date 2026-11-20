package enforce

import (
	"strings"

	"github.com/go-corral/corral/internal/config"
)

// SystemNote is the terse, model-facing description of the corral environment injected
// at session start. goos selects how a sandbox deny reads. backendNotes and providerNotes are
// launcher-authored, appended as bullets.
func SystemNote(goos, version, backendNotes, providerNotes string) string {
	silentDeny := "a masked directory is empty, a masked file reads as `File content masked by corral`, a file under a masked directory or an unmounted path reads as `No such file or directory`, and a write to a read-only path fails with `Read-only file system`. A write outside the working directory and the granted paths can also work, but it goes to sandbox-private storage that the user does not see"
	if goos == "darwin" {
		silentDeny = "a masked path or a path without a grant fails with `Operation not permitted`"
	}
	lines := []string{
		"You are running inside corral " + version + ", a security sandbox. For this session:",
		"- Writable: the working directory. Most other paths are read-only or absent.",
		"- Always-blocked: `" + strings.Join(config.AlwaysBlockedPaths, "`, `") + "`. No setting can open them. If one of them is a symlink, its target is blocked too.",
		"- Two layers can block you. The sandbox (`os`) gives no policy message: " + silentDeny + ". A path that is missing here can exist on the host.",
		"- The policy hook (`hook`) checks your own tool calls. It blocks credential access, secrets, destructive commands, and edits to corral's own files. Its deny starts with `blocked by corral policy [hook:<rule>]` and names a fix. When a call ran but corral hid its output, the message starts with `output withheld by corral policy [hook:<rule>]`. It reads the text of a Bash command, but not what the started processes do. A shell probe that works does not show that a tool call is allowed.",
		"- When something is blocked, propose a fix to the user. For a hook deny, propose the named fix. For a sandbox deny, propose a `providers.paths.ro` grant to read or a `providers.paths.rw` grant to write, unless the path is always-blocked, in the `block` list, or excluded by an AI ignore file. Never work around a block with a rename, a subprocess, or a symlink. In Claude Code, `dangerouslyDisableSandbox` removes only its own per-command sandbox, never corral's.",
		"- Put scratch files, scripts, and intermediate output in a `scratchpad/` directory in the working directory, not /tmp. The harness may point you at a /tmp scratchpad path, but /tmp here is sandbox-private and the user can't see it; the working directory is writable and visible to you both.",
	}
	lines = appendNoteBullets(lines, backendNotes)
	lines = appendNoteBullets(lines, providerNotes)
	return strings.Join(lines, "\n")
}

// appendNoteBullets appends each non-blank line of raw as a "- " bullet.
func appendNoteBullets(lines []string, raw string) []string {
	for _, ln := range strings.Split(raw, "\n") {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		if !strings.HasPrefix(ln, "- ") {
			ln = "- " + ln
		}
		lines = append(lines, ln)
	}
	return lines
}

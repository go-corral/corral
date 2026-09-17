package sandbox

import (
	"fmt"
	"strings"
)

// RenderPermissionsDoc renders the baseline rules into the Markdown permissions
// reference. Generated, never hand-edited; a drift-guard test holds the doc in sync.
func RenderPermissionsDoc(rules []Rule) string {
	var b strings.Builder
	b.WriteString("# Sandbox filesystem baseline\n\n")
	b.WriteString("> Generated from `internal/sandbox/baseline/sandbox-permissions.json` by\n")
	b.WriteString("> `go test ./internal/sandbox -update`. **Do not edit by hand.**\n\n")
	b.WriteString("The sandbox exposes **only** the paths below — deny-by-default: a path is\n")
	b.WriteString("reachable inside the sandbox only if a rule allows it. This is the safe base\n")
	b.WriteString("filesystem and nothing more. Feature mounts (docker socket, ssh-agent socket,\n")
	b.WriteString("kubeconfig) come from **Providers**, not this baseline; the per-launch working\n")
	b.WriteString("directory and your config `providers.paths.rw/ro` are layered on top at launch.\n\n")
	b.WriteString("This baseline is **agent-neutral**: the paths the *selected* agent needs outside\n")
	b.WriteString("its config dir (e.g. Claude Code's `~/.claude.json`) are contributed by that agent\n")
	b.WriteString("and folded in at launch, so they appear only when that agent runs — they are not\n")
	b.WriteString("listed here. See `docs/reference/agents.md`.\n\n")
	b.WriteString("Tokens (`$HOME`, `$AGENT_CONFIG_DIR`, …) are expanded per launch.\n\n")

	writeTable := func(title, goos string) {
		b.WriteString("## " + title + "\n\n")
		b.WriteString("| Path | Access | Flags | Description |\n")
		b.WriteString("| --- | --- | --- | --- |\n")
		for _, r := range rules {
			if !ArchMatch(r, goos) {
				continue
			}
			access := "ro"
			if r.Writeable {
				access = "rw"
			}
			var flags []string
			if r.Optional {
				flags = append(flags, "optional")
			}
			if r.Recursive != nil && !*r.Recursive {
				flags = append(flags, "node")
			}
			if r.Regex {
				flags = append(flags, "regex")
			}
			if r.Create {
				flags = append(flags, "create")
			}
			if r.ResolveSymlinks {
				flags = append(flags, "resolve-symlinks")
			}
			fl := strings.Join(flags, ", ")
			if fl == "" {
				fl = "—"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.Path, access, fl, r.Description)
		}
		b.WriteString("\n")
	}

	writeTable("Linux", "linux")
	writeTable("macOS — Seatbelt", "macos")
	return b.String()
}

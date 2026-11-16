// Package block is the providers.block config section: the config deny lists.
// The always-blocked paths are not part of it — DefaultSpec bakes them into the
// spec before the launcher applies the config sections.
package block

import "strings"

// AgentNotes returns the agent note for the config-added deny lists, or nil when
// both are empty.
func AgentNotes(dirs, files []string) []string {
	if len(dirs)+len(files) == 0 {
		return nil
	}
	// Every entry, with no cap: the agent checks a failed path against this list.
	masked := append(append([]string{}, dirs...), files...)
	return []string{"`providers.block` masks these paths, and the user can remove an entry: `" + strings.Join(masked, "`, `") + "`"}
}

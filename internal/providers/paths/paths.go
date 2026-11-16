// Package paths is the providers.paths config section: the extra host-path
// grants (providers.paths.rw / .ro).
package paths

import "github.com/go-corral/corral/internal/providers/spec"

// AgentNotes returns one agent note per non-empty grant list.
func AgentNotes(rw, ro []string) []string {
	var notes []string
	if len(rw) > 0 {
		notes = append(notes, "extra writable host paths granted by config: "+spec.SummarizeQuoted(rw))
	}
	if len(ro) > 0 {
		notes = append(notes, "extra read-only host paths granted by config: "+spec.SummarizeQuoted(ro))
	}
	return notes
}

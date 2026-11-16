// Package env is the providers.env config section: the sandbox env policy. The
// passthrough half is applied by DefaultSpec — the base < passthrough < agent-env <
// sandbox-marker layering is load-bearing. The launcher applies the set half.
package env

import "strings"

// AgentNotes returns the agent note that names the pinned variables, or nil when
// set is empty.
func AgentNotes(set []Var) []string {
	if len(set) == 0 {
		return nil
	}
	names := make([]string, len(set))
	for i, s := range set {
		names[i] = s.Name
	}
	// Names only — a pinned value may be something the operator would not want
	// riding the model's context every turn.
	return []string{"config pins these env vars inside the sandbox (already set, do not export/override): " + strings.Join(names, ", ")}
}

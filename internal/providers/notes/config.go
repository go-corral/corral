package notes

import (
	"errors"
	"fmt"
	"strings"
)

// maxAgentBytes restricts the notes size to avoid blowing up the environment variables
const maxAgentBytes = 64 << 10 // 64 KiB

// Config contains the lines added to the context
type Config struct {
	Agent []string `yaml:"agent"`
}

// Lines returns Agent deduplicated, with each entry trimmed of leading/trailing whitespace
func (c Config) Lines() []string {
	seen := make(map[string]bool, len(c.Agent))
	out := make([]string, 0, len(c.Agent))
	for _, line := range c.Agent {
		trimmed := strings.TrimSpace(line)
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		out = append(out, trimmed)
	}
	return out
}

// Validate checks providers.notes.agent: an entry must be non-empty and free of
// LF/CR/NUL after trimming and the trimmed entries must not exceed the 64 KiB limit
func (c Config) Validate() error {
	var total int
	for _, trimmed := range c.Lines() {
		if trimmed == "" {
			return errors.New("providers.notes.agent: an entry is empty after trimming")
		}
		if strings.ContainsAny(trimmed, "\n\r\x00") {
			return fmt.Errorf("providers.notes.agent: %q contains a line feed, carriage return, or NUL byte", trimmed)
		}
		total += len(trimmed)
	}
	if total > maxAgentBytes {
		return fmt.Errorf("providers.notes.agent: entries total %d bytes, over the %d-byte limit", total, maxAgentBytes)
	}
	return nil
}

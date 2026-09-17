package aiignore

import (
	"fmt"
	"strings"
)

// Config configures repo-level AI-exclusion discovery (providers.aiignore).
// The built-in defaults (.aiignore, .aiexclude) are always present and config
// entries only add to them (append-unique merge). Only the native default
// sources are self-protected from in-sandbox edits.
type Config struct {
	Sources []string `yaml:"sources"`
}

// DefaultSources are the built-in, always-active repo AI-exclusion filenames,
// and the native set: only these are self-protected.
var DefaultSources = []string{".aiignore", ".aiexclude"}

// EffectiveSources returns the configured source filenames, falling back to
// DefaultSources for a hand-built Config that never loaded internal/config's
// defaults.
func (c Config) EffectiveSources() []string {
	if len(c.Sources) > 0 {
		return c.Sources
	}
	return append([]string(nil), DefaultSources...)
}

// Validate checks providers.aiignore: each source must be a bare filename.
func (c Config) Validate() error {
	for _, s := range c.Sources {
		if s == "" || s == "." || s == ".." || strings.ContainsAny(s, "/\\") {
			return fmt.Errorf("providers.aiignore.sources: %q must be a bare filename (no path separators)", s)
		}
	}
	return nil
}

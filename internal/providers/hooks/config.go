package hooks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/go-corral/corral/internal/providers/spec"
)

// Config defines host-side scripts around the agent session. preStart entries may abort before
// launch; postEnd entries run after any session end and only warn on failure. These are unrelated
// to the in-sandbox `corral hook` enforcer.
type Config struct {
	// PreStart entries run before the agent starts, in lexical key order (run-parts style:
	// prefix 10-, 20- when order matters). A non-optional failure aborts the launch.
	PreStart map[string]Hook `yaml:"preStart"`
	// PostEnd entries run after the session ends (any exit, and on an aborted launch where a
	// preStart entry already ran), in lexical key order. Failures are always warn-only.
	PostEnd map[string]Hook `yaml:"postEnd"`
}

// Hook is one session-hook executable and its failure policy. Naming a file rather than a shell
// command lets the repo-config trust gate approve the exact bytes run on the host.
type Hook struct {
	// Exec is run directly, without a shell or PATH lookup. Relative paths resolve against the
	// session workdir; scripts use their shebang. Required for enabled entries.
	Exec string `yaml:"exec"`
	// Args are optional arguments covered by the config's trust hash. They merge additively across
	// layers; replace them by disabling the repo entry and defining another.
	Args []string `yaml:"args"`
	// Optional makes a preStart failure warn and continue. postEnd failures are always warnings.
	Optional bool `yaml:"optional"`
	// Enabled is a pointer so an explicit false survives layer merging. nil means enabled.
	Enabled *bool `yaml:"enabled"`
}

// IsEnabled reports whether the entry is active. nil defaults to enabled;
// only an explicit `enabled: false` disables it.
func (h Hook) IsEnabled() bool {
	return h.Enabled == nil || *h.Enabled
}

// Enabled reports whether the provider does anything: any enabled entry in either map.
func (c Config) Enabled() bool {
	return countEnabled(c.PreStart) > 0 || countEnabled(c.PostEnd) > 0
}

// Validate checks every label and requires an executable for enabled entries.
func (c Config) Validate() error {
	for _, ev := range []struct {
		name string
		m    map[string]Hook
	}{
		{"preStart", c.PreStart},
		{"postEnd", c.PostEnd},
	} {
		for _, key := range sortedKeys(ev.m) {
			// Checked for every key, disabled included: a later layer may re-enable it.
			if key == "" || spec.SanitizeLabel(key) != key {
				return fmt.Errorf("providers.hooks.%s.%q: invalid key — use run-parts style names "+
					"(letters, digits, '-', '_', '.'; start and end alphanumeric; e.g. 10-update)", ev.name, key)
			}
			if h := ev.m[key]; h.IsEnabled() && h.Exec == "" {
				return fmt.Errorf("providers.hooks.%s.%s: exec must not be empty", ev.name, key)
			}
		}
	}
	return nil
}

// Grants returns the `corral validate` summary of enabled hooks by event.
func (c Config) Grants() string {
	pre, post := countEnabled(c.PreStart), countEnabled(c.PostEnd)
	noun := "session hooks"
	if pre+post == 1 {
		noun = "session hook"
	}
	return fmt.Sprintf("runs %d pre-start / %d post-end host %s", pre, post, noun)
}

// FailurePolicy describes the configured hooks' failure behavior for validation reports.
func (c Config) FailurePolicy() string {
	required, optional := false, false
	for _, h := range c.PreStart {
		if !h.IsEnabled() {
			continue
		}
		if h.Optional {
			optional = true
		} else {
			required = true
		}
	}
	var parts []string
	if required {
		parts = append(parts, "required pre-start failures abort launch")
	}
	if optional {
		parts = append(parts, "optional pre-start failures continue")
	}
	if countEnabled(c.PostEnd) > 0 {
		parts = append(parts, "post-end failures warn")
	}
	return strings.Join(parts, "; ")
}

func sortedKeys(m map[string]Hook) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedStringKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func countEnabled(m map[string]Hook) int {
	n := 0
	for _, h := range m {
		if h.IsEnabled() {
			n++
		}
	}
	return n
}

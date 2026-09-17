package seatbelt

import (
	"fmt"
	"strings"
)

// Config is the macOS Seatbelt backend's configuration (config key
// sandbox.seatbelt).
type Config struct {
	Mach Mach `yaml:"mach"`
}

// Validate checks the mach knobs: lookup is open|strict, and each allow entry
// is a non-empty Mach global-name without whitespace or quote that does not
// compile to a match-all empty prefix.
func (c Config) Validate() error {
	switch c.Mach.Lookup {
	case "", "open", "strict":
	default:
		return fmt.Errorf("sandbox.seatbelt.mach.lookup: %q is not one of open|strict", c.Mach.Lookup)
	}
	for _, m := range c.Mach.Allow {
		if m == "" || strings.ContainsAny(m, " \t\n\"") {
			return fmt.Errorf("sandbox.seatbelt.mach.allow: %q must be a non-empty Mach global-name without whitespace or quotes", m)
		}
		// A bare "*" compiles to an empty prefix that matches every Mach service,
		// silently lifting strict's whole deny-default. Reject it so config can
		// only add named services, never re-open it wholesale.
		if machAllowEntry(m).Name == "" {
			return fmt.Errorf("sandbox.seatbelt.mach.allow: %q matches every Mach service (empty name prefix); list explicit service names, not a bare '*'", m)
		}
	}
	return nil
}

// Mach configures the macOS mach-lookup posture. The config default is "strict"
// (deny-default mach-lookup, re-allowing only the embedded allowlist plus
// Allow); "open" falls back to allow-default. The zero value is open.
type Mach struct {
	Lookup string   `yaml:"lookup"`
	Allow  []string `yaml:"allow"`
}

// Strict reports whether the deny-default strict mach-lookup posture is selected.
func (m Mach) Strict() bool { return m.Lookup == "strict" }

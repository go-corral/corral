package env

import (
	"fmt"
	"slices"

	"github.com/go-corral/corral/internal/providers/spec"
)

// Config controls the sandbox environment (providers.env). Passthrough is a
// strict allowlist of variable names forwarded from the host when set; Set fixes
// variables to literal values. A name may be in one, never both.
type Config struct {
	Passthrough []string `yaml:"passthrough"`
	Set         []Var    `yaml:"set"`
}

// Var is one Set entry. The Kubernetes-style {name, value} shape leaves room to add
// a sibling source field later without a breaking format change.
type Var struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
}

// Validate checks providers.env. coreReserved is corral's own core markers (which
// passthrough may not forward); allReserved is the full reserved set that Set may not name.
func (c Config) Validate(coreReserved []string, allReserved map[string]bool) error {
	for _, name := range c.Passthrough {
		if !isEnvName(name) {
			return fmt.Errorf("providers.env.passthrough: %q is not a valid environment variable name", name)
		}
		if slices.Contains(coreReserved, name) {
			return fmt.Errorf("providers.env.passthrough: %q is reserved by corral and cannot be forwarded", name)
		}
	}

	passSet := make(map[string]bool, len(c.Passthrough))
	for _, name := range c.Passthrough {
		passSet[name] = true
	}
	seenSet := make(map[string]bool, len(c.Set))
	for _, e := range c.Set {
		if !isEnvName(e.Name) {
			return fmt.Errorf("providers.env.set: %q is not a valid environment variable name", e.Name)
		}
		if allReserved[e.Name] {
			return fmt.Errorf("providers.env.set: %q is reserved by corral and cannot be set", e.Name)
		}
		if passSet[e.Name] {
			return fmt.Errorf("providers.env: %q is in both passthrough and set; a variable is either forwarded or set, not both", e.Name)
		}
		if seenSet[e.Name] {
			return fmt.Errorf("providers.env.set: %q is set more than once", e.Name)
		}
		seenSet[e.Name] = true
	}
	return nil
}

// isEnvName aliases spec.IsEnvName.
var isEnvName = spec.IsEnvName

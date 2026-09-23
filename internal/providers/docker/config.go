package docker

import "github.com/go-corral/corral/internal/health"

// Config configures the docker socket-broker (providers.docker).
type Config struct {
	Enabled  bool `yaml:"enabled"`
	Optional bool `yaml:"optional"`
}

// Grants describes what enabling docker adds.
func (c Config) Grants() string {
	return "docker daemon socket + ~/.docker"
}

// Warnings returns the advisory notices this config deserves at launch: the
// docker socket is a root-equivalent capability.
func (c Config) Warnings() []health.Check {
	if !c.Enabled {
		return nil
	}
	return []health.Check{{State: health.Warn, Label: "docker", Value: "grants root-equivalent host access",
		Reason: "a sandboxed process can mount the host filesystem, run privileged containers, and escape isolation"}}
}

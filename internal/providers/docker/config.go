package docker

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
func (c Config) Warnings() []string {
	if !c.Enabled {
		return nil
	}
	return []string{"docker is enabled — the docker socket grants root-equivalent host access " +
		"(a sandboxed process can mount the host filesystem, run privileged containers, and escape isolation)"}
}

package ssh

// Config configures the ssh provider (providers.ssh), which grants SSH into the
// sandbox when enabled.
type Config struct {
	Enabled  bool `yaml:"enabled"`
	Optional bool `yaml:"optional"`
}

// Grants describes what enabling ssh adds.
func (c Config) Grants() string {
	return "ssh-agent (socket + env) + read-only ~/.ssh config & known_hosts"
}

package bwrap

// Config is the Linux bwrap backend's configuration (config key sandbox.bwrap).
type Config struct{}

func (c Config) Validate() error { return nil }

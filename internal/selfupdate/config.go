package selfupdate

// Config configures corral's self-update notice on `corral run`. The release source is not
// a config field — it is fixed at compile time.
type Config struct {
	CheckOnStart bool `yaml:"checkOnStart"`
}

package home

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/pathutil"
)

// Config configures the private-$HOME provider (providers.home): HOME is
// redirected to Path and the launcher symlinks the allowed-under-home host
// paths into it. Default on.
type Config struct {
	Enabled bool `yaml:"enabled"`
	// Path is the host directory used as the sandbox's $HOME. Empty -> DefaultPath.
	Path string `yaml:"path"`
	// Keep lists private-home entries that intentionally shadow an allowed host
	// path, relative to the private home. Not host-~-expanded at load.
	Keep []string `yaml:"keep"`
}

// Grants describes what the home provider adds.
func (c Config) Grants() string {
	return "private $HOME (allowed paths symlinked in; tool caches & state isolated)"
}

// Validate checks providers.home: a custom Path must be absolute, and every Keep
// entry must normalize to a path inside the private home.
func (c Config) Validate() error {
	if p := c.Path; p != "" {
		if err := pathutil.RequireAbs("providers.home.path", p); err != nil {
			return err
		}
	}
	for _, k := range c.Keep {
		if _, ok := keepRel(k); !ok {
			return fmt.Errorf("providers.home.keep: %q must be a path relative to the private home (a leading ~/ is allowed) that stays inside it", k)
		}
	}
	return nil
}

// KeepRel returns the Keep entries normalized; entries Validate would reject are dropped.
func (c Config) KeepRel() []string {
	var out []string
	for _, k := range c.Keep {
		if rel, ok := keepRel(k); ok {
			out = append(out, rel)
		}
	}
	return out
}

// keepRel normalizes one Keep entry; ok is false for an entry that is not a path
// inside the private home.
func keepRel(entry string) (string, bool) {
	e := strings.TrimPrefix(entry, "~/")
	if e == "" || e == "~" || filepath.IsAbs(e) {
		return "", false
	}
	e = filepath.Clean(e)
	if e == "." || e == ".." || strings.HasPrefix(e, "../") {
		return "", false
	}
	return e, true
}

// DefaultPath is the sandbox's private $HOME when Path is unset: a persistent
// ~/.cache/corral/home-<hash> keyed to the active agent's config dir.
func DefaultPath(realHome, agentConfigDir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(agentConfigDir)))
	return filepath.Join(realHome, ".cache", "corral", "home-"+hex.EncodeToString(sum[:4]))
}

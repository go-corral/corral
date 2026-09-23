package block

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"github.com/go-corral/corral/internal/health"
	"github.com/go-corral/corral/internal/pathutil"
)

// Config lists paths the sandbox masks and the hook denies (providers.block).
// Directories are masked recursively; files are masked by a read-only stub bind.
// Both lists only add denies; Validate carries the absolute-path and
// always-blocked-interaction checks.
type Config struct {
	Directories []string `yaml:"directories"`
	Files       []string `yaml:"files"`
}

// Validate checks providers.block: every entry must be an absolute (or ~-prefixed)
// path, and no file entry may sit at or under an always-blocked directory. floor
// arrives ~-expanded and cleaned.
func (c Config) Validate(floor []string) error {
	for _, p := range c.Directories {
		if err := pathutil.RequireAbs("providers.block.directories", p); err != nil {
			return err
		}
	}
	for _, p := range c.Files {
		if err := pathutil.RequireAbs("providers.block.files", p); err != nil {
			return err
		}
	}
	// A block.files entry at or under an always-blocked directory is redundant and
	// signals a likely mistake.
	for _, floorDir := range floor {
		for _, bf := range c.Files {
			if pathutil.AtOrUnder(bf, floorDir) {
				return fmt.Errorf("providers.block.files: %q is already covered by the always-blocked path %q; remove it", bf, floorDir)
			}
		}
	}
	return nil
}

// Warnings returns the lint results for the providers.block: entries that do not exist
func (c Config) Warnings() []health.Check {
	var w []health.Check
	for _, l := range []struct {
		key   string
		paths []string
	}{{"directories", c.Directories}, {"files", c.Files}} {
		for _, p := range l.paths {
			if _, err := os.Lstat(p); errors.Is(err, fs.ErrNotExist) {
				w = append(w, health.Check{State: health.Warn, Label: "block." + l.key, Value: fmt.Sprintf("%q does not exist", p)})
			}
		}
	}
	return w
}

// Package pathutil holds path helpers that security-relevant path gates share.
package pathutil

import (
	"fmt"
	"path/filepath"
	"strings"
)

func nestedUnder(p, dir string) bool {
	return len(p) > len(dir) &&
		p[:len(dir)] == dir &&
		p[len(dir):len(dir)+1] == string(filepath.Separator)
}

// AtOrUnder reports whether p equals or is nested under dir. Both arguments must be
// absolute and cleaned. Prefix-safe; "/" contains every absolute path.
func AtOrUnder(p, dir string) bool {
	if p == dir {
		return true
	}
	if dir == string(filepath.Separator) {
		return true
	}
	return nestedUnder(p, dir)
}

// Under reports whether p is strictly nested under dir (equal paths return false).
func Under(p, dir string) bool {
	if dir == string(filepath.Separator) {
		return strings.HasPrefix(p, dir) && p != dir
	}
	return nestedUnder(p, dir)
}

func AtOrUnderClean(p, dir string) bool {
	return AtOrUnder(filepath.Clean(p), filepath.Clean(dir))
}

// Resolve returns p's symlink-resolved real path, falling back to cleaned p when it cannot
// be resolved. A resolution failure is never an error: the lexical fallback is what the
// caller's own check already compared, so Resolve is used in addition to a lexical check,
// never instead of it.
func Resolve(p string) string {
	if real, err := filepath.EvalSymlinks(p); err == nil {
		return real
	}
	return filepath.Clean(p)
}

func RequireAbs(field, p string) error {
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%s: %q must be an absolute or ~-prefixed path", field, p)
	}
	return nil
}

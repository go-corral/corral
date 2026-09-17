package sandbox

import (
	"path/filepath"

	"github.com/go-corral/corral/internal/pathutil"
)

func archForGOOS(goos string) string {
	switch goos {
	case "linux":
		return "linux"
	case "darwin":
		return "macos"
	default:
		return ""
	}
}

// BaselineDirs returns the host directory subtrees the static baseline mounts
// for goos, with tokens expanded. Regex and single-node (recursive:false) rules
// are excluded, and a rule whose token is missing/empty is skipped. The
// per-launch working directory and config providers.paths.rw/ro are not included.
func BaselineDirs(tokens map[string]string, goos string) []string {
	arch := archForGOOS(goos)
	if arch == "" {
		return nil
	}
	var dirs []string
	for _, r := range BaselineRules() {
		if !ArchMatch(r, arch) || r.Regex {
			continue
		}
		if r.Recursive != nil && !*r.Recursive {
			continue
		}
		if p, ok := ExpandPath(r.Path, tokens); ok {
			dirs = append(dirs, filepath.Clean(p))
		}
	}
	return dirs
}

// PathReachableInCorral reports whether hostPath would be reachable from inside
// a sandbox using the static baseline mounts alone. `corral sync` uses it to
// warn when the hook binary lives outside every baseline mount — the in-sandbox
// claude would then fail to exec the hook, silently disabling enforcement.
//
// hostPath should already be absolute and symlink-resolved.
func PathReachableInCorral(hostPath string, tokens map[string]string, goos string) bool {
	clean := filepath.Clean(hostPath)
	for _, dir := range BaselineDirs(tokens, goos) {
		if pathutil.AtOrUnder(clean, dir) {
			return true
		}
	}
	return false
}

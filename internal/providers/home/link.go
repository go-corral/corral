package home

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-corral/corral/internal/pathutil"
	"github.com/go-corral/corral/internal/sandbox"
)

// Link populates the sandbox-private home with symlinks back to every allowed-under-realHome
// host path. Always-blocked safety is structural: no always-blocked dir is ever a baseline target
// or mounted. It only creates or retargets symlinks; a pre-existing real file/dir is left untouched
// and returned as a launch warning. keep holds private-home-relative paths whose warning is
// suppressed. With apply false nothing on disk changes.
func Link(spec *sandbox.SandboxSpec, realHome, privHome, goos string, keep []string, guardDir string, apply bool) (shadows []string, err error) {
	realHome, privHome = filepath.Clean(realHome), filepath.Clean(privHome)
	cands := homeCandidates(spec, realHome, privHome, goos)
	// Shallowest paths first so a parent dir's symlink is created before any child.
	slices.SortFunc(cands, func(a, b string) int {
		return cmp.Compare(strings.Count(filepath.Clean(a), string(os.PathSeparator)), strings.Count(filepath.Clean(b), string(os.PathSeparator)))
	})

	for _, real := range cands {
		rel, _ := filepath.Rel(realHome, real) // cannot fail: homeCandidates checked real is under realHome
		// Skip targets that do not exist on the host.
		if _, err := os.Lstat(real); err != nil {
			continue
		}
		link := filepath.Join(privHome, rel)
		if link == real {
			continue // would self-reference
		}
		// Parent already redirects — skip.
		if ancestorIsSymlink(privHome, link) {
			continue
		}
		switch fi, err := os.Lstat(link); {
		case err == nil && fi.Mode()&os.ModeSymlink != 0:
			// Existing symlink: retarget only if it points elsewhere.
			if cur, _ := os.Readlink(link); cur == real {
				continue
			}
			if !apply {
				continue
			}
			if err := os.Remove(link); err != nil {
				return nil, fmt.Errorf("link home: retarget %s: %w", link, err)
			}
		case err == nil:
			guarded := guardDir != "" && filepath.Clean(real) == filepath.Clean(guardDir)
			if s, ok := shadowWarning(fi.IsDir(), link, real, rel, guarded, keep); ok {
				shadows = append(shadows, s)
			}
			continue
		case !errors.Is(err, fs.ErrNotExist):
			// ENOTDIR, ELOOP, EACCES: no symlink could be placed here, fail closed.
			return nil, fmt.Errorf("link home: inspect %s: %w", link, err)
		}
		if !apply {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
			return nil, fmt.Errorf("link home: create %s: %w", filepath.Dir(link), err)
		}
		if err := os.Symlink(real, link); err != nil {
			return nil, fmt.Errorf("link home: symlink %s -> %s: %w", link, real, err)
		}
	}
	return shadows, nil
}

// shadowWarning formats the warning for a real private-home entry standing where a symlink
// to the host path belongs. The guarded agent config dir gets its own text and ignores keep.
func shadowWarning(isDir bool, link, real, rel string, guarded bool, keep []string) (string, bool) {
	kind := "file"
	if isDir {
		kind = "directory"
	}
	if guarded {
		return fmt.Sprintf("home: $HOME/%s is a real %s in the private home (%s), not a link to the agent config dir %s: the agent reads its settings from the private copy, so the hooks corral sync registered on the host do not apply and the session may run unenforced; move it aside (providers.home.keep does not cover the agent config dir)",
			rel, kind, link, real), true
	}
	if keptEntry(keep, rel) {
		return "", false
	}
	return fmt.Sprintf("home: $HOME/%s is a real %s in the private home (%s), not a link to the host path %s; move it aside, or list %q under providers.home.keep",
		rel, kind, link, real, rel), true
}

func keptEntry(keep []string, rel string) bool {
	for _, k := range keep {
		if rel == k || strings.HasPrefix(rel, k+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// homeCandidates collects the real host paths under realHome that the sandbox allows:
// the launch rule set plus assembled spec mounts, excluding the workdir and anything under privHome.
// The checks and the dedup use the cleaned path; the returned path keeps its spelling, because
// the kernel resolves ".." after following symlinks. realHome and privHome must be clean.
func homeCandidates(spec *sandbox.SandboxSpec, realHome, privHome, goos string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" {
			return
		}
		c := filepath.Clean(p)
		if seen[c] {
			return
		}
		if !pathutil.Under(c, realHome) || pathutil.Under(c, privHome) || c == privHome {
			return
		}
		seen[c] = true
		out = append(out, p)
	}

	for _, r := range sandbox.RulesFor(*spec) {
		if !sandbox.ArchMatch(r, goos) || r.Regex {
			continue // regex rules are not concrete paths to link
		}
		if p, ok := sandbox.ExpandPath(r.Path, spec.Tokens); ok {
			add(p)
		}
	}
	for _, m := range spec.Mounts {
		if m.Src == spec.WorkDir {
			continue // workdir is reached by absolute path, not via $HOME
		}
		add(m.Src)
	}
	return out
}

// ancestorIsSymlink reports whether any directory component between base and link's
// parent is already a symlink on disk.
func ancestorIsSymlink(base, link string) bool {
	rel, err := filepath.Rel(base, filepath.Dir(link))
	if err != nil || rel == "." {
		return false
	}
	cur := base
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		if fi, err := os.Lstat(cur); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return true
		}
	}
	return false
}

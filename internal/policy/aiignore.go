package policy

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// AIIgnoreRule denies tool calls touching paths matched by a repo-level AI ignore file
// (.aiignore / .aiexclude). It is additive on the always-blocked and config block paths:
// it only adds denies, never re-allows. Event paths are canonicalized against the event cwd
// before matching. See MatchAIIgnore for the pattern subset.
type AIIgnoreRule struct {
	Root     string   // canonical repo root; empty disables the rule (no-op, never fail-closed)
	Patterns []string // raw ignore-file entries (comment/blank lines stripped)
}

func (r *AIIgnoreRule) Name() string { return "ai-ignore" }

func (r *AIIgnoreRule) Evaluate(ev *HookEvent) (Decision, bool, error) {
	if r.Root == "" || len(r.Patterns) == 0 {
		return Decision{}, false, nil
	}
	paths, err := ev.FilePaths()
	if err != nil {
		return Decision{}, false, err
	}
	for _, raw := range paths {
		canon, err := ev.canonicalize(raw)
		if err != nil {
			return Decision{}, false, err
		}
		if pat, hit := MatchAIIgnore(r.Root, canon, r.Patterns); hit {
			return Decision{
				Action: Deny,
				Rule:   r.Name(),
				Reason: fmt.Sprintf("%s is excluded by a repo AI ignore rule (pattern %q, resolved %q)", canon, pat, raw),
			}, true, nil
		}
	}
	return Decision{}, false, nil
}

// MatchAIIgnore reports whether canonicalPath is excluded by any ignore pattern rooted at root,
// returning the matching pattern. A path not under root is never matched. Exported so the
// launcher reuses the exact same matcher for the filesystem mask.
func MatchAIIgnore(root, canonicalPath string, patterns []string) (string, bool) {
	rel, ok := relUnder(canonicalPath, root)
	if !ok {
		return "", false
	}
	pathSegs := strings.Split(rel, "/")
	for _, raw := range patterns {
		patSegs, ok := compileIgnorePattern(raw)
		if !ok {
			continue
		}
		if matchAnyPrefix(pathSegs, patSegs) {
			return raw, true
		}
	}
	return "", false
}

func relUnder(p, root string) (string, bool) {
	if root == "" || p == root || !Within(p, root) {
		return "", false
	}
	rel := strings.TrimPrefix(p[len(root):], string(filepath.Separator))
	return filepath.ToSlash(rel), true
}

// compileIgnorePattern turns one raw ignore entry into match segments, or ok=false to skip it.
// A bare name is anchored "at any depth" via a leading `**` segment; a leading or embedded
// slash anchors to the repo root. A trailing slash (directory marker) is dropped.
func compileIgnorePattern(pat string) ([]string, bool) {
	pat = strings.TrimSpace(pat)
	if pat == "" || strings.HasPrefix(pat, "#") || strings.HasPrefix(pat, "!") {
		return nil, false
	}
	pat = strings.TrimSuffix(pat, "/")
	anchored := strings.HasPrefix(pat, "/")
	pat = strings.TrimPrefix(pat, "/")
	if pat == "" {
		return nil, false
	}
	if strings.Contains(pat, "/") {
		anchored = true
	}
	segs := strings.Split(pat, "/")
	if !anchored {
		segs = append([]string{"**"}, segs...)
	}
	out := segs[:0]
	for _, s := range segs {
		if s == "**" && len(out) > 0 && out[len(out)-1] == "**" {
			continue
		}
		out = append(out, s)
	}
	return out, true
}

// matchAnyPrefix reports whether the pattern matches the full path or any ancestor directory,
// so a pattern matching a directory blocks the whole subtree beneath it.
func matchAnyPrefix(pathSegs, patSegs []string) bool {
	for i := 1; i <= len(pathSegs); i++ {
		if segMatch(pathSegs[:i], patSegs) {
			return true
		}
	}
	return false
}

// segMatch reports whether patSegs matches the entire pathSegs slice. `**` consumes zero or
// more whole segments; any other segment is matched by path.Match. Iterative with backtracking
// to the last `**`: O(len(pathSegs)*len(patSegs)), allocation-free. Patterns come from repo
// content and run on every tool call, so exponential recursion would be a DoS vector.
func segMatch(pathSegs, patSegs []string) bool {
	p, q := 0, 0
	star, starPath := -1, 0
	for p < len(pathSegs) {
		switch {
		case q < len(patSegs) && patSegs[q] == "**":
			star, starPath = q, p
			q++
		case q < len(patSegs) && globSegMatch(patSegs[q], pathSegs[p]):
			p, q = p+1, q+1
		case star >= 0:
			starPath++
			p, q = starPath, star+1
		default:
			return false
		}
	}
	for q < len(patSegs) && patSegs[q] == "**" {
		q++
	}
	return q == len(patSegs)
}

// globSegMatch matches one pattern segment against one path segment. A malformed glob
// segment matches nothing: path.Match's error is swallowed (this matcher is deny-only).
func globSegMatch(pat, seg string) bool {
	ok, err := path.Match(pat, seg)
	return err == nil && ok
}

// AIIgnoreDiscovery is the discovered repo-level ignore state for one launch/hook init.
type AIIgnoreDiscovery struct {
	// Dir is the directory that holds the sources, Root its canonical form.
	Dir          string
	Root         string
	Patterns     []string
	Files        []string
	ProtectFiles []string
}

// isNativeSource reports whether a source filename is one of the built-in
// (native) AI-ignore files. Only native sources are self-protected from
// in-sandbox edits.
func isNativeSource(name string) bool {
	for _, n := range AIIgnoreNativeSources {
		if n == name {
			return true
		}
	}
	return false
}

// DiscoverAIIgnore walks up from startDir looking for the nearest directory containing
// any of the given source filenames and reads them. The search stops at the repo
// boundary (a directory containing .git). It is strictly best-effort: any read/stat
// error contributes nothing, and "no files found" returns a zero AIIgnoreDiscovery.
func DiscoverAIIgnore(startDir string, sources []string) AIIgnoreDiscovery {
	cur := startDir
	for cur != "" {
		var files, protect []string
		var patterns []string
		for _, name := range sources {
			p := filepath.Join(cur, name)
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			files = append(files, p)
			if isNativeSource(name) {
				protect = append(protect, p)
			}
			patterns = append(patterns, parseIgnoreLines(data)...)
		}
		if len(files) > 0 {
			root, err := CanonicalizeRoot(cur, "")
			if err != nil {
				root = filepath.Clean(cur)
			}
			return AIIgnoreDiscovery{Dir: cur, Root: root, Patterns: patterns, Files: files, ProtectFiles: protect}
		}
		// Repo boundary: do not search above .git.
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			return AIIgnoreDiscovery{}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return AIIgnoreDiscovery{}
		}
		cur = parent
	}
	return AIIgnoreDiscovery{}
}

// parseIgnoreLines splits ignore-file bytes into entries, dropping blank lines
// and comments.
func parseIgnoreLines(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// AIIgnoreProtectedPaths returns the paths of the given ignore source files, canonical in
// fsys, mapped to a self-protect reason. Callers pass only native sources.
func AIIgnoreProtectedPaths(files []string, fsys FS) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		if canon, err := CanonicalizeRootIn(fsys, f, ""); err == nil {
			out[canon] = "a repo AI ignore file"
		}
	}
	return out
}

// AIIgnoreNativeSources are the built-in, always-active repo AI-exclusion filenames,
// and the native set: only these are self-protected.
var AIIgnoreNativeSources = []string{".aiignore", ".aiexclude"}

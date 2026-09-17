package policy

import (
	"fmt"
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
		canon, err := Canonicalize(raw, ev.Cwd)
		if err != nil {
			return Decision{}, false, err
		}
		if pat, hit := MatchAIIgnore(r.Root, canon, r.Patterns); hit {
			return Decision{
				Action: Deny,
				Rule:   r.Name(),
				Reason: fmt.Sprintf("%s is excluded by a repo AI ignore rule (pattern %q); access is blocked by corral policy (resolved %q)", canon, pat, raw),
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

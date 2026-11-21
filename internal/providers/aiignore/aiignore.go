// Package aiignore is the providers.aiignore config section: the repo's AI-exclusion
// files. It holds the config, the launch-time mask that expands the ignore patterns to
// concrete paths, and the diagnostics for the patterns the matcher drops.
package aiignore

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers/spec"
)

// WalkCap bounds the launch-time filesystem walk that expands ignore patterns.
const WalkCap = 200_000

// NegationCount reports how many entries are "!" re-include negations, which
// corral's matcher drops (it has no negation). A source using them is
// over-approximated: corral may mask more than the source intends.
func NegationCount(patterns []string) int {
	n := 0
	for _, p := range patterns {
		if strings.HasPrefix(p, "!") {
			n++
		}
	}
	return n
}

// ConcreteMasks expands the ignore patterns to the concrete paths that currently
// match under root: matched directories (-> spec.BlockedPaths) and matched files
// (-> spec.BlockedFiles). A matched directory's whole subtree is masked, so the
// walk skips into it. Bounded by WalkCap; the hook still enforces every pattern.
func ConcreteMasks(root string, patterns []string) (dirs, files []string) {
	if root == "" || len(patterns) == 0 {
		return nil, nil
	}
	visited := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if p == root {
			return nil
		}
		if visited++; visited > WalkCap {
			return filepath.SkipAll
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if _, hit := policy.MatchAIIgnore(root, p, patterns); hit {
			if d.IsDir() {
				dirs = append(dirs, p)
				return filepath.SkipDir
			}
			if d.Type().IsRegular() {
				files = append(files, p)
			}
		}
		return nil
	})
	return dirs, files
}

// Masks is what the repo's ignore sources add to a launch: the concrete matches to
// mask, the banner rows, and the agent notes.
type Masks struct {
	Dirs       []string
	Files      []string
	Status     []string
	AgentNotes []string
}

// Mask discovers the ignore sources from workDir and expands their patterns to the
// concrete matches. It returns zero Masks when no source has a pattern.
func Mask(workDir string, sources []string) Masks {
	d := policy.DiscoverAIIgnore(workDir, sources)
	if len(d.Patterns) == 0 {
		return Masks{}
	}
	dirs, files := ConcreteMasks(d.Root, d.Patterns)
	masked := append(append([]string{}, dirs...), files...)

	note := "the patterns " + spec.SummarizeQuoted(d.Patterns) + " in `" + strings.Join(d.Files, "`, `") + "` exclude paths from AI tools. " +
		"The sandbox masks the paths that match now, and the hook blocks every match, also for files created later. Read the ignore files to check a path. The user can change these files."
	head := fmt.Sprintf("%d pattern(s) from %s — masking %d dir(s) + %d file(s)",
		len(d.Patterns), strings.Join(baseNames(d.Files), "/"), len(dirs), len(files))
	if len(masked) > 0 {
		head += ": " + spec.Summarize(masked)
	}
	status := []string{head}
	if negs := NegationCount(d.Patterns); negs > 0 {
		status = append(status, fmt.Sprintf("%d \"!\" re-include pattern(s) ignored (corral has no negation); it may mask more than the source intends", negs))
		note += " Corral ignores `!` lines, so a `!` line does not open a path."
	}
	return Masks{Dirs: dirs, Files: files, Status: status, AgentNotes: []string{note}}
}

// baseNames maps discovered source paths to their filenames for terse display.
func baseNames(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

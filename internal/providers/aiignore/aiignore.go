// Package aiignore implements the built-in repo AI-exclusion provider. The
// exported functions are the shared half reused by the hook: pure reads, safe on
// the fail-closed hook path.
package aiignore

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-corral/corral/internal/policy"
	"github.com/go-corral/corral/internal/providers/spec"
)

// WalkCap bounds the launch-time filesystem walk that expands ignore patterns.
const WalkCap = 200_000

// Discovery is the discovered repo-level ignore state for one launch/hook init.
type Discovery struct {
	Root         string
	Patterns     []string
	Files        []string
	ProtectFiles []string
}

// isNativeSource reports whether a source filename is one of the built-in
// (native) AI-ignore files. Only native sources are self-protected from
// in-sandbox edits.
func isNativeSource(name string) bool {
	for _, n := range DefaultSources {
		if n == name {
			return true
		}
	}
	return false
}

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

// Discover walks up from startDir looking for the nearest directory containing
// any of the given source filenames and reads them. The search stops at the repo
// boundary (a directory containing .git). It is strictly best-effort: any read/stat
// error contributes nothing, and "no files found" returns a zero Discovery.
func Discover(startDir string, sources []string) Discovery {
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
			root, err := policy.CanonicalizeRoot(cur, "")
			if err != nil {
				root = filepath.Clean(cur)
			}
			return Discovery{Root: root, Patterns: patterns, Files: files, ProtectFiles: protect}
		}
		// Repo boundary: do not search above .git.
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			return Discovery{}
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return Discovery{}
		}
		cur = parent
	}
	return Discovery{}
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

// ProtectedPaths returns the canonical paths of the given ignore source files
// mapped to a self-protect reason. Callers pass only native sources.
func ProtectedPaths(files []string) map[string]string {
	out := map[string]string{}
	for _, f := range files {
		if canon, err := policy.CanonicalizeRoot(f, ""); err == nil {
			out[canon] = "a repo AI ignore file"
		}
	}
	return out
}

// --- the built-in provider (launcher half) ---

type provider struct {
	sources []string
}

// New builds the aiignore provider for the configured source filenames.
func New(sources []string) spec.Provider { return &provider{sources: sources} }

func (p *provider) Name() string { return "aiignore" }

func (p *provider) Available(ctx context.Context) bool { return true }

// Mint discovers the repo's ignore sources from the session workdir and masks the
// concrete matches. It is pure.
func (p *provider) Mint(ctx context.Context, sess spec.Session, dryRun bool) (*spec.Contribution, error) {
	d := Discover(sess.WorkDir, p.sources)
	if len(d.Patterns) == 0 {
		return nil, nil
	}
	dirs, files := ConcreteMasks(d.Root, d.Patterns)
	masked := append(append([]string{}, dirs...), files...)

	head := fmt.Sprintf("%d pattern(s) from %s — masking %d dir(s) + %d file(s)",
		len(d.Patterns), strings.Join(baseNames(d.Files), "/"), len(dirs), len(files))
	if len(masked) > 0 {
		head += ": " + spec.Summarize(masked)
	}
	status := []string{head}
	if negs := NegationCount(d.Patterns); negs > 0 {
		status = append(status, fmt.Sprintf("%d \"!\" re-include pattern(s) ignored (corral has no negation); it may mask more than the source intends", negs))
	}

	// The model-facing note: the hook blocks every pattern match, so the model
	// should not probe or retry these paths.
	note := "repo AI-ignore is active: paths matching " + strings.Join(baseNames(d.Files), "/") + " are blocked (reads fail, even for files created later)"
	if len(masked) > 0 {
		note += "; currently masked: " + spec.SummarizeQuoted(masked)
	}

	return &spec.Contribution{
		BlockedDirs:  dirs,
		BlockedFiles: files,
		Status:       status,
		AgentNotes:   []string{note},
	}, nil
}

// baseNames maps discovered source paths to their filenames for terse display.
func baseNames(paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}
	return out
}

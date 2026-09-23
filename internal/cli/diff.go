package cli

import (
	"fmt"
	"strings"

	"github.com/go-corral/corral/internal/cli/report"
)

// unifiedDiff renders a git-style unified diff between two texts with the given labels
// and three lines of context per hunk. Returns "" when inputs are byte-identical.
func unifiedDiff(before, after []byte, fromName, toName string, c report.Style) string {
	if string(before) == string(after) {
		return ""
	}
	a := splitLines(string(before))
	b := splitLines(string(after))
	ops := diffOps(a, b)

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s--- %s%s\n", c.Dim, fromName, c.Reset)
	fmt.Fprintf(&sb, "%s+++ %s%s\n", c.Dim, toName, c.Reset)
	for _, h := range hunks(ops, 3) {
		fmt.Fprintf(&sb, "%s@@ -%d,%d +%d,%d @@%s\n", c.Yellow, h.aStart, h.aCount, h.bStart, h.bCount, c.Reset)
		for _, ln := range h.lines {
			switch ln.kind {
			case opEqual:
				fmt.Fprintf(&sb, " %s\n", ln.text)
			case opDel:
				fmt.Fprintf(&sb, "%s-%s%s\n", c.Red, ln.text, c.Reset)
			case opAdd:
				fmt.Fprintf(&sb, "%s+%s%s\n", c.Green, ln.text, c.Reset)
			}
		}
	}
	return sb.String()
}

// splitLines splits text into lines, dropping a trailing newline to avoid a phantom empty line.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	s = strings.TrimSuffix(s, "\n")
	return strings.Split(s, "\n")
}

type opKind int

const (
	opEqual opKind = iota
	opDel
	opAdd
)

type op struct {
	kind opKind
	text string
}

// diffOps computes a line-level diff of a→b as a flat op sequence using LCS DP.
func diffOps(a, b []string) []op {
	n, m := len(a), len(b)
	// lcs[i][j] = length of the LCS of a[i:] and b[j:].
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, op{opEqual, a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, op{opDel, a[i]})
			i++
		default:
			ops = append(ops, op{opAdd, b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{opDel, a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, op{opAdd, b[j]})
	}
	return ops
}

type hunk struct {
	aStart, aCount int
	bStart, bCount int
	lines          []op
}

// hunks groups a flat op sequence into unified-diff hunks with up to ctx lines of context.
func hunks(ops []op, ctx int) []hunk {
	// Index of every changed op.
	var changed []int
	for i, o := range ops {
		if o.kind != opEqual {
			changed = append(changed, i)
		}
	}
	if len(changed) == 0 {
		return nil
	}

	// Merge changed indices into ranges, padded by ctx and coalesced.
	type span struct{ lo, hi int } // inclusive op indices
	var spans []span
	for _, idx := range changed {
		lo, hi := idx-ctx, idx+ctx
		if lo < 0 {
			lo = 0
		}
		if hi > len(ops)-1 {
			hi = len(ops) - 1
		}
		if n := len(spans); n > 0 && lo <= spans[n-1].hi+1 {
			spans[n-1].hi = hi
			continue
		}
		spans = append(spans, span{lo, hi})
	}

	// Running 1-based line numbers.
	aLine, bLine := 1, 1
	pos := 0
	var out []hunk
	for _, sp := range spans {
		// Advance line counters over the ops before this span.
		for ; pos < sp.lo; pos++ {
			switch ops[pos].kind {
			case opEqual:
				aLine++
				bLine++
			case opDel:
				aLine++
			case opAdd:
				bLine++
			}
		}
		h := hunk{aStart: aLine, bStart: bLine}
		for ; pos <= sp.hi; pos++ {
			o := ops[pos]
			h.lines = append(h.lines, o)
			switch o.kind {
			case opEqual:
				h.aCount++
				h.bCount++
				aLine++
				bLine++
			case opDel:
				h.aCount++
				aLine++
			case opAdd:
				h.bCount++
				bLine++
			}
		}
		// A zero-length side conventionally reports start 0.
		if h.aCount == 0 {
			h.aStart = 0
		}
		if h.bCount == 0 {
			h.bStart = 0
		}
		out = append(out, h)
	}
	return out
}

package cli

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/pathutil"
)

type grantNode struct {
	grant    bool
	children map[string]*grantNode
}

func (n *grantNode) child(name string) *grantNode {
	if n.children == nil {
		n.children = make(map[string]*grantNode)
	}
	if n.children[name] == nil {
		n.children[name] = &grantNode{}
	}
	return n.children[name]
}

// writePathTree groups absolute, config-expanded paths without inspecting the filesystem.
// Grants carry a [grant] tag. Returns the number of distinct grants.
func writePathTree(w io.Writer, c ansi, paths []string, home, indent string) int {
	displayHome := home
	for _, p := range paths {
		if pathutil.AtOrUnderClean(home, p) {
			displayHome = ""
			break
		}
	}

	roots := &grantNode{}
	count := 0
	for _, p := range paths {
		p = abbrevHome(p, displayHome)
		root := "/"
		if p == "~" || strings.HasPrefix(p, "~/") {
			root = "~"
			p = strings.TrimPrefix(p, "~")
		}
		n := roots.child(root)
		for part := range strings.SplitSeq(strings.TrimPrefix(p, "/"), "/") {
			if part != "" {
				n = n.child(part)
			}
		}
		if !n.grant {
			count++
		}
		n.grant = true
	}
	for _, root := range slices.Sorted(maps.Keys(roots.children)) {
		writeGrantNode(w, c, root, roots.children[root], indent, "", "")
	}
	return count
}

func writeGrantNode(w io.Writer, c ansi, label string, n *grantNode, indent, branch, continuation string) {
	// A grant may also be an ancestor of another grant; collapsing past it would hide access.
	for !n.grant && len(n.children) == 1 {
		for name, child := range n.children {
			label = strings.TrimSuffix(label, "/") + "/" + name
			n = child
			break
		}
	}
	tag, style := "", c.dim
	if n.grant {
		style = c.bold
		tag = "  [grant]"
	} else if !strings.HasSuffix(label, "/") {
		label += "/"
	}
	fmt.Fprintf(w, "%s%s%s%s%s%s\n", indent, branch, style, reportText(label), c.reset, tag)
	keys := slices.Sorted(maps.Keys(n.children))
	for i, name := range keys {
		branch, next := "├── ", "│   "
		if i == len(keys)-1 {
			branch, next = "└── ", "    "
		}
		writeGrantNode(w, c, name, n.children[name], indent+continuation, branch, next)
	}
}

// reportText quotes control characters and delimiter-like text so data cannot forge report rows.
func reportText(s string) string {
	if !utf8.ValidString(s) || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\\\"[]") {
		return strconv.Quote(s)
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return strconv.Quote(s)
		}
	}
	return s
}

// reportProfileName quotes names that collide with the profile list's separator or markers.
func reportProfileName(s string) string {
	if s == "" || s == "none" || strings.Contains(s, ",") {
		return strconv.Quote(s)
	}
	return reportText(s)
}

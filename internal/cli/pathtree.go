package cli

import (
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/pathutil"
)

// grant is one path the sandbox reaches, with its access (rw or ro) and the config that sets it.
type grant struct{ path, access, source string }

type grantNode struct {
	access, source string
	children       map[string]*grantNode
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

// grantIndent is the indent of the grant trees; grantAccessColumn is the 1-based column of
// the access token.
const (
	grantIndent       = "    "
	grantAccessColumn = 31
)

// grantTrees groups absolute, config-expanded grants into one tree per root without
// inspecting the filesystem. The first grant of a path wins.
func grantTrees(c report.Style, grants []grant, home string) []report.Node {
	displayHome := home
	for _, g := range grants {
		if pathutil.AtOrUnderClean(home, g.path) {
			displayHome = ""
			break
		}
	}

	roots := &grantNode{}
	for _, g := range grants {
		p := abbrevHome(g.path, displayHome)
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
		if n.access == "" {
			n.access, n.source = g.access, g.source
		}
	}
	var out []report.Node
	for _, root := range slices.Sorted(maps.Keys(roots.children)) {
		out = append(out, grantTree(c, root, roots.children[root], 0))
	}
	return out
}

// grantTree renders n at depth, padding a grant's name so its access token lines up.
func grantTree(c report.Style, label string, n *grantNode, depth int) report.Node {
	// A grant may also be an ancestor of another grant; collapsing past it would hide access.
	for n.access == "" && len(n.children) == 1 {
		for name, child := range n.children {
			label = strings.TrimSuffix(label, "/") + "/" + name
			n = child
		}
	}
	label = reportText(label)
	node := report.Node{Text: c.Dim + label + c.Reset}
	if n.access != "" {
		pad := max(grantAccessColumn-1-len(grantIndent)-4*depth-utf8.RuneCountInString(label), 1)
		node.Text = c.Bold + label + c.Reset + strings.Repeat(" ", pad) + n.access + "   " + c.Dim + n.source + c.Reset
	}
	for _, name := range slices.Sorted(maps.Keys(n.children)) {
		node.Children = append(node.Children, grantTree(c, name, n.children[name], depth+1))
	}
	return node
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

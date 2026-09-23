// Package report renders corral's human-facing terminal output on one shared grid.
package report

import (
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// The detail grid: a status glyph, a label in a 16-column field, and the value at
// ValueColumn (1-based). Section rules end at RuleStop.
const (
	ValueColumn = 21
	RuleStop    = 66
)

// Glyph is one mark of the fixed glyph set.
type Glyph int

const (
	None Glyph = iota
	Ready
	Attention
	Blocked
	On
	Off
	Fix
)

var glyphs = [...]struct{ unicode, ascii string }{
	None:      {" ", ""},
	Ready:     {"✓", "[ok]"},
	Attention: {"!", "[!]"},
	Blocked:   {"✗", "[x]"},
	On:        {"●", "[on]"},
	Off:       {"○", "[--]"},
	Fix:       {"→", "->"},
}

// asciiSlot is the status column width in the ASCII form. ASCII rows drop the indent so
// the value stays at ValueColumn.
const asciiSlot = 4

// Style holds the color codes and the character set for one output stream. When color is
// off every code is empty, so call sites wrap text unconditionally.
type Style struct {
	Reset, Bold, Dim, Green, Yellow, Red, Brand string
	ASCII                                       bool
}

// NewStyle returns a Style with color codes when color is true, and the plain-ASCII
// character set when ascii is true.
func NewStyle(color, ascii bool) Style {
	s := Style{ASCII: ascii}
	if color {
		s.Reset = "\x1b[0m"
		s.Bold = "\x1b[1m"
		s.Dim = "\x1b[2m"
		s.Green = "\x1b[32m"
		s.Yellow = "\x1b[33m"
		s.Red = "\x1b[31m"
		// corral's mark color #E2552B as a 24-bit truecolor SGR.
		s.Brand = "\x1b[38;2;226;85;43m"
	}
	return s
}

// StyleFor returns the Style for f. A pipe or file (as in tests, or when output is
// redirected) gets no color.
func StyleFor(f *os.File) Style {
	return resolve(IsTerminal(f))
}

// resolve returns the Style for a stream: color only on a terminal the environment does
// not disable, ASCII when the locale is not UTF-8.
func resolve(terminal bool) Style {
	return NewStyle(terminal && !colorDisabledByEnv(), !unicodeByEnv())
}

// IsTerminal reports whether f is an interactive terminal (false for a pipe, file, or closed
// handle, as in tests/CI/`claude -p`). Asks the tty driver via term.IsTerminal, not a
// char-device mode bit: /dev/null is a char device too, so a mode check would misread
// `corral run < /dev/null` as interactive.
func IsTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// colorDisabledByEnv reports whether NO_COLOR (https://no-color.org) is set or TERM is "dumb".
func colorDisabledByEnv() bool {
	return os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"
}

// unicodeByEnv reports whether the effective locale (the first of LC_ALL, LC_CTYPE, LANG
// that is set) is UTF-8. No locale at all keeps Unicode.
func unicodeByEnv() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			v = strings.ToLower(v)
			return strings.Contains(v, "utf-8") || strings.Contains(v, "utf8")
		}
	}
	return true
}

// Sep returns the separator between fields on one line.
func (s Style) Sep() string {
	if s.ASCII {
		return "|"
	}
	return "·"
}

// Glyph returns g in the stream's character set.
func (s Style) Glyph(g Glyph) string {
	if s.ASCII {
		return glyphs[g].ascii
	}
	return glyphs[g].unicode
}

func (s Style) glyphColor(g Glyph) string {
	switch g {
	case Ready, On:
		return s.Green
	case Attention:
		return s.Yellow
	case Blocked:
		return s.Red
	case Off:
		return s.Dim
	}
	return ""
}

// Row is one detail row. Reason, when set, is printed dimmed on the line below.
type Row struct {
	Glyph  Glyph
	Label  string
	Value  string
	Reason string
}

// slot returns the status column for g and its visible width.
func (s Style) slot(g Glyph) (string, int) {
	if s.ASCII {
		return fmt.Sprintf("%-*s ", asciiSlot, s.Glyph(g)), asciiSlot + 1
	}
	return "  " + s.glyphColor(g) + s.Glyph(g) + s.Reset + " ", 4
}

// Row writes r on the detail grid. A label longer than 14 characters, the most that fits
// beside the wider ASCII status column, keeps one space before the value and moves only its
// own value right.
func (s Style) Row(w io.Writer, r Row) {
	lead, n := s.slot(r.Glyph)
	pad := strings.Repeat(" ", max(ValueColumn-1-n-utf8.RuneCountInString(r.Label), 1))
	fmt.Fprintf(w, "%s%s%s%s%s%s\n", lead, s.Dim, r.Label, pad, s.Reset, r.Value)
	if r.Reason != "" {
		s.Cont(w, s.Dim+r.Reason+s.Reset)
	}
}

// Cont writes text on its own line at the value column, under the row above.
func (s Style) Cont(w io.Writer, text string) {
	fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", ValueColumn-1), text)
}

// Quote writes one line of quoted output at the value column behind a dim gutter.
func (s Style) Quote(w io.Writer, text string) {
	bar := "│"
	if s.ASCII {
		bar = "|"
	}
	s.Cont(w, s.Dim+bar+" "+s.Reset+text)
}

// Message writes g in the status column followed by free text.
func (s Style) Message(w io.Writer, g Glyph, text string) {
	lead, _ := s.slot(g)
	fmt.Fprintf(w, "%s%s\n", lead, text)
}

// markArt is the corral mark (assets/logo.svg): a full-block pen with an open gate on the right.
var markArt = []string{
	"████████████",
	"█          █",
	"█  ████  █",
	"█  ████  █",
	"█          █",
	"████████████",
}

// markWidth is the mark's column width; ragged open-gate rows are padded to it.
const markWidth = 12

// mark writes the corral mark with beside[i] next to row i. Rows without text skip the
// padding and gutter.
func (s Style) mark(w io.Writer, beside []string) {
	for i, art := range markArt {
		if s.ASCII {
			art = strings.ReplaceAll(art, "█", "#")
		}
		row := "  " + s.Brand + art + s.Reset
		if i < len(beside) && beside[i] != "" {
			row += strings.Repeat(" ", markWidth-utf8.RuneCountInString(art)) + "  " + beside[i]
		}
		fmt.Fprintln(w, row)
	}
}

// Header writes a blank line, the mark with the version line and an optional verdict
// beside its middle rows, a blank line, and the roll-up rows.
func (s Style) Header(w io.Writer, version, verdict string, rollup []Row) {
	fmt.Fprintln(w)
	beside := make([]string, len(markArt))
	beside[2], beside[3] = version, verdict
	s.mark(w, beside)
	fmt.Fprintln(w)
	for _, r := range rollup {
		s.Row(w, r)
	}
}

// Rule writes a section rule with title that ends at RuleStop.
func (s Style) Rule(w io.Writer, title string) {
	line := "─"
	if s.ASCII {
		line = "-"
	}
	lead := "  " + line + line + " "
	fill := max(RuleStop-utf8.RuneCountInString(lead)-utf8.RuneCountInString(title)-1, 0)
	fmt.Fprintf(w, "%s%s%s%s%s%s %s%s%s\n", s.Dim, lead, s.Reset, s.Bold, title, s.Reset, s.Dim, strings.Repeat(line, fill), s.Reset)
}

// Node is one tree entry. Text is written as given.
type Node struct {
	Text     string
	Children []Node
}

// Tree writes root at indent and its descendants under branch characters.
func (s Style) Tree(w io.Writer, indent string, root Node) {
	fmt.Fprintf(w, "%s%s\n", indent, root.Text)
	s.branches(w, indent, root.Children)
}

func (s Style) branches(w io.Writer, prefix string, nodes []Node) {
	mid, last, pipe := "├── ", "└── ", "│   "
	if s.ASCII {
		mid, last, pipe = "|-- ", "`-- ", "|   "
	}
	for i, n := range nodes {
		branch, next := mid, pipe
		if i == len(nodes)-1 {
			branch, next = last, "    "
		}
		fmt.Fprintf(w, "%s%s%s\n", prefix, branch, n.Text)
		s.branches(w, prefix+next, n.Children)
	}
}

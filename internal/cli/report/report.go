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

// The header roll-up sits beside the mark with its labels in a RollupLabelWidth column, so
// its values start at RollupValueColumn (1-based). LineMax is the target line width: data
// that corral cannot shorten, such as a single long path, may pass it.
const (
	RollupLabelWidth  = 12
	RollupValueColumn = markIndent + markWidth + markGap + RollupLabelWidth + 1
	LineMax           = 80
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
	Reset, Bold, Dim, Green, Yellow, Red, Blue, Brand string
	ASCII                                             bool
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
		s.Blue = "\x1b[34m"
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

// StyleOf returns the Style for w: StyleFor when w is a file, else no color and the
// locale's character set.
func StyleOf(w io.Writer) Style {
	if f, ok := w.(*os.File); ok {
		return StyleFor(f)
	}
	return resolve(false)
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

// asciiText maps the non-ASCII characters corral's own text uses to plain ASCII.
var asciiText = strings.NewReplacer(
	"—", "-",
	"→", "->",
	"…", "...",
	"·", "|",
	"─", "-",
	"│", "|",
	"├", "|",
	"└", "`",
)

// Text returns t in the stream's character set. The primitives apply it to all text they
// write, except the command of a Fix.
func (s Style) Text(t string) string {
	if s.ASCII {
		return asciiText.Replace(t)
	}
	return t
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
	case Ready:
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

// Status returns g in its status color.
func (s Style) Status(g Glyph) string {
	if color := s.glyphColor(g); color != "" {
		return color + s.Glyph(g) + s.Reset
	}
	return s.Glyph(g)
}

// slot returns the status column for g and its visible width.
func (s Style) slot(g Glyph) (string, int) {
	if s.ASCII {
		return fmt.Sprintf("%-*s ", asciiSlot, s.Glyph(g)), asciiSlot + 1
	}
	return "  " + s.Status(g) + " ", 4
}

// Row writes r on the detail grid. A label longer than 14 characters, the most that fits
// beside the wider ASCII status column, keeps one space before the value and moves only its
// own value right. An Off row is dimmed whole.
func (s Style) Row(w io.Writer, r Row) {
	lead, n := s.slot(r.Glyph)
	label := s.Text(r.Label)
	pad := strings.Repeat(" ", max(ValueColumn-1-n-utf8.RuneCountInString(label), 1))
	line := label + pad + s.Text(r.Value)
	if r.Glyph == Off {
		line = s.Dim + line + s.Reset
	}
	fmt.Fprintf(w, "%s%s\n", lead, line)
	if r.Reason != "" {
		s.Cont(w, s.Dim+r.Reason+s.Reset)
	}
}

// Cont writes text on its own line at the value column, under the row above.
func (s Style) Cont(w io.Writer, text string) {
	fmt.Fprintf(w, "%s%s\n", strings.Repeat(" ", ValueColumn-1), s.Text(text))
}

// Fix writes the fix glyph and cmd at the value column, under the row above. cmd is written
// verbatim in every character set, so a copied command stays exact.
func (s Style) Fix(w io.Writer, cmd string) {
	fmt.Fprintf(w, "%s%s %s\n", strings.Repeat(" ", ValueColumn-1), s.Glyph(Fix), cmd)
}

// Quote writes one line of quoted output at the value column behind a dim gutter.
func (s Style) Quote(w io.Writer, text string) {
	s.Cont(w, s.Dim+"│ "+s.Reset+text)
}

// Message writes g in the status column followed by free text. Each further line of text
// starts at the column of the first.
func (s Style) Message(w io.Writer, g Glyph, text string) {
	lead, n := s.slot(g)
	text = strings.ReplaceAll(s.Text(text), "\n", "\n"+strings.Repeat(" ", n))
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

// markWidth is the mark's column width; ragged open-gate rows are padded to it. The mark
// sits markIndent columns in, and text beside it follows a markGap gutter.
const (
	markWidth  = 12
	markIndent = 2
	markGap    = 2
)

// mark writes the corral mark with beside[i] next to row i, top-aligned. Text past the
// mark's last row keeps the same column.
func (s Style) mark(w io.Writer, beside []string) {
	for i := range max(len(markArt), len(beside)) {
		row := strings.Repeat(" ", markIndent+markWidth)
		if i < len(markArt) {
			art := markArt[i]
			if s.ASCII {
				art = strings.ReplaceAll(art, "█", "#")
			}
			row = strings.Repeat(" ", markIndent) + s.Brand + art + s.Reset + strings.Repeat(" ", markWidth-utf8.RuneCountInString(art))
		}
		if i < len(beside) && beside[i] != "" {
			row += strings.Repeat(" ", markGap) + beside[i]
		}
		fmt.Fprintln(w, strings.TrimRight(row, " "))
	}
}

// Header writes a blank line and the mark with text beside it: the version line, the
// verdict lines, a blank line, and the roll-up rows. Roll-up rows carry no glyph; a Reason
// is printed dimmed under its value.
func (s Style) Header(w io.Writer, version string, verdict []string, rollup []Row) {
	fmt.Fprintln(w)
	beside := append(append([]string{version}, verdict...), "")
	for _, r := range rollup {
		pad := strings.Repeat(" ", max(RollupLabelWidth-utf8.RuneCountInString(r.Label), 1))
		beside = append(beside, r.Label+pad+r.Value)
		if r.Reason != "" {
			beside = append(beside, strings.Repeat(" ", RollupLabelWidth)+s.Dim+r.Reason+s.Reset)
		}
	}
	for i, b := range beside {
		beside[i] = s.Text(b)
	}
	s.mark(w, beside)
}

// Rule writes a section rule: the title, then a line that ends at RuleStop.
func (s Style) Rule(w io.Writer, title string) {
	line := "─"
	if s.ASCII {
		line = "-"
	}
	title = s.Text(title)
	fill := max(RuleStop-utf8.RuneCountInString(title)-1, 0)
	fmt.Fprintf(w, "%s%s%s %s%s%s\n", s.Bold, title, s.Reset, s.Dim, strings.Repeat(line, fill), s.Reset)
}

// Node is one tree entry.
type Node struct {
	Text     string
	Children []Node
}

// Tree writes root at indent and its descendants under branch characters.
func (s Style) Tree(w io.Writer, indent string, root Node) {
	fmt.Fprintf(w, "%s%s\n", indent, s.Text(root.Text))
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
		fmt.Fprintf(w, "%s%s%s\n", prefix, branch, s.Text(n.Text))
		s.branches(w, prefix+next, n.Children)
	}
}

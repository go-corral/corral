package report

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

var sgr = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func visible(s string) string { return sgr.ReplaceAllString(s, "") }

// forms covers the styled Unicode form and the plain ASCII form.
var forms = []struct {
	name  string
	style Style
}{
	{"styled", NewStyle(true, false)},
	{"plain", NewStyle(false, false)},
	{"ascii", NewStyle(false, true)},
}

func TestGrid(t *testing.T) {
	if ValueColumn != 21 || RuleStop != 66 {
		t.Errorf("grid = %d/%d, want 21/66", ValueColumn, RuleStop)
	}
}

func TestGlyphs(t *testing.T) {
	for _, tt := range []struct {
		g              Glyph
		unicode, ascii string
	}{
		{Ready, "✓", "[ok]"},
		{Attention, "!", "[!]"},
		{Blocked, "✗", "[x]"},
		{On, "●", "[on]"},
		{Off, "○", "[--]"},
		{Fix, "→", "->"},
	} {
		if got := NewStyle(false, false).Glyph(tt.g); got != tt.unicode {
			t.Errorf("Glyph(%d) = %q, want %q", tt.g, got, tt.unicode)
		}
		if got := NewStyle(false, true).Glyph(tt.g); got != tt.ascii {
			t.Errorf("ASCII Glyph(%d) = %q, want %q", tt.g, got, tt.ascii)
		}
		if len(tt.ascii) > asciiSlot {
			t.Errorf("ASCII token %q is wider than the status column", tt.ascii)
		}
	}
}

func TestResolveColor(t *testing.T) {
	for _, tt := range []struct {
		name, term, noColor string
		terminal, want      bool
	}{
		{"color terminal", "xterm-256color", "", true, true},
		{"not a terminal", "xterm-256color", "", false, false},
		{"NO_COLOR", "xterm-256color", "1", true, false},
		{"dumb terminal", "dumb", "", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("TERM", tt.term)
			t.Setenv("NO_COLOR", tt.noColor)
			if got := resolve(tt.terminal).Reset != ""; got != tt.want {
				t.Errorf("color = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestResolveASCII(t *testing.T) {
	for _, tt := range []struct {
		name, lcAll, lcCtype, lang string
		want                       bool
	}{
		{"UTF-8 LANG", "", "", "en_US.UTF-8", false},
		{"utf8 spelling", "", "", "de_DE.utf8", false},
		{"C locale", "C", "", "en_US.UTF-8", true},
		{"LC_CTYPE before LANG", "", "POSIX", "en_US.UTF-8", true},
		{"LC_ALL wins", "en_US.UTF-8", "C", "C", false},
		{"no locale", "", "", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("LC_ALL", tt.lcAll)
			t.Setenv("LC_CTYPE", tt.lcCtype)
			t.Setenv("LANG", tt.lang)
			if got := resolve(false).ASCII; got != tt.want {
				t.Errorf("ASCII = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestStyleForNonTerminals(t *testing.T) {
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "")
	file, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	// /dev/null is a character device but not a terminal.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = devNull.Close() }()
	for _, f := range []*os.File{file, devNull} {
		if IsTerminal(f) {
			t.Errorf("IsTerminal(%s) = true, want false", f.Name())
		}
		if StyleFor(f).Reset != "" {
			t.Errorf("StyleFor(%s) has color, want none", f.Name())
		}
	}
}

func TestNewStyleWithoutColorHasNoCodes(t *testing.T) {
	var out strings.Builder
	s := NewStyle(false, false)
	s.Header(&out, "corral v1", []string{"verdict"}, []Row{{Label: "a", Value: "b", Reason: "c"}})
	s.Rule(&out, "Providers")
	if strings.Contains(out.String(), "\x1b") {
		t.Errorf("uncolored output contains ANSI escapes:\n%q", out.String())
	}
}

func TestRowAlignment(t *testing.T) {
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			var out strings.Builder
			for _, g := range []Glyph{None, Ready, Attention, Blocked, On, Off} {
				f.style.Row(&out, Row{Glyph: g, Label: "workdir", Value: "~/code/x", Reason: "why"})
			}
			lines := strings.Split(strings.TrimSuffix(visible(out.String()), "\n"), "\n")
			for i, ln := range lines {
				want, word := "~/code/x", "value"
				if i%2 == 1 {
					want, word = "why", "reason"
				}
				if col := utf8.RuneCountInString(ln[:strings.Index(ln, want)]) + 1; col != ValueColumn {
					t.Errorf("%s starts at column %d, want %d: %q", word, col, ValueColumn, ln)
				}
			}
		})
	}
}

func TestRowLabelBoundary(t *testing.T) {
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			for _, label := range []string{"fourteen-chars", "fifteen-chars-x", "sixteen-chars-xy"} {
				var out strings.Builder
				f.style.Row(&out, Row{Glyph: Ready, Label: label, Value: "VALUE"})
				ln := visible(out.String())
				if !strings.Contains(ln, label+" ") {
					t.Errorf("label %q has no space before its value: %q", label, ln)
				}
				col := utf8.RuneCountInString(ln[:strings.Index(ln, "VALUE")]) + 1
				if len(label) <= 14 && col != ValueColumn {
					t.Errorf("label %q: value at column %d, want %d: %q", label, col, ValueColumn, ln)
				}
			}
		})
	}
}

func TestSep(t *testing.T) {
	if got := NewStyle(false, false).Sep(); got != "·" {
		t.Errorf("Sep = %q, want ·", got)
	}
	if got := NewStyle(false, true).Sep(); got != "|" {
		t.Errorf("ASCII Sep = %q, want |", got)
	}
}

func TestRowStyledCodes(t *testing.T) {
	var out strings.Builder
	NewStyle(true, false).Row(&out, Row{Glyph: Attention, Label: "network", Value: "open", Reason: "why"})
	NewStyle(true, false).Row(&out, Row{Glyph: On, Label: "ssh", Value: "agent"})
	NewStyle(true, false).Row(&out, Row{Glyph: Off, Label: "docker", Value: "off"})
	want := "  \x1b[33m!\x1b[0m network         open\n" +
		"                    \x1b[2mwhy\x1b[0m\n" +
		"  ● ssh             agent\n" +
		"  \x1b[2m○\x1b[0m \x1b[2mdocker          off\x1b[0m\n"
	if out.String() != want {
		t.Errorf("row = %q, want %q", out.String(), want)
	}
}

func TestRowASCII(t *testing.T) {
	var out strings.Builder
	s := NewStyle(false, true)
	s.Row(&out, Row{Glyph: Ready, Label: "workdir", Value: "~/code/x"})
	s.Row(&out, Row{Glyph: Attention, Label: "network", Value: "open"})
	want := "[ok] workdir        ~/code/x\n" +
		"[!]  network        open\n"
	if out.String() != want {
		t.Errorf("ASCII rows = %q, want %q", out.String(), want)
	}
}

func TestContQuoteMessage(t *testing.T) {
	for _, tt := range []struct {
		style Style
		want  string
	}{
		{NewStyle(true, false), "                    ~/more\n" +
			"                    \x1b[2m│ \x1b[0mhook output\n" +
			"  \x1b[33m!\x1b[0m heads up\n"},
		{NewStyle(false, true), "                    ~/more\n" +
			"                    | hook output\n" +
			"[!]  heads up\n"},
	} {
		var out strings.Builder
		tt.style.Cont(&out, "~/more")
		tt.style.Quote(&out, "hook output")
		tt.style.Message(&out, Attention, "heads up")
		if out.String() != tt.want {
			t.Errorf("lines = %q, want %q", out.String(), tt.want)
		}
	}
}

func TestHeader(t *testing.T) {
	for _, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			var out strings.Builder
			f.style.Header(&out, "corral v1.2.3", []string{"1 failed"}, []Row{
				{Label: "project", Value: "~/src/x"},
				{Label: "home", Value: "private $HOME"},
				{Label: "masked", Value: "~/.ssh"},
				{Label: "policy", Value: "checked", Reason: "logged"},
				{Value: "note"},
			})
			lines := strings.Split(strings.TrimSuffix(visible(out.String()), "\n"), "\n")
			// Line 3 is the blank gap between the verdict and the roll-up: mark only.
			if len(lines) != 10 || lines[0] != "" || utf8.RuneCountInString(lines[3]) > markIndent+markWidth {
				t.Fatalf("header layout:\n%s", out.String())
			}
			// Text beside the mark and below it starts at one column.
			for i, text := range map[int]string{1: "corral v1.2.3", 2: "1 failed", 4: "project", 7: "policy"} {
				if col := utf8.RuneCountInString(lines[i][:strings.Index(lines[i], text)]); col != markIndent+markWidth+markGap {
					t.Errorf("%q starts at offset %d, want %d", text, col, markIndent+markWidth+markGap)
				}
			}
			for i, value := range map[int]string{4: "~/src/x", 5: "private $HOME", 6: "~/.ssh", 7: "checked", 8: "logged", 9: "note"} {
				if col := utf8.RuneCountInString(lines[i][:strings.Index(lines[i], value)]) + 1; col != RollupValueColumn {
					t.Errorf("roll-up value starts at column %d, want %d: %q", col, RollupValueColumn, lines[i])
				}
			}
		})
	}
}

func TestRollupGrid(t *testing.T) {
	if RollupLabelWidth != 12 || RollupValueColumn != 29 || LineMax != 80 {
		t.Errorf("roll-up grid = %d/%d/%d, want 12/29/80", RollupLabelWidth, RollupValueColumn, LineMax)
	}
}

func TestMarkASCII(t *testing.T) {
	var out strings.Builder
	NewStyle(false, true).mark(&out, nil)
	if strings.Contains(out.String(), "█") || !strings.HasPrefix(out.String(), "  ############\n") {
		t.Errorf("ASCII mark:\n%s", out.String())
	}
}

func TestRule(t *testing.T) {
	for _, tt := range []struct {
		style Style
		lead  string
		fill  string
	}{
		{NewStyle(true, false), "Providers ", "─"},
		{NewStyle(false, true), "Providers ", "-"},
	} {
		var out strings.Builder
		tt.style.Rule(&out, "Providers")
		got := strings.TrimSuffix(visible(out.String()), "\n")
		if !strings.HasPrefix(got, tt.lead) || strings.Trim(got[len(tt.lead):], tt.fill) != "" {
			t.Errorf("rule = %q", got)
		}
		if n := utf8.RuneCountInString(got); n != RuleStop {
			t.Errorf("rule ends at column %d, want %d", n, RuleStop)
		}
	}
}

func TestTree(t *testing.T) {
	root := Node{Text: "/srv/", Children: []Node{
		{Text: "projects", Children: []Node{{Text: "example"}}},
		{Text: "reference"},
	}}
	for _, tt := range []struct {
		style Style
		want  string
	}{
		{NewStyle(false, false), "  /srv/\n" +
			"  ├── projects\n" +
			"  │   └── example\n" +
			"  └── reference\n"},
		{NewStyle(false, true), "  /srv/\n" +
			"  |-- projects\n" +
			"  |   `-- example\n" +
			"  `-- reference\n"},
	} {
		var out strings.Builder
		tt.style.Tree(&out, "  ", root)
		if out.String() != tt.want {
			t.Errorf("tree = %q, want %q", out.String(), tt.want)
		}
	}
}

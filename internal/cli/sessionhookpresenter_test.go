package cli

import (
	"fmt"
	"strings"
	"testing"
)

// The presenter's label row must adopt the banner's exact geometry + label styling: "hooks" in
// the label column, "setup output from <event>.<key>" (the short key) in the value column —
// byte-identical to a bannerLine row — with the hook's output as a "│ "-guttered quoted block
// in the content column beneath it, closed by a blank line. The expected width is derived from
// the banner's own constants, never a magic number, so a banner geometry change moves the
// expectation with it.
func TestBannerSessionHookPresenterRegion(t *testing.T) {
	var b strings.Builder
	bannerSessionHookPresenter(&b, colors(false))("preStart", "10-hallo", "hi\nho\n", false)
	// Same grid as bannerLine: indent + left-justified label (bannerLabelW) + value, then each
	// output line guttered under the value column, then the closing blank line. colors(false)
	// zeroes the dim/reset codes.
	var want strings.Builder
	bannerLine(&want, colors(false), "hooks", []string{"setup output from preStart.10-hallo"})
	fmt.Fprintf(&want, "%s│ hi\n%s│ ho\n\n", bannerCont(), bannerCont())
	if b.String() != want.String() {
		t.Errorf("region = %q, want %q", b.String(), want.String())
	}
}

// The gutter bar renders dim while the hook's own text stays at normal intensity: dim is the
// banner's label color, so dim content would read as category rather than information — the
// glyph alone marks the block as relayed foreign output.
func TestBannerSessionHookPresenterDimsGutterNotText(t *testing.T) {
	var b strings.Builder
	c := colors(true)
	bannerSessionHookPresenter(&b, c)("preStart", "10-hallo", "hi\n", false)
	if want := bannerCont() + c.dim + "│ " + c.reset + "hi\n"; !strings.Contains(b.String(), want) {
		t.Errorf("want dim gutter + plain text %q, got %q", want, b.String())
	}
}

// A quiet hook renders nothing at all — the provider only calls the presenter when the hook
// wrote something, but rendering-empty inputs (a lone newline, trailing blanks only) must not
// leave a stray label row either.
func TestBannerSessionHookPresenterSkipsEmptyRenderings(t *testing.T) {
	for _, output := range []string{"", "\n", "\r\n", "  \n\t\n"} {
		var b strings.Builder
		bannerSessionHookPresenter(&b, colors(false))("preStart", "10-hallo", output, false)
		if b.String() != "" {
			t.Errorf("output %q must render nothing, got %q", output, b.String())
		}
	}
}

// Truncated output must say so — a guttered marker line closes the block, and it appears even
// when the renderable content is otherwise empty, so the cut is never silent.
func TestBannerSessionHookPresenterTruncationMarker(t *testing.T) {
	var b strings.Builder
	bannerSessionHookPresenter(&b, colors(false))("preStart", "10-hallo", "partial\n", true)
	if !strings.Contains(b.String(), "│ … output truncated") {
		t.Errorf("truncated output must carry the marker, got %q", b.String())
	}
	b.Reset()
	bannerSessionHookPresenter(&b, colors(false))("preStart", "10-hallo", "\n", true)
	if !strings.Contains(b.String(), "setup output from preStart.10-hallo") ||
		!strings.Contains(b.String(), "output truncated") {
		t.Errorf("a truncation with no renderable content still needs the region + marker, got %q", b.String())
	}
}

// terminalLines renders captured output the way a terminal would have displayed it: '\r'
// progress redraws collapse to their final frame, CRLF endings are plain line endings, trailing
// blank lines are stripped (interior ones survive), and ANSI escapes pass through untouched.
func TestTerminalLines(t *testing.T) {
	cases := []struct {
		name   string
		output string
		want   []string
	}{
		{"plain lines", "a\nb\n", []string{"a", "b"}},
		{"no trailing newline", "prompt-less tail", []string{"prompt-less tail"}},
		{"CR progress redraw keeps the final frame", "10%\r20%\rdone\n", []string{"done"}},
		{"CR redraw without newline", "10%\r20%", []string{"20%"}},
		{"CRLF is a plain line ending", "line\r\nnext\n", []string{"line", "next"}},
		{"trailing blank lines stripped", "a\n\n \n", []string{"a"}},
		{"interior blank line survives", "a\n\nb\n", []string{"a", "", "b"}},
		{"all whitespace yields nothing", " \n\t\n", nil},
		{"ANSI escapes pass through", "\x1b[31mred\x1b[0m\n", []string{"\x1b[31mred\x1b[0m"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := terminalLines(tc.output)
			if len(got) != len(tc.want) {
				t.Fatalf("lines = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("line %d = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

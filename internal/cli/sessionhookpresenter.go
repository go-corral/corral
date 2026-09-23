package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/providers/hooks"
)

// bannerSessionHookPresenter builds the session-hooks provider's preStart output presenter.
// Shows captured output as an attributed row with the output quoted below it.
func bannerSessionHookPresenter(w io.Writer, c report.Style) hooks.Presenter {
	return func(event, key, output string, truncated bool) {
		lines := terminalLines(output)
		if len(lines) == 0 && !truncated {
			return
		}
		c.Row(w, report.Row{Label: "hooks", Value: "setup output from " + event + "." + key})
		for _, ln := range lines {
			c.Quote(w, ln)
		}
		if truncated {
			c.Quote(w, c.Dim+"(output truncated)"+c.Reset)
		}
		fmt.Fprintln(w)
	}
}

// terminalLines renders captured hook output one string per screen line: split on '\n',
// keep only what follows the last '\r' (progress redraw), strip trailing blanks.
func terminalLines(output string) []string {
	lines := strings.Split(output, "\n")
	for i, ln := range lines {
		ln = strings.TrimSuffix(ln, "\r")
		if j := strings.LastIndexByte(ln, '\r'); j >= 0 {
			ln = ln[j+1:]
		}
		lines[i] = ln
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

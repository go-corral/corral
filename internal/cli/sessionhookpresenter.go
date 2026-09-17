package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/go-corral/corral/internal/providers/hooks"
)

// bannerSessionHookPresenter builds the session-hooks provider's preStart output presenter.
// Shows captured output via bannerLine with an attributed label and a dim gutter.
func bannerSessionHookPresenter(w io.Writer, c ansi) hooks.Presenter {
	return func(event, key, output string, truncated bool) {
		lines := terminalLines(output)
		if len(lines) == 0 && !truncated {
			return
		}
		bannerLine(w, c, "hooks", []string{"setup output from " + event + "." + key})
		for _, ln := range lines {
			fmt.Fprintf(w, "%s%s│ %s%s\n", bannerCont(), c.dim, c.reset, ln)
		}
		if truncated {
			fmt.Fprintf(w, "%s%s│ … output truncated%s\n", bannerCont(), c.dim, c.reset)
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

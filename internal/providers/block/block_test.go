package block

import (
	"strings"
	"testing"
)

// The AgentNote lists every entry with no cap, so the agent can check a path against it, and
// states that the user can remove an entry.
func TestBlockNoteListsEveryEntry(t *testing.T) {
	dirs := []string{"/d0", "/d1", "/d2", "/d3", "/d4"}
	files := []string{"/f0.env", "/f1.env", "/f2.env"}
	note := AgentNotes(dirs, files)[0]
	for _, p := range append(dirs, files...) {
		if !strings.Contains(note, "`"+p+"`") {
			t.Errorf("note must name %s: %q", p, note)
		}
	}
	if strings.Contains(note, "more") {
		t.Errorf("note must not summarize the list: %q", note)
	}
	if !strings.Contains(note, "the user can remove an entry") {
		t.Errorf("note must state that the user can remove an entry: %q", note)
	}
}

func TestBlockNoteEmpty(t *testing.T) {
	if got := AgentNotes(nil, nil); got != nil {
		t.Errorf("AgentNotes(nil, nil) = %q, want nil", got)
	}
}

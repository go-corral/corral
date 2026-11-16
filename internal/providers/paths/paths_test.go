package paths

import (
	"reflect"
	"testing"
)

// Paths are backtick-quoted: the note renders as markdown, and quoting keeps a
// space-containing path one token. An empty list adds no note.
func TestAgentNotes(t *testing.T) {
	rw := "extra writable host paths granted by config: `/srv/my work`"
	ro := "extra read-only host paths granted by config: `/etc/ssl`"
	for _, tc := range []struct {
		name   string
		rw, ro []string
		want   []string
	}{
		{"rw only", []string{"/srv/my work"}, nil, []string{rw}},
		{"ro only", nil, []string{"/etc/ssl"}, []string{ro}},
		{"both", []string{"/srv/my work"}, []string{"/etc/ssl"}, []string{rw, ro}},
	} {
		if got := AgentNotes(tc.rw, tc.ro); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: AgentNotes = %q, want %q", tc.name, got, tc.want)
		}
	}
}

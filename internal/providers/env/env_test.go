package env

import (
	"reflect"
	"testing"
)

// The note names the pinned variables in declaration order, never their values. With no
// set entries there is no note: routine forwarding is not worth per-turn context tokens.
func TestAgentNotes(t *testing.T) {
	got := AgentNotes([]Var{{Name: "FOO", Value: "bar"}, {Name: "API_URL", Value: "http://stub"}})
	want := []string{"config pins these env vars inside the sandbox (already set, do not export/override): FOO, API_URL"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AgentNotes = %q, want %q", got, want)
	}
	if got := AgentNotes(nil); got != nil {
		t.Errorf("no pinned vars → no note, got %q", got)
	}
}

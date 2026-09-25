package notes

import (
	"slices"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = expect success
	}{
		{"valid", Config{Agent: []string{"Keep notes short.", "Update the OpenSpec requirement."}}, ""},
		{"empty", Config{}, ""},
		{"whitespace-only entry", Config{Agent: []string{"   "}}, "providers.notes.agent"},
		{"embedded newline", Config{Agent: []string{"line one\nline two"}}, "providers.notes.agent"},
		{"embedded carriage return", Config{Agent: []string{"line one\rline two"}}, "providers.notes.agent"},
		{"embedded NUL", Config{Agent: []string{"line one\x00line two"}}, "providers.notes.agent"},
		// A YAML block scalar's trailing newline is trimmed away, leaving a valid entry.
		{"block scalar trailing newline", Config{Agent: []string{"A single line.\n"}}, ""},
		{"total size exceeded", Config{Agent: []string{strings.Repeat("a", maxAgentBytes+1)}}, "65536"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestLines(t *testing.T) {
	got := Config{Agent: []string{"  A  ", "B\n", "C"}}.Lines()
	if want := []string{"A", "B", "C"}; !slices.Equal(got, want) {
		t.Errorf("Lines() = %q, want %q", got, want)
	}
	// Equal-after-trim entries collapse to the first occurrence.
	got = Config{Agent: []string{"  A  ", "A", "B\n", "B"}}.Lines()
	if want := []string{"A", "B"}; !slices.Equal(got, want) {
		t.Errorf("Lines() = %q, want %q", got, want)
	}
}

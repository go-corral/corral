package aiignore

import (
	"strings"
	"testing"
)

// Validate owns the bare-filename source check. These exercise the method directly
// (config's Load test proves the wiring end-to-end).
func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = expect success
	}{
		{"valid", Config{Sources: []string{".aiignore", ".gitignore"}}, ""},
		{"path separator", Config{Sources: []string{"sub/dir/.gitignore"}}, "must be a bare filename (no path separators)"},
		{"backslash", Config{Sources: []string{"sub\\.gitignore"}}, "must be a bare filename (no path separators)"},
		{"dotdot", Config{Sources: []string{".."}}, "must be a bare filename (no path separators)"},
		{"empty", Config{Sources: []string{""}}, "must be a bare filename (no path separators)"},
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

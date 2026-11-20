package home

import (
	"strings"
	"testing"
)

// Validate owns the absolute-path check for a custom private-home Path and the inside-the-home
// check for Keep entries. These exercise the method directly (config's Load tests prove the
// wiring end-to-end).
func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = expect success
	}{
		{"empty", Config{Path: ""}, ""},
		{"absolute", Config{Path: "/cache/home"}, ""},
		{"relative", Config{Path: "cache/home"}, "providers.home.path: \"cache/home\" must be an absolute or ~-prefixed path"},
		{"keep relative", Config{Keep: []string{".local/share/uv", "work"}}, ""},
		{"keep tilde", Config{Keep: []string{"~/.local/bin"}}, ""},
		{"keep absolute", Config{Keep: []string{"/home/u/.local/bin"}}, "providers.home.keep: \"/home/u/.local/bin\""},
		{"keep escape", Config{Keep: []string{"../other"}}, "providers.home.keep: \"../other\""},
		{"keep bare tilde", Config{Keep: []string{"~"}}, "providers.home.keep: \"~\""},
		{"keep dot", Config{Keep: []string{"."}}, "providers.home.keep: \".\""},
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

// KeepRel normalizes entries to clean private-home-relative paths: the ~/ spelling and the bare
// one collapse to the same path, and a spelling with "." segments is cleaned.
func TestKeepRel(t *testing.T) {
	got := Config{Keep: []string{"~/.local/bin", "work/./sub/", ".local/bin"}}.KeepRel()
	want := []string{".local/bin", "work/sub", ".local/bin"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("KeepRel() = %q, want %q", got, want)
	}
}

func TestDir(t *testing.T) {
	for _, tc := range []struct {
		name        string
		cfg         Config
		wantDir     string
		wantEnabled bool
	}{
		{"disabled", Config{Path: "/custom/home"}, "", false},
		{"set path", Config{Enabled: true, Path: "/custom/home"}, "/custom/home", true},
		{"default path", Config{Enabled: true}, DefaultPath("/home/u", "/home/u/.claude"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, enabled := tc.cfg.Dir("/home/u", "/home/u/.claude")
			if dir != tc.wantDir || enabled != tc.wantEnabled {
				t.Errorf("Dir() = %q, %v, want %q, %v", dir, enabled, tc.wantDir, tc.wantEnabled)
			}
		})
	}
}

package sandbox

import (
	"strings"
	"testing"
)

// defaultKindFor is the single OS→backend mapping. corral supports exactly Linux
// (bwrap) and macOS (seatbelt); every other OS must fail early with an
// unsupported-OS error rather than guessing a backend.
func TestDefaultKindFor(t *testing.T) {
	cases := []struct {
		goos    string
		want    Kind
		wantErr bool
	}{
		{"linux", KindBwrap, false},
		{"darwin", KindSeatbelt, false},
		{"windows", "", true},
		{"freebsd", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := defaultKindFor(c.goos)
		if c.wantErr {
			if err == nil {
				t.Errorf("defaultKindFor(%q): want error, got kind %q", c.goos, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("defaultKindFor(%q): unexpected error %v", c.goos, err)
		}
		if got != c.want {
			t.Errorf("defaultKindFor(%q) = %q, want %q", c.goos, got, c.want)
		}
	}
	// The unsupported error must name the OS so it is actionable.
	if _, err := defaultKindFor("plan9"); err == nil || !strings.Contains(err.Error(), "plan9") {
		t.Errorf("unsupported-OS error should name the OS, got: %v", err)
	}
}

func TestParseKind(t *testing.T) {
	for _, in := range []string{"bwrap", "seatbelt"} {
		if got, err := ParseKind(in); err != nil || string(got) != in {
			t.Errorf("ParseKind(%q) = (%q, %v), want (%q, nil)", in, got, err, in)
		}
	}
	for _, in := range []string{"", "BWRAP", "nsjail", "landlock"} {
		if _, err := ParseKind(in); err == nil {
			t.Errorf("ParseKind(%q): want error", in)
		}
	}
}

// ResolveKind honors an explicit override on any OS (so --dry-run -backend bwrap
// works cross-platform) and otherwise falls back to the OS default.
func TestResolveKind(t *testing.T) {
	if got, err := ResolveKind("seatbelt"); err != nil || got != KindSeatbelt {
		t.Errorf("ResolveKind(\"seatbelt\") = (%q, %v), want seatbelt", got, err)
	}
	if got, err := ResolveKind("bwrap"); err != nil || got != KindBwrap {
		t.Errorf("ResolveKind(\"bwrap\") = (%q, %v), want bwrap", got, err)
	}
	if _, err := ResolveKind("bogus"); err == nil {
		t.Error("ResolveKind(\"bogus\"): want error")
	}
	// Empty override defers to the OS default; it must agree with DefaultKind.
	got, gerr := ResolveKind("")
	want, werr := DefaultKind()
	if got != want || (gerr == nil) != (werr == nil) {
		t.Errorf("ResolveKind(\"\") = (%q, %v); DefaultKind = (%q, %v) — must agree", got, gerr, want, werr)
	}
}

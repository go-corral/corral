package selfupdate

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		a, b       string
		want       int
		comparable bool
	}{
		{"1.2.3", "1.2.3", 0, true},
		{"v1.2.3", "1.2.3", 0, true}, // leading v is stripped on both sides
		{"1.2.4", "1.2.3", 1, true},
		{"1.2.3", "1.2.4", -1, true},
		{"1.3.0", "1.2.9", 1, true},
		{"2.0.0", "1.9.9", 1, true},
		{"1.2", "1.2.0", 0, true},   // missing patch defaults to 0
		{"1", "1.0.0", 0, true},     // missing minor+patch default to 0
		{"0.3.0", "0.3.0", 0, true}, // the current corral series
		// Build metadata does not affect precedence (SemVer §10).
		{"1.2.3+abc", "1.2.3+def", 0, true},
		// Pre-release ranks below the released version (SemVer §11).
		{"1.2.3-rc.1", "1.2.3", -1, true},
		{"1.2.3", "1.2.3-rc.1", 1, true},
		{"1.2.3-rc.2", "1.2.3-rc.1", 1, true},
		{"1.2.3-alpha", "1.2.3-beta", -1, true},
		{"1.2.3-1", "1.2.3-2", -1, true},  // numeric identifiers compare numerically
		{"1.2.3-1", "1.2.3-rc", -1, true}, // numeric ranks below alphanumeric
		{"1.2.3-a.1", "1.2.3-a", 1, true}, // a longer prerelease wins the tie
		// Incomparable: a dev/non-semver string on either side.
		{"dev", "1.2.3", 0, false},
		{"1.2.3", "dev", 0, false},
		{"", "1.2.3", 0, false},
		{"1.2.3.4", "1.2.3", 0, false}, // too many numeric fields
		{"x.y.z", "1.2.3", 0, false},
	}
	for _, tt := range tests {
		got, comparable := Compare(tt.a, tt.b)
		if got != tt.want || comparable != tt.comparable {
			t.Errorf("Compare(%q, %q) = (%d, %v), want (%d, %v)", tt.a, tt.b, got, comparable, tt.want, tt.comparable)
		}
	}
}

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"0.4.0", "0.3.0", true},
		{"0.3.0", "0.3.0", false},
		{"0.3.0", "0.4.0", false},
		{"1.0.0", "1.0.0-rc.1", true}, // a release supersedes its release candidate
		{"0.4.0", "dev", false},       // a dev build is never told it is outdated
		{"garbage", "0.3.0", false},
	}
	for _, tt := range tests {
		if got := IsNewer(tt.latest, tt.current); got != tt.want {
			t.Errorf("IsNewer(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
		}
	}
}

func TestStripV(t *testing.T) {
	for in, want := range map[string]string{
		"v1.2.3":  "1.2.3",
		"1.2.3":   "1.2.3",
		" v0.3.0": "0.3.0",  // surrounding space trimmed
		"vv1.0.0": "v1.0.0", // only one leading v is stripped
	} {
		if got := StripV(in); got != want {
			t.Errorf("StripV(%q) = %q, want %q", in, got, want)
		}
	}
}

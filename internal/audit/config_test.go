package audit

import (
	"testing"
	"time"
)

func TestParseExtendedDuration(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"1w", 7 * 24 * time.Hour, true},
		{"6mo", 6 * 30 * 24 * time.Hour, true},
		{"180d", 180 * 24 * time.Hour, true},
		{"1y", 365 * 24 * time.Hour, true},
		{"1.5y", time.Duration(1.5 * float64(365*24*time.Hour)), true},
		{"12h", 12 * time.Hour, true},
		{"5m", 5 * time.Minute, true}, // bare minutes, not months
		{"90m", 90 * time.Minute, true},
		{"1h30m", 90 * time.Minute, true},
		{"", 0, false},
		{"abc", 0, false},
		{"3 weeks", 0, false},
	}
	for _, c := range cases {
		got, err := parseExtendedDuration(c.in)
		if c.ok && err != nil {
			t.Errorf("parseExtendedDuration(%q) unexpected error: %v", c.in, err)
		}
		if !c.ok && err == nil {
			t.Errorf("parseExtendedDuration(%q) expected error, got %s", c.in, got)
		}
		if c.ok && got != c.want {
			t.Errorf("parseExtendedDuration(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// New resolves the string-config durations through the Effective* accessors into the
// Logger's fields, and an empty field falls back to its Default*.
func TestNewResolvesConfigDurations(t *testing.T) {
	l := New(Config{RotateInterval: "2h", Retention: "5h", Gzip: true}, "/tmp/audit.jsonl")
	if l.rotateInterval != 2*time.Hour {
		t.Errorf("rotateInterval = %s, want 2h", l.rotateInterval)
	}
	if l.retention != 5*time.Hour {
		t.Errorf("retention = %s, want 5h", l.retention)
	}
	if !l.gzip {
		t.Error("gzip = false, want true")
	}

	def := New(Config{}, "/tmp/audit.jsonl")
	if def.rotateInterval != DefaultAuditRotateInterval {
		t.Errorf("empty config rotateInterval = %s, want %s", def.rotateInterval, DefaultAuditRotateInterval)
	}
	if def.retention != DefaultAuditRetention {
		t.Errorf("empty config retention = %s, want %s", def.retention, DefaultAuditRetention)
	}
}

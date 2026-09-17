package audit

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Config configures the structured decision log. Logging is always on — only path and
// rotation are tunable. Rotation is time-based: the live log rolls to a timestamped backup
// once older than RotateInterval, and backups older than Retention are pruned at rotation time.
// RotateInterval and Retention accept Go durations plus the units d, w, mo (30d), y (365d).
type Config struct {
	Path           string `yaml:"path"`
	RotateInterval string `yaml:"rotateInterval"`
	Retention      string `yaml:"retention"`
	Gzip           bool   `yaml:"gzip"`
}

const (
	DefaultAuditRotateInterval = 7 * 24 * time.Hour      // 1w
	DefaultAuditRetention      = 6 * 30 * 24 * time.Hour // 6mo
)

func (a Config) EffectiveRotateInterval() time.Duration {
	if a.RotateInterval == "" {
		return DefaultAuditRotateInterval
	}
	if d, err := parseExtendedDuration(a.RotateInterval); err == nil && d > 0 {
		return d
	}
	return DefaultAuditRotateInterval
}

func (a Config) EffectiveRetention() time.Duration {
	if a.Retention == "" {
		return DefaultAuditRetention
	}
	if d, err := parseExtendedDuration(a.Retention); err == nil && d > 0 {
		return d
	}
	return DefaultAuditRetention
}

// Validate checks the audit rotation tunables: RotateInterval and Retention must each parse
// as a positive duration, and Retention must be >= RotateInterval.
func (a Config) Validate() error {
	var rotate, retain time.Duration
	if s := a.RotateInterval; s != "" {
		d, err := parseExtendedDuration(s)
		switch {
		case err != nil:
			return fmt.Errorf("policy.audit.rotateInterval: %q is not a valid duration (e.g. 1w, 12h, 30d): %w", s, err)
		case d <= 0:
			return fmt.Errorf("policy.audit.rotateInterval: %q must be positive", s)
		}
		rotate = d
	} else {
		rotate = DefaultAuditRotateInterval
	}
	if s := a.Retention; s != "" {
		d, err := parseExtendedDuration(s)
		switch {
		case err != nil:
			return fmt.Errorf("policy.audit.retention: %q is not a valid duration (e.g. 6mo, 26w, 180d): %w", s, err)
		case d <= 0:
			return fmt.Errorf("policy.audit.retention: %q must be positive", s)
		}
		retain = d
	} else {
		retain = DefaultAuditRetention
	}
	if retain < rotate {
		return fmt.Errorf("policy.audit.retention (%s) must be >= policy.audit.rotateInterval (%s); a shorter retention would prune a backup before the next rotation", retain, rotate)
	}
	return nil
}

// parseExtendedDuration extends time.ParseDuration (which tops out at hours) with the units
// d (24h), w (7d), mo (30d), y (365d). mo is matched before bare-minute "m", so "5m" stays
// 5 minutes. Rejects non-finite values and out-of-range magnitudes.
func parseExtendedDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	for _, u := range []struct {
		suffix string
		unit   time.Duration
	}{
		{"mo", 30 * 24 * time.Hour},
		{"w", 7 * 24 * time.Hour},
		{"d", 24 * time.Hour},
		{"y", 365 * 24 * time.Hour},
	} {
		if num, ok := strings.CutSuffix(s, u.suffix); ok {
			f, err := strconv.ParseFloat(strings.TrimSpace(num), 64)
			if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || math.Abs(f) > float64(math.MaxInt64)/float64(u.unit) {
				return 0, fmt.Errorf("invalid duration %q", s)
			}
			return time.Duration(f * float64(u.unit)), nil
		}
	}
	return time.ParseDuration(s)
}

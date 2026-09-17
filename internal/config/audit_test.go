package config

import (
	"testing"
	"time"

	"github.com/go-corral/corral/internal/audit"
)

// Unsupported audit keys must fail strict decoding rather than silently disabling logging.
func TestAuditEnabledKeyRejected(t *testing.T) {
	if _, _, err := loadFrom(t, "", "", "policy:\n  audit:\n    enabled: false\n", ""); err == nil {
		t.Fatal("expected error on the removed audit.enabled key (fail-closed), got nil")
	}
}

func TestAuditLegacySizeRotationKeysRejected(t *testing.T) {
	for _, key := range []string{"maxSizeMB: 5", "maxBackups: 5"} {
		if _, _, err := loadFrom(t, "", "", "policy:\n  audit:\n    "+key+"\n", ""); err == nil {
			t.Errorf("expected error on the removed audit key %q (fail-closed), got nil", key)
		}
	}
}

func TestAuditTunablesParse(t *testing.T) {
	cfg, _, err := loadFrom(t, "", "", "policy:\n  audit:\n    rotateInterval: 2w\n    retention: 1y\n    gzip: false\n", "")
	if err != nil {
		t.Fatalf("audit tunables must parse: %v", err)
	}
	if got := cfg.Policy.Audit.EffectiveRotateInterval(); got != 14*24*time.Hour {
		t.Errorf("rotateInterval 2w = %s, want 336h", got)
	}
	if got := cfg.Policy.Audit.EffectiveRetention(); got != 365*24*time.Hour {
		t.Errorf("retention 1y = %s, want 8760h", got)
	}
	if cfg.Policy.Audit.Gzip {
		t.Error("gzip: false must be applied")
	}
}

func TestAuditDefaults(t *testing.T) {
	cfg, _, err := loadFrom(t, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Policy.Audit.EffectiveRotateInterval(); got != audit.DefaultAuditRotateInterval {
		t.Errorf("default rotateInterval = %s, want %s (1w)", got, audit.DefaultAuditRotateInterval)
	}
	if got := cfg.Policy.Audit.EffectiveRetention(); got != audit.DefaultAuditRetention {
		t.Errorf("default retention = %s, want %s (6mo)", got, audit.DefaultAuditRetention)
	}
	if !cfg.Policy.Audit.Gzip {
		t.Error("gzip must default to true")
	}
}

func TestAuditValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{"bad rotate duration", "policy:\n  audit:\n    rotateInterval: nonsense\n", true},
		{"non-positive rotate", "policy:\n  audit:\n    rotateInterval: 0h\n", true},
		{"bad retention duration", "policy:\n  audit:\n    retention: 3 fortnights\n", true},
		{"retention shorter than interval", "policy:\n  audit:\n    rotateInterval: 2w\n    retention: 3d\n", true},
		{"retention equal to interval is allowed", "policy:\n  audit:\n    rotateInterval: 7d\n    retention: 1w\n", false},
		{"valid extended units", "policy:\n  audit:\n    rotateInterval: 12h\n    retention: 6mo\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := loadFrom(t, "", "", c.yaml, "")
			if c.wantErr && err == nil {
				t.Errorf("expected validation error, got nil")
			}
			if !c.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

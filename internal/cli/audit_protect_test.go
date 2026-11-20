package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers/home"
)

// effectiveAuditPath: configured policy.audit.path wins; empty falls back to the default
// under the state dir, keyed like the private home. Shared by the auditor and the self-protect
// gate so they agree.
func TestEffectiveAuditPath(t *testing.T) {
	cfg := &config.Config{}
	cfg.Policy.Audit.Path = "/custom/audit.jsonl"
	if p := effectiveAuditPath(cfg, "/state", "/cfgdir"); p != "/custom/audit.jsonl" {
		t.Errorf("configured path should win, got %q", p)
	}
	cfg.Policy.Audit.Path = ""
	key := strings.TrimPrefix(filepath.Base(home.DefaultPath("/home/u", "/cfgdir")), "home-")
	want := filepath.Join("/state", "corral", "audit", key, "corral-audit.jsonl")
	if p := effectiveAuditPath(cfg, "/state", "/cfgdir"); p != want {
		t.Errorf("default audit path = %q, want %q", p, want)
	}
	if p := legacyAuditPath("/cfgdir"); p != "/cfgdir/corral-audit.jsonl" {
		t.Errorf("legacy audit path = %q, want /cfgdir/corral-audit.jsonl", p)
	}
}

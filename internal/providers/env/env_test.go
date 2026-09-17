package env

import (
	"context"
	"github.com/go-corral/corral/internal/providers/spec"
	"reflect"
	"strings"
	"testing"
)

func TestEnvMintContributesEnvSetAndNote(t *testing.T) {
	cfg := Config{
		Passthrough: []string{"TERM", "LANG"},
		Set:         []Var{{Name: "FOO", Value: "bar"}, {Name: "API_URL", Value: "http://stub"}},
	}
	c, err := New(cfg).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.EnvSet) != 2 || c.EnvSet[0].Name != "FOO" {
		t.Errorf("EnvSet = %v", c.EnvSet)
	}
	if len(c.Env) != 0 || len(c.Mounts) != 0 || c.Cleanup != nil {
		t.Errorf("env provider must use the EnvSet channel only: %+v", c)
	}
	// No Status row: the env policy is static config — the counts live in validate's Grants.
	if len(c.Status) != 0 {
		t.Errorf("env must author no launch status row, got %v", c.Status)
	}
	note := strings.Join(c.AgentNotes, "\n")
	if !strings.Contains(note, "FOO, API_URL") {
		t.Errorf("note must name the pinned vars: %q", note)
	}
	if strings.Contains(note, "bar") || strings.Contains(note, "http://stub") {
		t.Errorf("note must NOT carry pinned values: %q", note)
	}
}

// With no set entries the provider contributes no model note (routine forwarding is not
// worth per-turn context tokens) — and, like every static built-in, no status row.
func TestEnvMintNoSetNoNote(t *testing.T) {
	c, err := New(Config{Passthrough: []string{"TERM"}}).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.AgentNotes) != 0 {
		t.Errorf("no pinned vars → no note, got %v", c.AgentNotes)
	}
	if len(c.Status) != 0 {
		t.Errorf("env must author no launch status row, got %v", c.Status)
	}
}

// Mint is pure: dryRun and a real launch return identical contributions.
func TestEnvMintDryRunIdentical(t *testing.T) {
	p := New(Config{Passthrough: []string{"TERM"}, Set: []Var{{Name: "A", Value: "b"}}})
	real, err := p.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	dry, err := p.Mint(context.Background(), spec.Session{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(real, dry) {
		t.Errorf("dry-run must equal real: %+v vs %+v", real, dry)
	}
}

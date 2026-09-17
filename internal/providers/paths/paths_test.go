package paths

import (
	"context"
	"github.com/go-corral/corral/internal/providers/spec"
	"reflect"
	"strings"
	"testing"
)

func TestPathsMintContributesGrantChannels(t *testing.T) {
	c, err := New([]string{"/srv/work"}, []string{"/etc/ssl"}).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.RWPaths) != 1 || c.RWPaths[0] != "/srv/work" || len(c.ROPaths) != 1 || c.ROPaths[0] != "/etc/ssl" {
		t.Errorf("grant channels wrong: %+v", c)
	}
	if len(c.Mounts) != 0 || len(c.BlockedDirs) != 0 || c.Cleanup != nil {
		t.Errorf("paths provider must use the grant channels only: %+v", c)
	}
	// Paths are backtick-quoted: the note renders as markdown, and quoting keeps a
	// space-containing path one token.
	if len(c.AgentNotes) != 2 || !strings.Contains(c.AgentNotes[0], "`/srv/work`") || !strings.Contains(c.AgentNotes[1], "`/etc/ssl`") {
		t.Errorf("AgentNotes should name the grants by kind, backtick-quoted: %v", c.AgentNotes)
	}
	// No Status row: the banner's access rows already show the grants; a static count in the
	// providers tree would only restate them.
	if len(c.Status) != 0 {
		t.Errorf("paths must author no launch status row, got %v", c.Status)
	}
}

// Mint is pure: dryRun and a real launch return identical contributions (the
// built-in contract that allows pre-gate resolution).
func TestPathsMintDryRunIdentical(t *testing.T) {
	p := New([]string{"/a"}, nil)
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
	// rw-only grants must not emit an empty ro note line.
	if len(real.AgentNotes) != 1 {
		t.Errorf("rw-only grant should yield exactly one note: %v", real.AgentNotes)
	}
}

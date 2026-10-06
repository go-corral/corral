package block

import (
	"context"
	"github.com/go-corral/corral/internal/providers/spec"
	"reflect"
	"strings"
	"testing"
)

func TestBlockMintContributesDenyChannels(t *testing.T) {
	c, err := New([]string{"/data/vault"}, []string{"/repo/.env"}).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.BlockedDirs) != 1 || c.BlockedDirs[0] != "/data/vault" {
		t.Errorf("BlockedDirs = %v", c.BlockedDirs)
	}
	if len(c.BlockedFiles) != 1 || c.BlockedFiles[0] != "/repo/.env" {
		t.Errorf("BlockedFiles = %v", c.BlockedFiles)
	}
	if len(c.Mounts) != 0 || len(c.Env) != 0 || c.Cleanup != nil {
		t.Errorf("block provider must contribute deny channels only: %+v", c)
	}
	// No Status row: the banner's "blocked" access row already names these exact paths.
	if len(c.Status) != 0 {
		t.Errorf("block must author no launch status row, got %v", c.Status)
	}
	// Paths are backtick-quoted: the note renders as markdown, and quoting keeps a
	// space-containing path one token.
	if len(c.AgentNotes) != 1 || !strings.Contains(c.AgentNotes[0], "`/data/vault`") || !strings.Contains(c.AgentNotes[0], "`/repo/.env`") {
		t.Errorf("AgentNotes should name the masked paths backtick-quoted: %v", c.AgentNotes)
	}
}

// Mint is pure: dryRun and a real launch return identical contributions, which is
// what allows the launcher to resolve built-ins before the confirmation gate.
func TestBlockMintDryRunIdentical(t *testing.T) {
	p := New([]string{"/d"}, []string{"/f.env"})
	real, err := p.Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	dry, err := p.Mint(context.Background(), spec.Session{}, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(real, dry) {
		t.Errorf("dry-run contribution must equal the real one: %+v vs %+v", real, dry)
	}
}

// The AgentNote lists every entry with no cap, so the agent can check a path against it, and
// states that the user can remove an entry.
func TestBlockNoteListsEveryEntry(t *testing.T) {
	dirs := []string{"/d0", "/d1", "/d2", "/d3", "/d4"}
	files := []string{"/f0.env", "/f1.env", "/f2.env"}
	c, err := New(dirs, files).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	note := c.AgentNotes[0]
	for _, p := range append(dirs, files...) {
		if !strings.Contains(note, "`"+p+"`") {
			t.Errorf("note must name %s: %q", p, note)
		}
	}
	if strings.Contains(note, "more") {
		t.Errorf("note must not summarize the list: %q", note)
	}
	if !strings.Contains(note, "the user can remove an entry") {
		t.Errorf("note must state that the user can remove an entry: %q", note)
	}
}

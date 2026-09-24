package notes

import (
	"context"
	"reflect"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
)

func TestMintContributesAgentNotes(t *testing.T) {
	lines := []string{"A", "B"}
	c, err := New(lines).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.AgentNotes, lines) {
		t.Errorf("AgentNotes = %v, want %v", c.AgentNotes, lines)
	}
}

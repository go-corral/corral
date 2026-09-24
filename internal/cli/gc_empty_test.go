package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/providers"
)

// With no providers implementing Reaper, gc returns 0 and reports 'no orphaned resources'.
func TestCmdGCNoReapers(t *testing.T) {
	var out strings.Builder
	// Empty reapers slice: no providers implement Reaper.
	code := runGC(context.Background(), []providers.Reaper{}, gcOptions{}, strings.NewReader(""), &out)
	if code != 0 {
		t.Errorf("cmdGC with no reapers: got exit code %d, want 0", code)
	}

	output := out.String()
	if output != "  ✓ no orphaned resources\n" {
		t.Errorf("cmdGC output must say 'no orphaned resources', got: %q", output)
	}
}

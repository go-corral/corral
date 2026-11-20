package cli

import (
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// KindBwrap maps to "linux".
func TestBaselineArchBwrapLinux(t *testing.T) {
	got := baselineArch(sandbox.KindBwrap)
	if got != "linux" {
		t.Errorf("baselineArch(KindBwrap) = %q, want 'linux'", got)
	}
}

// KindSeatbelt maps to "macos" (not "darwin").
func TestBaselineArchSeatbeltMacOS(t *testing.T) {
	got := baselineArch(sandbox.KindSeatbelt)
	if got != "macos" {
		t.Errorf("baselineArch(KindSeatbelt) = %q, want 'macos'", got)
	}
}

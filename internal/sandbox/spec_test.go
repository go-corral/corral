package sandbox

import (
	"slices"
	"testing"
)

func TestEnviron(t *testing.T) {
	spec := SandboxSpec{SetEnv: map[string]string{"Z": "1", "A": "2", "M": "3", "LD_PRELOAD": "/work/p.so", "DYLD_INSERT_LIBRARIES": "/work/i.dylib"}}
	if got, want := spec.Environ(), []string{"A=2", "M=3", "Z=1"}; !slices.Equal(got, want) {
		t.Errorf("Environ() = %q, want %q", got, want)
	}
	// A nil exec.Cmd.Env inherits the host environment.
	if got := (SandboxSpec{}).Environ(); got == nil {
		t.Error("Environ() with no SetEnv = nil, want a non-nil empty slice")
	}
}

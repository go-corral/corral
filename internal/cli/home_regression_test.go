package cli

import (
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// p above dir returns false.
func TestUnderDirAboveParent(t *testing.T) {
	cases := []struct {
		p    string
		dir  string
		want bool
		name string
	}{
		{"/home", "/home/u", false, "parent is not under child"},
		{"/home/u", "/home/u/proj", false, "grandparent is not under child"},
		{"/", "/home/u", false, "root is not under any dir"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := underDir(c.p, c.dir)
			if got != c.want {
				t.Errorf("underDir(%q, %q) = %v, want %v", c.p, c.dir, got, c.want)
			}
		})
	}
}

// A sibling p returns false.
func TestUnderDirParallelPaths(t *testing.T) {
	cases := []struct {
		p    string
		dir  string
		want bool
		name string
	}{
		{"/home/other", "/home/u", false, "sibling is not under"},
		{"/usr/local", "/usr/bin", false, "siblings under /usr"},
		{"/home", "/usr", false, "completely separate trees"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := underDir(c.p, c.dir)
			if got != c.want {
				t.Errorf("underDir(%q, %q) = %v, want %v", c.p, c.dir, got, c.want)
			}
		})
	}
}

// Valid under-cases: a child (nested or direct) is under; the dir itself is not (strict).
func TestUnderDirValid(t *testing.T) {
	cases := []struct {
		p    string
		dir  string
		want bool
		name string
	}{
		{"/home/u/.ssh", "/home/u", true, "child is under parent"},
		{"/home/u/proj/src/main.go", "/home/u", true, "nested child is under parent"},
		{"/home/u", "/home/u", false, "same path is not 'under' (strict)"},
		{"/home/u/.", "/home/u", false, "dot notation still same path"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := underDir(c.p, c.dir)
			if got != c.want {
				t.Errorf("underDir(%q, %q) = %v, want %v", c.p, c.dir, got, c.want)
			}
		})
	}
}

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

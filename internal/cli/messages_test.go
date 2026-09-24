package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
)

func TestFatalf(t *testing.T) {
	for _, tt := range []struct{ locale, want string }{
		{"C.UTF-8", "  ✗ load config: bad — yaml\n"},
		{"C", "[x]  load config: bad - yaml\n"},
	} {
		t.Setenv("LC_ALL", tt.locale)
		var out strings.Builder
		if code := fatalf(&out, "load config: %s", "bad — yaml"); code != 1 {
			t.Errorf("fatalf returned %d, want 1", code)
		}
		if out.String() != tt.want {
			t.Errorf("LC_ALL=%s: fatalf wrote %q, want %q", tt.locale, out.String(), tt.want)
		}
	}
}

func TestLineWriter(t *testing.T) {
	var out strings.Builder
	w := &lineWriter{w: &out, c: report.NewStyle(false, true), g: report.Attention}
	_, _ = w.Write([]byte("could not create the stub; files stay "))
	_, _ = w.Write([]byte("hook-enforced\nsecond — line\npartial"))
	want := "[!]  could not create the stub; files stay hook-enforced\n" +
		"[!]  second - line\n"
	if out.String() != want {
		t.Errorf("lines = %q, want %q", out.String(), want)
	}
	w.Flush()
	w.Flush()
	if want += "[!]  partial\n"; out.String() != want {
		t.Errorf("after Flush, lines = %q, want %q", out.String(), want)
	}
}

func TestTeardownReporter(t *testing.T) {
	var out strings.Builder
	rep := teardownReporter(&out, report.NewStyle(false, false))
	rep("kubernetes", nil, "unused")
	rep("gitlab", errors.New("revoke: 500"), "the token may still be live — revoke it")
	want := "  ✓ kubernetes      minted credentials torn down\n" +
		"  ✗ gitlab          teardown failed\n" +
		"                    the token may still be live — revoke it\n"
	if out.String() != want {
		t.Errorf("teardown rows = %q, want %q", out.String(), want)
	}
}

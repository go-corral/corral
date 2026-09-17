package cli

import (
	"strings"
	"testing"
)

// plain is the no-color ansi used in tests so assertions match raw text.
var plain = ansi{}

func TestUnifiedDiffIdenticalIsEmpty(t *testing.T) {
	if d := unifiedDiff([]byte("a\nb\n"), []byte("a\nb\n"), "x", "y", plain); d != "" {
		t.Fatalf("identical inputs should diff to empty, got:\n%s", d)
	}
	// Whole-empty inputs too.
	if d := unifiedDiff(nil, nil, "x", "y", plain); d != "" {
		t.Fatalf("empty inputs should diff to empty, got:\n%s", d)
	}
}

func TestUnifiedDiffAddition(t *testing.T) {
	before := []byte("line1\nline2\n")
	after := []byte("line1\nline2\nline3\n")
	d := unifiedDiff(before, after, "old", "new", plain)

	if !strings.Contains(d, "--- old\n") || !strings.Contains(d, "+++ new\n") {
		t.Errorf("missing header:\n%s", d)
	}
	if !strings.Contains(d, "+line3") {
		t.Errorf("addition not marked with +:\n%s", d)
	}
	// The context lines are unchanged (space-prefixed), not removed.
	if strings.Contains(d, "-line1") || strings.Contains(d, "-line2") {
		t.Errorf("unchanged lines must not be removals:\n%s", d)
	}
	if !strings.Contains(d, " line2") {
		t.Errorf("context line should be space-prefixed:\n%s", d)
	}
}

func TestUnifiedDiffReplacement(t *testing.T) {
	before := []byte("keep\nold value\ntail\n")
	after := []byte("keep\nnew value\ntail\n")
	d := unifiedDiff(before, after, "a", "b", plain)
	if !strings.Contains(d, "-old value") {
		t.Errorf("expected removal of old value:\n%s", d)
	}
	if !strings.Contains(d, "+new value") {
		t.Errorf("expected addition of new value:\n%s", d)
	}
	if !strings.Contains(d, " keep") || !strings.Contains(d, " tail") {
		t.Errorf("expected surrounding context:\n%s", d)
	}
	// Deletion precedes the addition at the same position (unified-diff convention).
	if strings.Index(d, "-old value") > strings.Index(d, "+new value") {
		t.Errorf("deletion should precede addition:\n%s", d)
	}
}

func TestUnifiedDiffHunkHeader(t *testing.T) {
	before := []byte("a\nb\nc\n")
	after := []byte("a\nB\nc\n")
	d := unifiedDiff(before, after, "a", "b", plain)
	// One changed line in the middle, ctx=3 → both sides span all three lines.
	if !strings.Contains(d, "@@ -1,3 +1,3 @@") {
		t.Errorf("expected hunk header @@ -1,3 +1,3 @@:\n%s", d)
	}
}

func TestUnifiedDiffCreateFromEmpty(t *testing.T) {
	d := unifiedDiff(nil, []byte("only\n"), "a", "b", plain)
	if !strings.Contains(d, "+only") {
		t.Errorf("expected added line:\n%s", d)
	}
	// The "from" side is empty → its hunk start is 0.
	if !strings.Contains(d, "@@ -0,0 +1,1 @@") {
		t.Errorf("expected @@ -0,0 +1,1 @@ for create-from-empty:\n%s", d)
	}
}

func TestUnifiedDiffColorWraps(t *testing.T) {
	c := colors(true)
	d := unifiedDiff([]byte("x\n"), []byte("y\n"), "a", "b", c)
	if !strings.Contains(d, c.green) || !strings.Contains(d, c.red) {
		t.Errorf("colorized diff should contain green+red codes:\n%q", d)
	}
}

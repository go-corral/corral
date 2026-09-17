package pathutil

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAtOrUnder covers inclusive, path-boundary-safe containment, including the root case.
func TestAtOrUnder(t *testing.T) {
	for _, tc := range []struct {
		p, dir string
		want   bool
	}{
		{"/a/b", "/a/b", true},                      // equal: at-or-under is inclusive
		{"/a/b/c", "/a/b", true},                    // properly nested
		{"/a/b/sub/dir", "/a/b", true},              // multi-level nesting
		{"/a/bx", "/a/b", false},                    // prefix match but not a path boundary
		{"/usr-local/bin", "/usr", false},           // prefix is not a path boundary
		{"/home/alice-admin", "/home/alice", false}, // prefix but not nested
		{"/home/alice/x", "/home/alice", true},      // properly nested
		{"/a", "/a/b", false},                       // parent of dir, not under it
		{"/anything", "/", true},                    // everything is under root
		{"/", "/", true},                            // root is under itself
		{"/usr/bin", "/", true},                     // nested under root
	} {
		if got := AtOrUnder(tc.p, tc.dir); got != tc.want {
			t.Errorf("AtOrUnder(%q, %q) = %v, want %v", tc.p, tc.dir, got, tc.want)
		}
	}
}

// TestAtOrUnderClean covers normalization of both operands without weakening path-boundary checks.
func TestAtOrUnderClean(t *testing.T) {
	for _, tc := range []struct {
		p, dir string
		want   bool
	}{
		{"/a/b/", "/a/b", true},         // trailing separator on p
		{"/a/b", "/a/b/", true},         // trailing separator on dir (locks dir-cleaning)
		{"/a/x/../b/c", "/a/b", true},   // ".." in p must clean to /a/b/c (locks p-cleaning)
		{"/a/b/../bx/y", "/a/b", false}, // cleaning preserves the path boundary
		{"/a/b/./c", "/a/b", true},      // un-cleaned "." segment in p
		{"/x/..", "/", true},            // p cleans to "/", which is under root via the Clean path
		{"/foo", "/.", true},            // dir cleans to "/": drives the root branch through Clean
		{"/usr-local", "/usr", false},   // still prefix-safe after cleaning
	} {
		if got := AtOrUnderClean(tc.p, tc.dir); got != tc.want {
			t.Errorf("AtOrUnderClean(%q, %q) = %v, want %v", tc.p, tc.dir, got, tc.want)
		}
	}
}

// TestResolve covers full symlink resolution and the cleaned lexical fallback for missing paths.
// The fallback keeps optional mount paths subject to lexical containment checks.
func TestResolve(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	// dir itself may be a symlink (macOS /var/folders), so compare against its resolved form.
	wantReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}

	abs := filepath.Join(dir, "abs")   // absolute target
	rel := filepath.Join(dir, "rel")   // relative target
	chain := filepath.Join(dir, "two") // link -> link -> real
	for _, l := range []struct{ path, target string }{
		{abs, real}, {rel, "real"}, {chain, "abs"},
	} {
		if err := os.Symlink(l.target, l.path); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct{ name, in, want string }{
		{"absolute symlink", abs, wantReal},
		{"relative symlink", rel, wantReal},
		{"symlink chain", chain, wantReal},
		{"real dir", real, wantReal},
		{"missing path", filepath.Join(dir, "nope"), filepath.Join(dir, "nope")},
		{"uncleaned missing path", filepath.Join(dir, "a", "..", "nope"), filepath.Join(dir, "nope")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Resolve(tc.in); got != tc.want {
				t.Errorf("Resolve(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestResolveDanglingSymlinkFallsBack locks that a dangling link degrades to the lexical
// path rather than to "" — returning empty would make a containment check compare against
// nothing and silently pass.
func TestResolveDanglingSymlinkFallsBack(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "dangling")
	if err := os.Symlink(filepath.Join(dir, "gone"), link); err != nil {
		t.Fatal(err)
	}
	if got := Resolve(link); got != link {
		t.Errorf("Resolve(dangling) = %q, want the lexical path %q", got, link)
	}
}

// TestUnder covers exclusive containment, including that $HOME is not under itself.
func TestUnder(t *testing.T) {
	for _, tc := range []struct {
		p, dir string
		want   bool
	}{
		{"/a/b", "/a/b", false},             // equal: strictly-under is exclusive
		{"/a/b/c", "/a/b", true},            // properly nested
		{"/a/bx", "/a/b", false},            // prefix match but not a path boundary
		{"/usr-local/bin", "/usr", false},   // substring false-positive guard
		{"/Users/u/proj", "/Users/u", true}, // seatbelt's $HOME-internal case
		{"/Users/u", "/Users/u", false},     // equal is not under
		{"/Users/other", "/Users/u", false}, // sibling, not under
		{"/foo", "/", true},                 // under root
		{"/", "/", false},                   // root is not strictly under itself
	} {
		if got := Under(tc.p, tc.dir); got != tc.want {
			t.Errorf("Under(%q, %q) = %v, want %v", tc.p, tc.dir, got, tc.want)
		}
	}
}

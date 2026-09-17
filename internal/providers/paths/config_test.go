package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Validate owns the absolute-path and always-blocked overlap checks; config passes the
// ~-expanded, cleaned floor. Overlap is prefix-safe (a sibling like ~/.ssh-backup is not
// under ~/.ssh). These exercise the method directly (config's Load tests prove the wiring).
func TestValidate(t *testing.T) {
	floor := []string{"/home/u/.ssh", "/home/u/.gnupg", "/home/u/.aws"}

	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = expect success
	}{
		{"valid", Config{RW: []string{"/srv/work"}, RO: []string{"/etc/ssl"}}, ""},
		{"relative rw", Config{RW: []string{"rel/path"}}, "providers.paths.rw: \"rel/path\" must be an absolute or ~-prefixed path"},
		{"relative ro", Config{RO: []string{"rel/path"}}, "providers.paths.ro: \"rel/path\" must be an absolute or ~-prefixed path"},
		{"rw overlaps floor", Config{RW: []string{"/home/u/.ssh/keys"}}, "overlaps the always-blocked path"},
		{"ro at floor", Config{RO: []string{"/home/u/.aws"}}, "overlaps the always-blocked path"},
		{"prefix-sibling allowed", Config{RW: []string{"/home/u/.ssh-backup"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate(floor)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

// Warnings flags a read-only entry that a read-write entry covers, since read-write wins where
// the two overlap. The reverse direction is the supported case and must stay quiet, as must a
// prefix sibling.
func TestWarnings(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want int
	}{
		{"ro under rw", Config{RW: []string{"/srv/work"}, RO: []string{"/srv/work/vendor"}}, 1},
		{"ro equals rw", Config{RW: []string{"/srv/work"}, RO: []string{"/srv/work"}}, 1},
		{"one warning per ro entry", Config{RW: []string{"/srv", "/srv/work"}, RO: []string{"/srv/work/vendor"}}, 1},
		{"rw under ro is the supported case", Config{RW: []string{"/srv/work/build"}, RO: []string{"/srv/work"}}, 0},
		{"prefix sibling", Config{RW: []string{"/srv/work"}, RO: []string{"/srv/work-ro"}}, 0},
		{"no grants", Config{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.Warnings()
			if len(got) != tc.want {
				t.Fatalf("Warnings() = %q, want %d warning(s)", got, tc.want)
			}
			for _, w := range got {
				if !strings.Contains(w, "has no effect") {
					t.Errorf("Warnings() = %q, want the no-effect wording", w)
				}
			}
		})
	}
}

// TestValidateResolved locks the symlink-resolving half of the floor guard, which needs a
// real filesystem (Validate's lexical check cannot see any of these). The two directions
// that must be refused: a grant resolving into the floor (the bypass — bwrap mounts the
// resolved secret dir at the link's unmasked name), and a grant resolving to an ancestor
// of the floor (the floor mask sits outside the bind destination's name, so it cannot
// cover it). The case that must stay legal is the one the mask handles: a plain,
// non-symlinked ancestor grant, including when the floor dir is itself a symlink.
func TestValidateResolved(t *testing.T) {
	// On macOS t.TempDir() sits under /var, a firmlink to /private/var; resolving the base keeps
	// the plain-grant cases from tripping the symlink-resolving refusal. Linux: no-op.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sshDir := filepath.Join(home, ".ssh")
	mustMkdir(t, sshDir)
	mustMkdir(t, filepath.Join(home, "work"))
	// A dotfiles-managed floor dir: ~/.gnupg -> ~/dotfiles/gnupg (stow/chezmoi pattern).
	mustMkdir(t, filepath.Join(home, "dotfiles", "gnupg"))
	mustSymlink(t, filepath.Join(home, "dotfiles", "gnupg"), filepath.Join(home, ".gnupg"))

	mustMkdir(t, filepath.Join(sshDir, "sub"))
	mustSymlink(t, sshDir, filepath.Join(home, "abslink")) // -> ~/.ssh
	mustSymlink(t, ".ssh", filepath.Join(home, "rellink")) // -> ~/.ssh (relative)
	mustSymlink(t, filepath.Join(sshDir, "sub"), filepath.Join(home, "sublink"))
	mustSymlink(t, home, filepath.Join(home, "homelink"))                  // -> ~ (contains the floor)
	mustSymlink(t, filepath.Join(home, "work"), filepath.Join(home, "ok")) // -> ~/work (unrelated)
	mustSymlink(t, filepath.Join(home, "dotfiles"), filepath.Join(home, "dotlink"))

	floor := []string{sshDir, filepath.Join(home, ".gnupg"), filepath.Join(home, ".aws")}
	p := func(rel string) string { return filepath.Join(home, rel) }

	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = expect success
	}{
		// The finding: a grant that is only at/under the floor after resolution.
		{"rw symlink at floor (absolute target)", Config{RW: []string{p("abslink")}}, "resolves to the always-blocked path"},
		{"ro symlink at floor (relative target)", Config{RO: []string{p("rellink")}}, "resolves to the always-blocked path"},
		{"rw symlink under floor", Config{RW: []string{p("sublink")}}, "is inside the always-blocked path"},
		// A symlink to an ancestor: the mask cannot reach inside the link's name.
		{"rw symlink to a floor ancestor", Config{RW: []string{p("homelink")}}, "contains the always-blocked path"},
		// Same, via a symlinked floor dir: the grant reaches ~/dotfiles, which holds the
		// real ~/.gnupg. Only refused because the grant is a symlink.
		{"rw symlink to a symlinked floor's parent", Config{RW: []string{p("dotlink")}}, "contains the always-blocked path"},
		// Must stay legal: the mask covers these (AlwaysBlockedMaskPaths masks the resolved path).
		{"plain ancestor grant", Config{RW: []string{home}}, ""},
		{"plain grant of a symlinked floor's parent", Config{RW: []string{p("dotfiles")}}, ""},
		{"symlink to an unrelated dir", Config{RW: []string{p("ok")}}, ""},
		{"plain unrelated grant", Config{RO: []string{p("work")}}, ""},
		// Grants compile to optional mounts, so a not-yet-existing path is legal and must
		// fall back to the lexical check rather than being refused.
		{"missing grant", Config{RW: []string{p("not-created-yet")}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.ValidateResolved(floor)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("ValidateResolved() = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("ValidateResolved() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

func mustSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

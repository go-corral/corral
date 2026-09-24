package cli

import (
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/cli/report"
)

// renderGrants prints the grant trees of paths, each granted ro, the way validate does.
func renderGrants(c report.Style, paths []string) string {
	var grants []grant
	for _, p := range paths {
		grants = append(grants, grant{p, "ro", "x"})
	}
	var b strings.Builder
	for _, root := range grantTrees(c, grants, "/home/user") {
		c.Tree(&b, grantIndent, root)
	}
	return b.String()
}

func TestGrantTrees(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  string
	}{
		{name: "empty"},
		{
			name:  "single path",
			paths: []string{"/srv/reference/handbook"},
			want:  "    /srv/reference/handbook   ro   x\n",
		},
		{
			name:  "shared prefixes and spaces",
			paths: []string{"/srv/wiki/Services", "/srv/code/repo", "/srv/wiki/Acceptable Use"},
			want: "    /srv\n" +
				"    ├── code/repo             ro   x\n" +
				"    └── wiki\n" +
				"        ├── Acceptable Use    ro   x\n" +
				"        └── Services          ro   x\n",
		},
		{
			name:  "ancestor grant is not collapsed",
			paths: []string{"/srv/projects/example/src", "/srv/projects", "/srv/reference/handbook"},
			want: "    /srv\n" +
				"    ├── projects              ro   x\n" +
				"    │   └── example/src       ro   x\n" +
				"    └── reference/handbook    ro   x\n",
		},
		{
			name:  "whole components only",
			paths: []string{"/srv2/project", "/srv/project"},
			want:  "    /\n    ├── srv/project           ro   x\n    └── srv2/project          ro   x\n",
		},
		{
			name:  "home abbreviation and unrelated root",
			paths: []string{"/home/user/docs", "/opt/reference", "/home/user/.agents"},
			want:  "    /opt/reference            ro   x\n    ~\n    ├── .agents               ro   x\n    └── docs                  ro   x\n",
		},
		{
			name:  "home grant keeps the containment visible",
			paths: []string{"/home/user", "/home/user/docs"},
			want:  "    /home/user                ro   x\n    └── docs                  ro   x\n",
		},
		{
			name:  "home ancestor keeps the containment visible",
			paths: []string{"/home", "/home/user/docs"},
			want:  "    /home                     ro   x\n    └── user/docs             ro   x\n",
		},
		{
			name:  "root grant",
			paths: []string{"/", "/srv/code"},
			want:  "    /                         ro   x\n    └── srv/code              ro   x\n",
		},
		{
			name:  "duplicates",
			paths: []string{"/srv/code", "/srv/code"},
			want:  "    /srv/code                 ro   x\n",
		},
		{
			name:  "escape row and marker spoofing",
			paths: []string{"/srv/a\nWarnings\x1b[0m", "/srv/b [grant]", "/srv/c\\n", "/srv/d\u202e"},
			want: "    /srv\n" +
				"    ├── \"a\\nWarnings\\x1b[0m\"  ro   x\n" +
				"    ├── \"b [grant]\"           ro   x\n" +
				"    ├── \"c\\\\n\"                ro   x\n" +
				"    └── \"d\\u202e\"             ro   x\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := slices.Clone(tt.paths)
			if got := renderGrants(report.Style{}, tt.paths); got != tt.want {
				t.Errorf("got:\n%s\nwant:\n%s", got, tt.want)
			}
			if !slices.Equal(tt.paths, original) {
				t.Fatal("renderer mutated input")
			}
			slices.Reverse(original)
			if got := renderGrants(report.Style{}, original); got != tt.want {
				t.Errorf("output depends on input order:\n%s", got)
			}
		})
	}
}

// The tree uses the stream's branch characters, and every access token starts at
// grantAccessColumn unless the name is too long, which keeps one space. An rw grant wins over
// an ro grant on the same path.
func TestGrantTreeBranchesAndColumn(t *testing.T) {
	grants := []grant{
		{"/home/u/src/corral", "rw", "project"},
		{"/home/u/work/cache", "rw", "providers.paths.rw"},
		{"/home/u/work/a-directory-name-past-the-column", "rw", "providers.paths.rw"},
		{"/home/u/src/corral", "ro", "providers.paths.ro"},
		{"/usr/share/doc", "ro", "providers.paths.ro"},
	}
	for _, tt := range []struct {
		ascii bool
		want  string
	}{
		{false, `    /usr/share/doc            ro   providers.paths.ro
    ~
    ├── src/corral            rw   project
    └── work
        ├── a-directory-name-past-the-column rw   providers.paths.rw
        └── cache             rw   providers.paths.rw
`},
		{true, `    /usr/share/doc            ro   providers.paths.ro
    ~
    |-- src/corral            rw   project
    ` + "`" + `-- work
        |-- a-directory-name-past-the-column rw   providers.paths.rw
        ` + "`" + `-- cache             rw   providers.paths.rw
`},
	} {
		c := report.NewStyle(false, tt.ascii)
		var b strings.Builder
		for _, root := range grantTrees(c, grants, "/home/u") {
			c.Tree(&b, grantIndent, root)
		}
		if b.String() != tt.want {
			t.Errorf("ascii=%t: tree =\n%s\nwant\n%s", tt.ascii, b.String(), tt.want)
		}
		for _, ln := range strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n") {
			i := strings.Index(ln, " r")
			if i < 0 || strings.Contains(ln, "past-the-column") {
				continue
			}
			if col := utf8.RuneCountInString(ln[:i]) + 2; col != grantAccessColumn {
				t.Errorf("ascii=%t: access token at column %d, want %d: %q", tt.ascii, col, grantAccessColumn, ln)
			}
		}
	}
}

// Grant names are bold and intermediate directories dim; control characters stay quoted.
func TestGrantTreeStyled(t *testing.T) {
	c := report.NewStyle(true, false)
	got := renderGrants(c, []string{"/srv/projects", "/srv/projects/example", "/srv/reference/a\x1b[22m"})
	want := "    \x1b[2m/srv\x1b[0m\n" +
		"    ├── \x1b[1mprojects\x1b[0m              ro   \x1b[2mx\x1b[0m\n" +
		"    │   └── \x1b[1mexample\x1b[0m           ro   \x1b[2mx\x1b[0m\n" +
		"    └── \x1b[1m\"reference/a\\x1b[22m\"\x1b[0m ro   \x1b[2mx\x1b[0m\n"
	if got != want {
		t.Errorf("styled tree = %q, want %q", got, want)
	}
}

func TestReportText(t *testing.T) {
	for _, tt := range []struct{ text, want string }{
		{"Acceptable Use", "Acceptable Use"},
		{"日本語", "日本語"},
		{"tab\tname", `"tab\tname"`},
		{"invalid\xff", `"invalid\xff"`},
		{" leading", `" leading"`},
		{"trailing ", `"trailing "`},
		{"quote\"name", `"quote\"name"`},
	} {
		if got := reportText(tt.text); got != tt.want {
			t.Errorf("reportText(%q) = %q, want %q", tt.text, got, tt.want)
		}
	}
}

func TestReportProfileName(t *testing.T) {
	for _, tt := range []struct{ name, want string }{
		{"ordinary", "ordinary"},
		{"none", `"none"`},
		{"", `""`},
		{"a, b", `"a, b"`},
		{" leading", `" leading"`},
	} {
		if got := reportProfileName(tt.name); got != tt.want {
			t.Errorf("reportProfileName(%q) = %q, want %q", tt.name, got, tt.want)
		}
	}
}

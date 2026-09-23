package cli

import (
	"slices"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
)

func TestWritePathTree(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  string
		count int
	}{
		{name: "empty"},
		{
			name:  "single path",
			paths: []string{"/srv/reference/handbook"},
			want:  "  /srv/reference/handbook  [grant]\n",
			count: 1,
		},
		{
			name:  "shared prefixes and spaces",
			paths: []string{"/srv/wiki/Services", "/srv/code/repo", "/srv/wiki/Acceptable Use"},
			want: "  /srv/\n" +
				"  ├── code/repo  [grant]\n" +
				"  └── wiki/\n" +
				"      ├── Acceptable Use  [grant]\n" +
				"      └── Services  [grant]\n",
			count: 3,
		},
		{
			name:  "ancestor grant is not collapsed",
			paths: []string{"/srv/projects/example/src", "/srv/projects", "/srv/reference/handbook"},
			want: "  /srv/\n" +
				"  ├── projects  [grant]\n" +
				"  │   └── example/src  [grant]\n" +
				"  └── reference/handbook  [grant]\n",
			count: 3,
		},
		{
			name:  "whole components only",
			paths: []string{"/srv2/project", "/srv/project"},
			want:  "  /\n  ├── srv/project  [grant]\n  └── srv2/project  [grant]\n",
			count: 2,
		},
		{
			name:  "home abbreviation and unrelated root",
			paths: []string{"/home/user/docs", "/opt/reference", "/home/user/.agents"},
			want:  "  /opt/reference  [grant]\n  ~/\n  ├── .agents  [grant]\n  └── docs  [grant]\n",
			count: 3,
		},
		{
			name:  "home grant keeps the containment visible",
			paths: []string{"/home/user", "/home/user/docs"},
			want:  "  /home/user  [grant]\n  └── docs  [grant]\n",
			count: 2,
		},
		{
			name:  "home ancestor keeps the containment visible",
			paths: []string{"/home", "/home/user/docs"},
			want:  "  /home  [grant]\n  └── user/docs  [grant]\n",
			count: 2,
		},
		{
			name:  "root grant",
			paths: []string{"/", "/srv/code"},
			want:  "  /  [grant]\n  └── srv/code  [grant]\n",
			count: 2,
		},
		{
			name:  "duplicates",
			paths: []string{"/srv/code", "/srv/code"},
			want:  "  /srv/code  [grant]\n",
			count: 1,
		},
		{
			name:  "escape row and marker spoofing",
			paths: []string{"/srv/a\nWarnings\x1b[0m", "/srv/b [grant]", "/srv/c\\n", "/srv/d\u202e"},
			want: "  /srv/\n" +
				"  ├── \"a\\nWarnings\\x1b[0m\"  [grant]\n" +
				"  ├── \"b [grant]\"  [grant]\n" +
				"  ├── \"c\\\\n\"  [grant]\n" +
				"  └── \"d\\u202e\"  [grant]\n",
			count: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := slices.Clone(tt.paths)
			var out strings.Builder
			count := writePathTree(&out, report.Style{}, tt.paths, "/home/user", "  ")
			if out.String() != tt.want || count != tt.count {
				t.Errorf("got (%d grants):\n%s\nwant (%d grants):\n%s", count, out.String(), tt.count, tt.want)
			}
			if !slices.Equal(tt.paths, original) {
				t.Fatal("renderer mutated input")
			}
			slices.Reverse(original)
			out.Reset()
			writePathTree(&out, report.Style{}, original, "/home/user", "  ")
			if out.String() != tt.want {
				t.Errorf("output depends on input order:\n%s", out.String())
			}
		})
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

package cli

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/block"
	"github.com/go-corral/corral/internal/providers/paths"
)

func TestSessionWarnings(t *testing.T) {
	// The caller supplies the resolved backend's read-only baseline targets; /usr is a
	// stable read-only system path, so the shadow check uses it as the fixture.
	roTargets := []string{"/usr"}

	// docker enabled + a paths.rw grant that covers a baseline read-only path (/usr).
	cfg := &config.Config{}
	cfg.Providers.Docker.Enabled = true
	cfg.Providers.Paths.RW = []string{"/usr"}
	w := strings.Join(sessionWarnings(cfg, roTargets), "\n")
	if !strings.Contains(w, "docker") || !strings.Contains(w, "root-equivalent") {
		t.Errorf("expected a docker root-equivalent warning, got: %q", w)
	}
	if !strings.Contains(w, "/usr") || !strings.Contains(w, "writable") {
		t.Errorf("expected a baseline-shadow warning for /usr, got: %q", w)
	}

	// Regression guard (review finding): a grant nested under a read-only baseline
	// path (a writable hole, e.g. /usr/local/bin under the RO /usr) must also warn —
	// not just a grant that equals or contains the RO target.
	child := &config.Config{}
	child.Providers.Paths.RW = []string{"/usr/local/bin"}
	cw := strings.Join(sessionWarnings(child, roTargets), "\n")
	if !strings.Contains(cw, "/usr/local/bin") || !strings.Contains(cw, "writable") {
		t.Errorf("a grant nested under a read-only baseline path must warn, got: %q", cw)
	}

	// A clean config (no docker, no overlapping grant) warns about nothing.
	if got := sessionWarnings(&config.Config{}, roTargets); len(got) != 0 {
		t.Errorf("clean config should produce no warnings, got: %v", got)
	}
}

// When the resolved backend reports /private-normalized read-only targets (always on
// macOS; also under -backend seatbelt dry-run inspection on Linux), a paths.rw grant under
// the /var|/tmp|/etc subtrees must still trip the shadow advisory against its /private
// target. The check is gate-free (it compares the raw and /private-folded grant), so this
// holds on any host and is fully exercised by CI.
func TestSessionWarningsMacPrivateNormalization(t *testing.T) {
	cfg := &config.Config{}
	cfg.Providers.Paths.RW = []string{"/var/log", "/etc/ssl", "/tmp/scratch"}
	roTargets := []string{"/private/var/log", "/private/etc/ssl", "/private/tmp/scratch"}
	warnings := sessionWarnings(cfg, roTargets)
	if len(warnings) != 3 {
		t.Errorf("each /var|/etc|/tmp grant must overlap its /private-normalized target; want 3 warnings, got %d: %v", len(warnings), warnings)
	}
	// The message must echo the grant as written, not the folded /private form.
	if w := strings.Join(warnings, "\n"); strings.Contains(w, `paths.rw "/private/`) {
		t.Errorf("the advisory must echo the grant as written, not /private-folded: %q", w)
	}
}

// Gate-free additivity: the raw grant form preserves Linux behaviour, so a grant under a
// non-/private read-only target (a bwrap-style target, or a bare /var|/tmp|/etc node) still
// warns and is never lost to the /private folding.
func TestSessionWarningsRawFormPreserved(t *testing.T) {
	cfg := &config.Config{}
	cfg.Providers.Paths.RW = []string{"/var/log", "/usr/local"}
	// bwrap-style (non-/private) targets, incl. a bare /var node.
	roTargets := []string{"/var", "/usr"}
	warnings := sessionWarnings(cfg, roTargets)
	if len(warnings) != 2 {
		t.Errorf("raw-form overlaps (/var/log⊂/var, /usr/local⊂/usr) must still warn; want 2, got %d: %v", len(warnings), warnings)
	}
}

// bannerFixture is a session with every optional roll-up row present.
func bannerFixture() (*config.Config, bannerInfo) {
	cfg := &config.Config{
		Providers: config.Providers{
			Paths: paths.Config{RO: []string{"/home/u/.agents"}, RW: []string{"/data"}},
			Block: block.Config{Directories: []string{"/data/secrets"}}, // a config-added blocked dir
		},
	}
	cfg.Providers.Home.Enabled = true
	return cfg, bannerInfo{
		version:  "0.3.0",
		latest:   "0.4.0",
		home:     "/home/u",
		workdir:  "/home/u/src/x",
		auditLog: "/home/u/.claude/corral-audit.jsonl",
		profiles: []string{"offline"},
	}
}

var bannerNotices = []providers.Notice{
	{Provider: "home", Text: "private $HOME at /home/u/.cache/corral/home-x"},
	{Provider: "aiignore", Text: "3 pattern(s) from .aiignore"},
	{Provider: "aiignore", Text: `1 "!" re-include pattern(s) ignored`},
}

func TestWriteStartupBanner(t *testing.T) {
	cfg, info := bannerFixture()
	var b strings.Builder
	writeStartupBanner(&b, report.NewStyle(false, false), cfg, info, []string{"heads up"}, bannerNotices, []string{"hooks"})
	want := strings.Join([]string{
		"",
		"  ████████████  corral v0.3.0   profile offline",
		"  █          █  ! 0.3.0 → 0.4.0 available",
		"  █  ████  █      → corral update",
		"  █  ████  █",
		"  █          █  project     ~/src/x   rw",
		"  ████████████  writable    /data",
		"                read-only   ~/.agents",
		"                home        private $HOME   kept between sessions",
		"                policy      audit events in ~/.claude/corral-audit.jsonl",
		"                            ! bash-mode is not checked or secret-scanned",
		"",
		"  ! heads up",
		"",
		"providers " + strings.Repeat("─", 56),
		"  ● home            private $HOME at ~/.cache/corral/home-x",
		"  ● aiignore        3 pattern(s) from .aiignore",
		`                    1 "!" re-include pattern(s) ignored`,
		"  ○ hooks           acts only at launch (not expanded in this dry-run)",
		"",
	}, "\n")
	if got := b.String(); got != want {
		t.Errorf("banner =\n%s\nwant\n%s", got, want)
	}
}

// With ASCII-only input, the ASCII form of all run output is ASCII only: nothing corral
// formats itself adds Unicode.
func TestWriteStartupBannerASCII(t *testing.T) {
	cfg, info := bannerFixture()
	c := report.NewStyle(false, true)
	var b strings.Builder
	writeStartupBanner(&b, c, cfg, info, []string{"heads up"}, bannerNotices, []string{"hooks"})
	bannerSessionHookPresenter(&b, c)("preStart", "10-a", "hi\n", true)
	want := strings.Join([]string{
		"",
		"  ############  corral v0.3.0   profile offline",
		"  #          #  [!] 0.3.0 -> 0.4.0 available",
		"  #  ####  #        -> corral update",
		"  #  ####  #",
		"  #          #  project     ~/src/x   rw",
		"  ############  writable    /data",
		"                read-only   ~/.agents",
		"                home        private $HOME   kept between sessions",
		"                policy      audit events in ~/.claude/corral-audit.jsonl",
		"                            ! bash-mode is not checked or secret-scanned",
		"",
		"[!]  heads up",
		"",
		"providers " + strings.Repeat("-", 56),
		"[on] home           private $HOME at ~/.cache/corral/home-x",
		"[on] aiignore       3 pattern(s) from .aiignore",
		`                    1 "!" re-include pattern(s) ignored`,
		"[--] hooks          acts only at launch (not expanded in this dry-run)",
		"     hooks          setup output from preStart.10-a",
		"                    | hi",
		"                    | (output truncated)",
		"",
		"",
	}, "\n")
	if got := b.String(); got != want {
		t.Errorf("ASCII banner =\n%s\nwant\n%s", got, want)
	}
}

// The real launch prints the banner in two halves with its confirmation gate between them,
// so the prompt lands directly under the warnings. writeBannerHeader carries the mark, the
// roll-up, and the warnings, all known before providers mint; writeBannerBody carries only
// the providers section.
func TestBannerHeaderBodySplit(t *testing.T) {
	cfg, info := bannerFixture()

	var head strings.Builder
	writeBannerHeader(&head, report.NewStyle(false, false), cfg, info, []string{"heads up"})
	h := head.String()
	if !strings.HasSuffix(h, "\n  ! heads up\n") {
		t.Errorf("header must end with the warnings, so the gate prompt follows them:\n%s", h)
	}
	if strings.Contains(h, "providers") {
		t.Errorf("header must not contain the providers section (it prints below the gate):\n%s", h)
	}

	var body strings.Builder
	writeBannerBody(&body, report.NewStyle(false, false), "/home/u", bannerNotices, nil)
	bd := body.String()
	if !strings.HasPrefix(bd, "\nproviders ─") {
		t.Errorf("body must open with a blank line and the providers rule:\n%s", bd)
	}
	for _, absent := range []string{"corral v0.3.0", "project", "heads up"} {
		if strings.Contains(bd, absent) {
			t.Errorf("body must not contain header content %q:\n%s", absent, bd)
		}
	}
}

// Rows without data drop out of the roll-up: no extra grants means no writable or
// read-only row, no profile or update leaves the version line bare, and without the home provider
// the agent writes to the host $HOME.
func TestBannerRollupOptionalRows(t *testing.T) {
	var b strings.Builder
	writeBannerHeader(&b, report.NewStyle(false, false), &config.Config{}, bannerInfo{version: "dev", home: "/home/u", workdir: "/w", auditLog: "/a.jsonl"}, nil)
	out := b.String()
	for _, absent := range []string{"writable", "read-only", "profile"} {
		if strings.Contains(out, absent) {
			t.Errorf("roll-up without data must not show %q:\n%s", absent, out)
		}
	}
	for _, want := range []string{"corral dev\n  █          █\n", "home        host $HOME\n", "policy      audit events in /a.jsonl\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("roll-up missing %q:\n%s", want, out)
		}
	}
}

// The providers section stays when no provider reported, so its absence is visible.
func TestWriteStartupBannerNoProviders(t *testing.T) {
	var b strings.Builder
	writeBannerBody(&b, report.NewStyle(false, false), "/home/u", nil, nil)
	if want := "\nproviders " + strings.Repeat("─", report.RuleStop-len("providers ")) + "\n    (none)\n"; b.String() != want {
		t.Errorf("empty providers section = %q, want %q", b.String(), want)
	}
}

// Long grant lists stay within LineMax: the paths that do not fit are counted.
func TestBannerFitsLineMax(t *testing.T) {
	cfg := &config.Config{Providers: config.Providers{Paths: paths.Config{
		RO: []string{"/home/u/Documents/git/github.com", "/home/u/.agents", "/home/u/Documents/git/gitlab.com"},
		RW: []string{"/srv/cache", "/home/u/Documents/git/github.com/go-corral/openspec-artifacts"},
	}}}
	for _, c := range []report.Style{report.NewStyle(false, false), report.NewStyle(false, true)} {
		var b strings.Builder
		writeBannerHeader(&b, c, cfg, bannerInfo{version: "0.3.0", latest: "0.4.0", home: "/home/u", workdir: "/home/u/src/x", auditLog: "/home/u/.claude/corral-audit.jsonl"}, nil)
		for _, ln := range strings.Split(b.String(), "\n") {
			if n := utf8.RuneCountInString(ln); n > report.LineMax {
				t.Errorf("line is %d columns, want at most %d: %q", n, report.LineMax, ln)
			}
		}
		for _, want := range []string{"writable    /srv/cache +1\n", "read-only   ~/Documents/git/github.com ~/.agents +1\n"} {
			if !strings.Contains(b.String(), want) {
				t.Errorf("grant rows must count the paths that do not fit, missing %q:\n%s", want, b.String())
			}
		}
	}
}

// The update verdict names both versions; its fix line starts under the message text.
func TestBannerUpdateVerdict(t *testing.T) {
	for _, tt := range []struct {
		style     report.Style
		warn, fix string
	}{
		{report.NewStyle(false, false), "  █          █  ! 0.3.0 → 0.4.0 available\n", "  █  ████  █      → corral update\n"},
		{report.NewStyle(false, true), "  #          #  [!] 0.3.0 -> 0.4.0 available\n", "  #  ####  #        -> corral update\n"},
	} {
		var b strings.Builder
		writeBannerHeader(&b, tt.style, &config.Config{}, bannerInfo{version: "0.3.0", latest: "0.4.0", home: "/h", workdir: "/w", auditLog: "/a"}, nil)
		if !strings.Contains(b.String(), tt.warn+tt.fix) {
			t.Errorf("header missing the update verdict %q%q:\n%s", tt.warn, tt.fix, b.String())
		}
	}
}

func TestFitPaths(t *testing.T) {
	for _, tt := range []struct {
		paths  []string
		width  int
		want   string
		hidden int
	}{
		{nil, 20, "", 0},
		{[]string{"/a", "/b"}, 20, "/a /b", 0},
		{[]string{"/home/u/x", "/b"}, 20, "~/x /b", 0},
		{[]string{"/aaaa", "/bbbb", "/c"}, 14, "/aaaa /bbbb /c", 0},
		// "/aaaa /bbbb +1" is 14 columns: the second path fits only while its "+1" does too.
		{[]string{"/aaaa", "/bbbb", "/ccc"}, 14, "/aaaa /bbbb", 1},
		{[]string{"/aaaa", "/bbbb", "/ccc"}, 13, "/aaaa", 2},
		// The first path is always shown.
		{[]string{"/a-very-long-path", "/b"}, 5, "/a-very-long-path", 1},
		// Control characters cannot rewrite the row; a space would split one path in two.
		{[]string{"/a\x1b[2K\rb", "/home/u/Application Support"}, 40, `"/a\x1b[2K\rb" "~/Application Support"`, 0},
		// The quoted form counts: `/c "~/a b" +1` is 13 columns.
		{[]string{"/c", "/home/u/a b", "/dd"}, 12, "/c", 2},
		{[]string{"/c", "/home/u/a b", "/dd"}, 13, `/c "~/a b"`, 1},
	} {
		if got, hidden := fitPaths(tt.paths, "/home/u", tt.width); got != tt.want || hidden != tt.hidden {
			t.Errorf("fitPaths(%q, %d) = %q, %d, want %q, %d", tt.paths, tt.width, got, hidden, tt.want, tt.hidden)
		}
	}
}

// Color follows the mockup: paths blue, the rw tag green, counts and notes dim, active
// provider rows in the default color, and launch-only rows dim whole.
func TestWriteStartupBannerColors(t *testing.T) {
	cfg, info := bannerFixture()
	c := report.NewStyle(true, false)
	var b strings.Builder
	writeStartupBanner(&b, c, cfg, info, nil, bannerNotices[:1], []string{"hooks"})
	out := b.String()
	for _, want := range []string{
		c.Bold + "corral v0.3.0" + c.Reset + "   " + c.Dim + "profile offline" + c.Reset,
		"project     " + c.Blue + "~/src/x" + c.Reset + "   " + c.Green + "rw" + c.Reset,
		"home        " + c.Blue + "private $HOME" + c.Reset + "   " + c.Dim + "kept between sessions" + c.Reset,
		"policy      audit events in " + c.Blue + "~/.claude/corral-audit.jsonl" + c.Reset,
		c.Bold + "providers" + c.Reset + " " + c.Dim + "─",
		"  ● home            private $HOME at ~/.cache/corral/home-x\n",
		"  " + c.Dim + "○" + c.Reset + " " + c.Dim + "hooks           acts only at launch (not expanded in this dry-run)" + c.Reset + "\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("styled banner missing %q:\n%q", want, out)
		}
	}
}

func TestAbbrevHome(t *testing.T) {
	for _, tt := range []struct{ path, home, want string }{
		{"/home/user/docs", "/home/user", "~/docs"},
		{"/home/user", "/home/user/", "~"},
		{"/home/user2/docs", "/home/user", "/home/user2/docs"},
		{"/home/user", "", "/home/user"},
		{"/srv/docs", "/", "/srv/docs"},
		{"/", "/", "/"},
		{"/srv/docs", "relative", "/srv/docs"},
		{"/home/user", "/home/user/docs", "/home/user"},
	} {
		if got := abbrevHome(tt.path, tt.home); got != tt.want {
			t.Errorf("abbrevHome(%q, %q) = %q, want %q", tt.path, tt.home, got, tt.want)
		}
	}
}

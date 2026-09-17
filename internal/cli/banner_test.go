package cli

import (
	"os"
	"strings"
	"testing"

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

func TestWriteStartupBanner(t *testing.T) {
	cfg := &config.Config{
		Net: config.NetOpen,
		Providers: config.Providers{
			Paths: paths.Config{RW: []string{"/data"}},
			Block: block.Config{Directories: []string{"/data/secrets"}}, // a config-added blocked dir
		},
	}
	cfg.Providers.Home.Enabled = true

	var b strings.Builder
	writeStartupBanner(&b, colors(false), cfg, "0.3.0", "a newer corral is available: 0.3.0 → 0.4.0",
		"/home/u", []string{"offline"}, "/tmp/corral-work-x1y2z3",
		[]string{"heads up"}, []providers.Notice{
			{Provider: "home", Text: "private $HOME at /home/u/.cache/corral/home-x"},
			{Provider: "gitlab", Text: "minted project access token for g/r (scopes: read_api)"},
		})
	out := b.String()

	for _, want := range []string{
		// version + status sit beside the logo; the update notice is the version warning there
		"corral", "v0.3.0", "· sandbox active", "⚠ a newer corral is available: 0.3.0 → 0.4.0",
		"session", "profile", "offline", "network", "open",
		"workdir", "/tmp/corral-work-x1y2z3", "connectors", "off",
		"providers", "read-write", "/data",
		// blocked paths are spelled out (home abbreviated to ~), floor tagged,
		// config additions after a "+"; AI-ignore masks moved to the aiignore
		// provider's status row in the providers section
		"blocked", "~/.ssh", "~/.gnupg", "~/.aws", "(always blocked)", "/data/secrets",
		// the standing "!" bash-mode caveat is a banner line, not a model-only note
		"note", "bash-mode output is not secret-scanned",
		"⚠ heads up",
		// provider status rows are labeled with their provider name, host paths abbreviated
		"home       private $HOME at ~/.cache/corral/home-x",
		"gitlab     minted project access token for g/r (scopes: read_api)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("banner missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("colors(false) must emit no ANSI escape codes:\n%q", out)
	}
}

// The real launch prints the banner in two halves with its confirmation gate between them,
// so the prompt lands directly under the warnings (not mid-providers). writeBannerHeader must
// carry the logo + warnings and nothing from the config summary; writeBannerBody must carry
// the config summary + providers and none of the header — so the gate slots cleanly between.
func TestBannerHeaderBodySplit(t *testing.T) {
	cfg := &config.Config{
		Net:       config.NetOpen,
		Providers: config.Providers{Paths: paths.Config{RW: []string{"/data"}}},
	}
	warnings := []string{"heads up"}

	var head strings.Builder
	writeBannerHeader(&head, colors(false), "0.3.0", "a newer corral is available", warnings)
	h := head.String()
	for _, want := range []string{"corral", "v0.3.0", "· sandbox active", "⚠ a newer corral is available", "⚠ heads up"} {
		if !strings.Contains(h, want) {
			t.Errorf("header missing %q:\n%s", want, h)
		}
	}
	for _, absent := range []string{"session", "workdir", "providers", "read-write"} {
		if strings.Contains(h, absent) {
			t.Errorf("header must not contain body field %q (it prints below the gate):\n%s", absent, h)
		}
	}

	var body strings.Builder
	writeBannerBody(&body, colors(false), cfg, "/home/u", []string{"offline"}, "/w", []providers.Notice{
		{Provider: "home", Text: "private $HOME at /home/u/.cache/corral/home-x"},
	})
	b := body.String()
	for _, want := range []string{"session", "offline", "workdir", "read-write", "/data", "providers", "home"} {
		if !strings.Contains(b, want) {
			t.Errorf("body missing %q:\n%s", want, b)
		}
	}
	for _, absent := range []string{"sandbox active", "heads up"} {
		if strings.Contains(b, absent) {
			t.Errorf("body must not contain header content %q:\n%s", absent, b)
		}
	}
}

// The providers section attributes every status row to its provider: the name prints
// once per consecutive run (further rows indent under the text column), the first row
// carries the "providers" label, and host paths in the status text abbreviate to ~.
func TestWriteNoticesLabelsProviders(t *testing.T) {
	var b strings.Builder
	writeNotices(&b, colors(false), "/home/u", []providers.Notice{
		{Provider: "block", Text: "masking 0 dir(s) + 1 file(s)"},
		{Provider: "aiignore", Text: "3 pattern(s) from .aiignore"},
		{Provider: "aiignore", Text: `1 "!" re-include pattern(s) ignored`},
		{Provider: "hooks", Text: "preStart ran 10-a · from /home/u/proj"},
	})
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	want := []string{
		"  providers  block      masking 0 dir(s) + 1 file(s)",
		"             aiignore   3 pattern(s) from .aiignore",
		`                        1 "!" re-include pattern(s) ignored`,
		"             hooks      preStart ran 10-a · from ~/proj",
	}
	if len(lines) != len(want) {
		t.Fatalf("lines = %q, want %q", lines, want)
	}
	for i, w := range want {
		if lines[i] != w {
			t.Errorf("line %d = %q, want %q", i, lines[i], w)
		}
	}
}

// An empty notices set renders the providers row as "(none)" rather than dropping the
// section (writeStartupBanner falls back to the plain label row).
func TestWriteStartupBannerNoProviders(t *testing.T) {
	var b strings.Builder
	writeStartupBanner(&b, colors(false), &config.Config{}, "dev", "", "/home/u", nil, "/w", nil, nil)
	if !strings.Contains(b.String(), "providers  (none)") {
		t.Errorf("empty notices must render the providers row as (none):\n%s", b.String())
	}
}

func TestColorsAndColorTo(t *testing.T) {
	if c := colors(false); c.yellow != "" || c.reset != "" || c.bold != "" {
		t.Error("disabled colors must be empty strings")
	}
	if c := colors(true); c.yellow == "" || c.reset == "" {
		t.Error("enabled colors must be non-empty")
	}
	// A regular file is not a terminal → no color.
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if colorTo(f) {
		t.Error("a regular file is not a tty; colorTo must be false")
	}
}

// TestIsTerminalDevNull ensures a character-device mode bit is not mistaken for a terminal.
func TestIsTerminalDevNull(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if isTerminal(f) {
		t.Error("/dev/null is a character device but not a terminal; isTerminal must be false")
	}
	if colorTo(f) {
		t.Error("colorTo(/dev/null) must be false")
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

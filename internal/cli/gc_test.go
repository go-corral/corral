package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/providers"
)

// cliFakeReaper implements providers.Provider + providers.Reaper for runGC tests.
type cliFakeReaper struct {
	name    string
	orphans []providers.Orphan
	reaped  int
}

func (f *cliFakeReaper) Name() string                   { return f.name }
func (f *cliFakeReaper) Available(context.Context) bool { return true }
func (f *cliFakeReaper) Mint(context.Context, providers.Session, bool) (*providers.Contribution, error) {
	return nil, nil
}
func (f *cliFakeReaper) GC(context.Context) ([]providers.Orphan, error) { return f.orphans, nil }
func (f *cliFakeReaper) Reap(_ context.Context, approved []providers.Orphan) error {
	f.reaped += len(approved)
	return nil
}

func TestRunGCNoOrphans(t *testing.T) {
	var out strings.Builder
	code := runGC(context.Background(), nil, gcOptions{}, strings.NewReader(""), &out)
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "no orphaned resources") {
		t.Errorf("output = %q", out.String())
	}
}

func TestRunGCDryRunNeverReaps(t *testing.T) {
	r := &cliFakeReaper{name: "k8s", orphans: []providers.Orphan{{Provider: "k8s", ID: "sa1", Describe: "SA sa1"}}}
	var out strings.Builder
	code := runGC(context.Background(), []providers.Reaper{r}, gcOptions{DryRun: true}, strings.NewReader(""), &out)
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	if r.reaped != 0 {
		t.Errorf("dry-run must not reap, reaped %d", r.reaped)
	}
	if !strings.Contains(out.String(), "dry-run") || !strings.Contains(out.String(), "SA sa1") {
		t.Errorf("output = %q", out.String())
	}
}

func TestRunGCConfirmationGates(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		yes      bool
		wantReap int
	}{
		{"declines on N", "n\n", false, 0},
		{"declines on empty (default no)", "\n", false, 0},
		{"declines on EOF", "", false, 0},
		{"approves on y", "y\n", false, 1},
		{"approves on yes", "yes\n", false, 1},
		{"--yes skips prompt", "", true, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &cliFakeReaper{name: "k8s", orphans: []providers.Orphan{{Provider: "k8s", ID: "sa1", Describe: "SA sa1"}}}
			var out strings.Builder
			code := runGC(context.Background(), []providers.Reaper{r}, gcOptions{Yes: c.yes}, strings.NewReader(c.input), &out)
			if code != 0 {
				t.Errorf("exit = %d, want 0", code)
			}
			if r.reaped != c.wantReap {
				t.Errorf("reaped %d, want %d (output: %q)", r.reaped, c.wantReap, out.String())
			}
		})
	}
}

func TestRunGCLayout(t *testing.T) {
	orphans := []providers.Orphan{
		{Provider: "kubernetes", ID: "sa1", Describe: "ServiceAccount corral/corral-alice-s1"},
		{Provider: "kubernetes", ID: "sa2", Describe: "ServiceAccount corral/corral-bob-s2"},
	}
	for _, tt := range []struct {
		name    string
		style   report.Style
		orphans []providers.Orphan
		opts    gcOptions
		want    string
	}{
		{"none", report.NewStyle(false, false), nil, gcOptions{}, "corral gc\n" +
			"  ✓ no orphaned resources\n"},
		{"dry-run", report.NewStyle(false, false), orphans, gcOptions{DryRun: true}, "corral gc   2 orphaned resources\n" +
			"  ● kubernetes      ServiceAccount corral/corral-alice-s1\n" +
			"  ● kubernetes      ServiceAccount corral/corral-bob-s2\n" +
			"    dry-run: nothing deleted\n"},
		{"reaped", report.NewStyle(false, false), orphans[:1], gcOptions{Yes: true}, "corral gc   1 orphaned resource\n" +
			"  ● kubernetes      ServiceAccount corral/corral-alice-s1\n" +
			"  ✓ reaped 1 resource\n"},
		{"ascii dry-run", report.NewStyle(false, true), orphans[:1], gcOptions{DryRun: true}, "corral gc   1 orphaned resource\n" +
			"[on] kubernetes     ServiceAccount corral/corral-alice-s1\n" +
			"     dry-run: nothing deleted\n"},
		{"ascii reaped", report.NewStyle(false, true), orphans, gcOptions{Yes: true}, "corral gc   2 orphaned resources\n" +
			"[on] kubernetes     ServiceAccount corral/corral-alice-s1\n" +
			"[on] kubernetes     ServiceAccount corral/corral-bob-s2\n" +
			"[ok] reaped 2 resources\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &cliFakeReaper{name: "kubernetes", orphans: tt.orphans}
			opts := tt.opts
			opts.Title, opts.Colors = true, tt.style
			var out strings.Builder
			if code := runGC(context.Background(), []providers.Reaper{r}, opts, strings.NewReader(""), &out); code != 0 {
				t.Errorf("exit = %d, want 0", code)
			}
			if out.String() != tt.want {
				t.Errorf("output:\n%s\nwant:\n%s", out.String(), tt.want)
			}
		})
	}
}

func TestRunGCDeclined(t *testing.T) {
	r := &cliFakeReaper{name: "kubernetes", orphans: []providers.Orphan{{Provider: "kubernetes", ID: "sa1", Describe: "SA sa1"}}}
	var out strings.Builder
	runGC(context.Background(), []providers.Reaper{r}, gcOptions{Colors: report.NewStyle(false, false)}, strings.NewReader("n\n"), &out)
	want := "  ● kubernetes      SA sa1\n" +
		"Reap these 1 resource(s)? [y/N]     nothing deleted\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

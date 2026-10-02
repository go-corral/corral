package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/hooks"
	"github.com/go-corral/corral/internal/trust"
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

// gc does not prompt: it loads a kubeconfig in the workdir only when its current content is
// approved, and it never contacts the server of a changed one.
func TestGCGatedKubeconfig(t *testing.T) {
	for _, changed := range []bool{false, true} {
		home, work := t.TempDir(), t.TempDir()
		t.Setenv("XDG_STATE_HOME", "")
		contacted := false
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			contacted = true
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/api/v1/serviceaccounts":
				fmt.Fprint(w, `{"kind":"ServiceAccountList","apiVersion":"v1","items":[{"metadata":{"name":"corral-alice-s1","namespace":"corral",`+
					`"labels":{"corral.dev/managed":"true","corral.dev/user":"alice","corral.dev/session":"s1"}}}]}`)
			case "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":
				fmt.Fprint(w, `{"kind":"ClusterRoleBindingList","apiVersion":"rbac.authorization.k8s.io/v1","items":[]}`)
			case "/apis/rbac.authorization.k8s.io/v1/rolebindings":
				fmt.Fprint(w, `{"kind":"RoleBindingList","apiVersion":"rbac.authorization.k8s.io/v1","items":[]}`)
			default:
				http.NotFound(w, r)
			}
		}))
		kubeconfig := func(user string) []byte {
			return []byte("apiVersion: v1\nkind: Config\ncurrent-context: c\n" +
				"clusters:\n- name: c\n  cluster:\n    server: " + srv.URL + "\n" +
				"contexts:\n- name: c\n  context:\n    cluster: c\n    user: " + user + "\n" +
				"users:\n- name: " + user + "\n  user:\n    token: t\n")
		}
		path := filepath.Join(work, "kube", "dev.yml")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, kubeconfig("a"), 0o600); err != nil {
			t.Fatal(err)
		}
		sum, err := hooks.HashFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := trust.NewStore(trust.DefaultDir(home)).Approve([]trust.Entry{{Path: path, SHA256: sum}}); err != nil {
			t.Fatal(err)
		}
		if changed {
			if err := os.WriteFile(path, kubeconfig("b"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("KUBECONFIG", path)

		cfg := &config.Config{}
		cfg.Providers.Kubernetes.Enabled = true
		reapers := providers.Reapers(gcCandidates(cfg, home, nil, work))
		var out strings.Builder
		runGC(context.Background(), reapers, gcOptions{DryRun: true, Colors: report.NewStyle(false, false)}, strings.NewReader(""), &out)
		srv.Close()

		if changed {
			if !strings.Contains(out.String(), "load kubeconfig: "+path+" is not approved") || contacted {
				t.Errorf("a changed kubeconfig must not load (server contacted: %v):\n%s", contacted, out.String())
			}
			continue
		}
		if !strings.Contains(out.String(), "ServiceAccount corral/corral-alice-s1") {
			t.Errorf("an approved kubeconfig must load and list the orphan:\n%s", out.String())
		}
	}
}

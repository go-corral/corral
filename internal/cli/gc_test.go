package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-corral/corral/internal/cli/report"
	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/providers"
	"github.com/go-corral/corral/internal/providers/hooks"
	"github.com/go-corral/corral/internal/providers/kubernetes"
	"github.com/go-corral/corral/internal/trust"
)

// cliFakeReaper implements providers.Provider + providers.Reaper for runGC tests.
type cliFakeReaper struct {
	name    string
	orphans []providers.Orphan
	gcErr   error
	reaped  int
}

func (f *cliFakeReaper) Name() string                   { return f.name }
func (f *cliFakeReaper) Available(context.Context) bool { return true }
func (f *cliFakeReaper) Mint(context.Context, providers.Session, bool) (*providers.Contribution, error) {
	return nil, nil
}
func (f *cliFakeReaper) GC(context.Context) ([]providers.Orphan, error) { return f.orphans, f.gcErr }
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

// A reaper that fails to report keeps the exit status at 1 after the preview, a declined prompt,
// and a successful reap of the other reapers' orphans.
func TestRunGCPartialFailure(t *testing.T) {
	for _, tc := range []struct {
		name     string
		opts     gcOptions
		input    string
		wantReap int
	}{
		{"dry-run", gcOptions{DryRun: true}, "", 0},
		{"declined", gcOptions{}, "n\n", 0},
		{"reaped", gcOptions{Yes: true}, "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok := &cliFakeReaper{name: "kubernetes", orphans: []providers.Orphan{{Provider: "kubernetes", ID: "sa1", Describe: "SA sa1"}}}
			failed := &cliFakeReaper{name: "vault", gcErr: errors.New("unreachable")}
			var out strings.Builder
			code := runGC(context.Background(), []providers.Reaper{ok, failed}, tc.opts, strings.NewReader(tc.input), &out)
			if code != 1 {
				t.Errorf("exit = %d, want 1:\n%s", code, out.String())
			}
			if ok.reaped != tc.wantReap {
				t.Errorf("reaped %d, want %d:\n%s", ok.reaped, tc.wantReap, out.String())
			}
			if !strings.Contains(out.String(), `provider "vault": unreachable`) {
				t.Errorf("want the failed reaper reported:\n%s", out.String())
			}
		})
	}
}

// gc checks declared clusters even when none is enabled, and leaves an unconfigured Kubernetes
// provider alone.
func TestGCCandidatesKubernetes(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	names := func(cfg *config.Config) []string {
		var out []string
		for _, p := range gcCandidates(cfg, t.TempDir(), nil, t.TempDir()) {
			out = append(out, p.Name())
		}
		return out
	}
	declared := &config.Config{}
	declared.Providers.Kubernetes.Clusters = map[string]kubernetes.Cluster{"staging": {Enabled: new(false)}}
	if got := names(declared); !slices.Equal(got, []string{"kubernetes"}) {
		t.Errorf("only disabled declared clusters: candidates = %v, want [kubernetes]", got)
	}
	if got := names(&config.Config{}); slices.Contains(got, "kubernetes") {
		t.Errorf("enabled: false and no clusters: candidates = %v, want no kubernetes", got)
	}
}

// gc does not prompt: it loads a kubeconfig in the workdir only when its current content is
// approved, and it never contacts the server of a changed one. The gate and the provider resolve a
// relative kubeconfig.path against the same workdir, so a changed file never loads from disk. This
// holds for a declared cluster that is disabled, which gc checks as well.
func TestGCGatedKubeconfig(t *testing.T) {
	for _, cluster := range []string{"implicit", "enabled", "disabled"} {
		for _, changed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/changed=%v", cluster, changed), func(t *testing.T) {
				home, work := t.TempDir(), t.TempDir()
				t.Chdir(work)
				t.Setenv("XDG_STATE_HOME", "")
				var contacted atomic.Bool
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					contacted.Store(true)
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

				cfg := &config.Config{}
				if cluster == "implicit" {
					t.Setenv("KUBECONFIG", path)
					cfg.Providers.Kubernetes.Enabled = true
				} else {
					t.Setenv("KUBECONFIG", "")
					cfg.Providers.Kubernetes.Clusters = map[string]kubernetes.Cluster{
						"dev": {Enabled: new(cluster == "enabled"), Kubeconfig: kubernetes.Kubeconfig{Path: "kube/dev.yml"}},
					}
				}
				reapers := providers.Reapers(gcCandidates(cfg, home, nil, work))
				var out strings.Builder
				runGC(context.Background(), reapers, gcOptions{DryRun: true, Colors: report.NewStyle(false, false)}, strings.NewReader(""), &out)
				srv.Close()

				if changed {
					if !strings.Contains(out.String(), "load kubeconfig: "+path+" is not approved") || contacted.Load() {
						t.Errorf("a changed kubeconfig must not load (server contacted: %v):\n%s", contacted.Load(), out.String())
					}
					return
				}
				if !strings.Contains(out.String(), "ServiceAccount corral/corral-alice-s1") {
					t.Errorf("an approved kubeconfig must load and list the orphan:\n%s", out.String())
				}
			})
		}
	}
}

// stagingCluster serves one orphaned ServiceAccount and counts the deletes.
func stagingCluster(t *testing.T) (server *httptest.Server, deletes *atomic.Int32) {
	t.Helper()
	deletes = new(atomic.Int32)
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodDelete {
			deletes.Add(1)
			fmt.Fprint(w, `{"kind":"Status","apiVersion":"v1","status":"Success"}`)
			return
		}
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
	t.Cleanup(server.Close)
	return server, deletes
}

func serverKubeconfig(server, user string) []byte {
	return []byte("apiVersion: v1\nkind: Config\ncurrent-context: c\n" +
		"clusters:\n- name: c\n  cluster:\n    server: " + server + "\n" +
		"contexts:\n- name: c\n  context:\n    cluster: c\n    user: " + user + "\n" +
		"users:\n- name: " + user + "\n  user:\n    token: t\n")
}

func writeTestFile(t *testing.T, p string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// gc does not load a gated kubeconfig of a disabled cluster whose content changed after approval,
// still lists the orphans on the other cluster, and exits non-zero. Both ways gc builds the
// provider gate the disabled cluster: with another cluster enabled, and with none enabled.
func TestGCUnapprovedKubeconfigDisabledCluster(t *testing.T) {
	for _, stagingEnabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("staging enabled=%v", stagingEnabled), func(t *testing.T) {
			home, work, other := t.TempDir(), t.TempDir(), t.TempDir()
			t.Setenv("XDG_STATE_HOME", "")
			var contacted atomic.Bool
			dev := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				contacted.Store(true)
				http.Error(w, "unexpected", http.StatusInternalServerError)
			}))
			defer dev.Close()
			staging, _ := stagingCluster(t)

			devPath := filepath.Join(work, "kube", "dev.yml")
			writeTestFile(t, devPath, serverKubeconfig(dev.URL, "a"))
			sum, err := hooks.HashFile(devPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := trust.NewStore(trust.DefaultDir(home)).Approve([]trust.Entry{{Path: devPath, SHA256: sum}}); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, devPath, serverKubeconfig(dev.URL, "b"))
			stagingPath := filepath.Join(other, "staging.yml")
			writeTestFile(t, stagingPath, serverKubeconfig(staging.URL, "a"))

			cfg := &config.Config{}
			cfg.Providers.Kubernetes.Clusters = map[string]kubernetes.Cluster{
				"dev":     {Enabled: new(false), Kubeconfig: kubernetes.Kubeconfig{Path: "kube/dev.yml"}},
				"staging": {Enabled: new(stagingEnabled), Kubeconfig: kubernetes.Kubeconfig{Path: stagingPath}},
			}
			reapers := providers.Reapers(gcCandidates(cfg, home, nil, work))
			var out strings.Builder
			code := runGC(context.Background(), reapers, gcOptions{DryRun: true, Colors: report.NewStyle(false, false)}, strings.NewReader(""), &out)

			if code != 1 {
				t.Errorf("exit = %d, want 1 for the cluster that failed", code)
			}
			if contacted.Load() {
				t.Error("gc contacted the server of the changed kubeconfig")
			}
			if !strings.Contains(out.String(), "cluster dev: load kubeconfig: "+devPath+" is not approved") {
				t.Errorf("want an error naming dev:\n%s", out.String())
			}
			if !strings.Contains(out.String(), "cluster staging: ServiceAccount corral/corral-alice-s1") {
				t.Errorf("want the orphan on staging listed:\n%s", out.String())
			}
		})
	}
}

// uninstall reports incomplete cleanup when one cluster fails collection, after it reaps the
// orphan of the other cluster.
func TestUninstallGCPhasePartialFailure(t *testing.T) {
	staging, deletes := stagingCluster(t)
	dir := t.TempDir()
	stagingPath := filepath.Join(dir, "staging.yml")
	writeTestFile(t, stagingPath, serverKubeconfig(staging.URL, "a"))
	cfg := &config.Config{}
	cfg.Providers.Kubernetes.Clusters = map[string]kubernetes.Cluster{
		"dev":     {Enabled: new(true), Kubeconfig: kubernetes.Kubeconfig{Path: filepath.Join(dir, "missing.yml")}},
		"staging": {Enabled: new(true), Kubeconfig: kubernetes.Kubeconfig{Path: stagingPath}},
	}
	t.Chdir(t.TempDir())
	t.Setenv("XDG_STATE_HOME", "")
	var out strings.Builder
	opts := uninstallOptions{Home: t.TempDir(), Yes: true, Colors: report.NewStyle(false, false)}
	if !uninstallGCPhase(opts, uninstallFootprint{Cfg: cfg}, strings.NewReader(""), &out) {
		t.Errorf("want the gc phase to report a failure:\n%s", out.String())
	}
	if n := deletes.Load(); n != 1 {
		t.Errorf("deletes = %d, want the staging orphan reaped:\n%s", n, out.String())
	}
	if !strings.Contains(out.String(), "cluster dev: ") {
		t.Errorf("want an error naming dev:\n%s", out.String())
	}
}

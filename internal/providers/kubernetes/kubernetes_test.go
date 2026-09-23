package kubernetes

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/go-corral/corral/internal/providers/spec"
)

// fakeK8s builds a k8s provider backed by a fake clientset seeded with objs. It
// installs two reactors the bare fake lacks: a token-subresource reactor (the
// default tracker returns an empty TokenRequest, so resp.Status.Token would be ""),
// and a label-filtering List reactor (the fake's tracker filters List by namespace
// only, not by label selector — so without this, matchNamespaces/GC would see
// unmanaged objects and the tests would assert against wrong behavior).
func fakeK8s(t *testing.T, cfg Config, objs ...runtime.Object) (*k8s, *fake.Clientset) {
	t.Helper()
	cs := fake.NewClientset(objs...)

	cs.PrependReactor("list", "*", func(a k8stesting.Action) (bool, runtime.Object, error) {
		la, ok := a.(k8stesting.ListActionImpl)
		if !ok {
			return false, nil, nil
		}
		sel := la.GetListRestrictions().Labels
		if sel == nil || sel.Empty() {
			return false, nil, nil // no label selector → let the default tracker handle it
		}
		listObj, err := cs.Tracker().List(la.GetResource(), la.Kind, la.GetNamespace())
		if err != nil {
			return true, nil, err
		}
		items, err := meta.ExtractList(listObj)
		if err != nil {
			return true, nil, err
		}
		var kept []runtime.Object
		for _, it := range items {
			m, err := meta.Accessor(it)
			if err != nil {
				return true, nil, err
			}
			if sel.Matches(labels.Set(m.GetLabels())) {
				kept = append(kept, it)
			}
		}
		if err := meta.SetList(listObj, kept); err != nil {
			return true, nil, err
		}
		return true, listObj, nil
	})

	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() != "token" {
			return false, nil, nil
		}
		return true, &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{Token: "fake-bearer-token"}}, nil
	})

	k := &k8s{
		cfg:  cfg,
		home: t.TempDir(),
		connect: func() (kubernetes.Interface, *rest.Config, error) {
			return cs, &rest.Config{
				Host:            "https://api.example:6443",
				TLSClientConfig: rest.TLSClientConfig{CAData: []byte("FAKE-CA-DATA")},
			}, nil
		},
	}
	return k, cs
}

// spyTokenRequests records the TokenRequest the provider sends (the fakeK8s token reactor
// discards it) so a test can assert the BoundObjectRef binding. It records and falls
// through, leaving the response to the reactor behind it.
func spyTokenRequests(cs *fake.Clientset) *authnv1.TokenRequest {
	seen := &authnv1.TokenRequest{}
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(k8stesting.CreateActionImpl)
		if !ok || ca.GetSubresource() != "token" {
			return false, nil, nil
		}
		if req, ok := ca.GetObject().(*authnv1.TokenRequest); ok {
			seen.Spec = req.Spec
		}
		return false, nil, nil
	})
	return seen
}

// stampSecretUID makes the fake assign a UID on Secret creation — the real API server
// does, and the token's BoundObjectRef carries it. The reactor must complete the create
// itself (a reactor mutating its own deep copy would not reach the tracker).
func stampSecretUID(t *testing.T, cs *fake.Clientset, uid string) {
	t.Helper()
	cs.PrependReactor("create", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca, ok := a.(k8stesting.CreateActionImpl)
		if !ok {
			return false, nil, nil
		}
		s, ok := ca.GetObject().(*corev1.Secret)
		if !ok {
			return false, nil, nil
		}
		s.UID = types.UID(uid)
		if err := cs.Tracker().Create(ca.GetResource(), s, ca.GetNamespace()); err != nil {
			return true, nil, err
		}
		return true, s, nil
	})
}

// rbacActions reports the RBAC/namespace-mutating API calls recorded on cs — the calls
// preProvisioned mode must never make.
func rbacActions(cs *fake.Clientset) []string {
	var out []string
	for _, a := range cs.Actions() {
		res := a.GetResource().Resource
		switch {
		case res == "clusterrolebindings" || res == "rolebindings" || res == "roles" || res == "clusterroles":
			out = append(out, a.GetVerb()+" "+res)
		case res == "namespaces" && a.GetVerb() != "get":
			out = append(out, a.GetVerb()+" "+res)
		}
	}
	return out
}

func ns(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}
}

func nsLabeled(name string, lbls map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: lbls}}
}

func TestKubernetesMintClusterWide(t *testing.T) {
	cfg := Config{ServiceAccountNamespace: "corral", TokenLifetime: "8h"}
	k, cs := fakeK8s(t, cfg, ns("corral"))
	ctx := context.Background()

	c, err := k.Mint(ctx, spec.Session{User: "alice", ID: "sess1"}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Contribution: one read-only own-path kubeconfig mount + KUBECONFIG env + Cleanup.
	if len(c.Mounts) != 1 || !c.Mounts[0].ReadOnly || c.Mounts[0].Src != c.Mounts[0].Dst {
		t.Errorf("want one read-only own-path mount, got %+v", c.Mounts)
	}
	if c.Env["KUBECONFIG"] != c.Mounts[0].Src {
		t.Errorf("KUBECONFIG must point at the mounted kubeconfig: %v", c.Env)
	}
	if c.Cleanup == nil {
		t.Fatal("k8s minter must register a Cleanup (it is the first real cleanup-bearing provider)")
	}
	// CleanupHint is surfaced only if teardown fails: it points at the `corral gc` backstop
	// and the bounded token lifetime, and must never carry the token value.
	if !strings.Contains(c.CleanupHint, "corral gc") || !strings.Contains(c.CleanupHint, "8h") {
		t.Errorf("CleanupHint should name the `corral gc` remedy and the token lifetime: %q", c.CleanupHint)
	}
	if strings.Contains(c.CleanupHint, "fake-bearer-token") {
		t.Errorf("CleanupHint must not leak the minted token: %q", c.CleanupHint)
	}
	// The AgentNote tells the model which cluster it can reach as whom and with what
	// permissions (API server, minted SA + lifetime, the bound roles) — and never the
	// token value.
	if len(c.AgentNotes) != 1 {
		t.Fatalf("expected one AgentNotes line, got %v", c.AgentNotes)
	}
	for _, want := range []string{"KUBECONFIG", "https://api.example:6443", "corral/corral-alice-sess1", "8h", "ClusterRole view cluster-wide"} {
		if !strings.Contains(c.AgentNotes[0], want) {
			t.Errorf("AgentNotes should mention %q: %q", want, c.AgentNotes[0])
		}
	}
	if strings.Contains(c.AgentNotes[0], "fake-bearer-token") {
		t.Errorf("AgentNotes must not leak the minted token: %q", c.AgentNotes[0])
	}

	saName := "corral-alice-sess1"
	if _, err := cs.CoreV1().ServiceAccounts("corral").Get(ctx, saName, metav1.GetOptions{}); err != nil {
		t.Errorf("service account not created: %v", err)
	}
	crbs, _ := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if len(crbs.Items) != 1 {
		t.Fatalf("want 1 ClusterRoleBinding (default permission), got %d", len(crbs.Items))
	}
	crb := crbs.Items[0]
	if crb.RoleRef.Kind != "ClusterRole" || crb.RoleRef.Name != "view" {
		t.Errorf("default bind should target the view ClusterRole, got %+v", crb.RoleRef)
	}
	if len(crb.Subjects) != 1 || crb.Subjects[0].Name != saName || crb.Subjects[0].Namespace != "corral" {
		t.Errorf("CRB subject must be the session SA: %+v", crb.Subjects)
	}
	if crb.Labels[labelManaged] != "true" || crb.Labels[labelUser] != "alice" || crb.Labels[labelSession] != "sess1" {
		t.Errorf("CRB provenance labels wrong: %v", crb.Labels)
	}

	// The kubeconfig is written, parseable, and holds the minted token + embedded CA.
	data, err := os.ReadFile(c.Mounts[0].Src)
	if err != nil {
		t.Fatalf("kubeconfig not written: %v", err)
	}
	kc, err := clientcmd.Load(data)
	if err != nil {
		t.Fatalf("kubeconfig not parseable: %v", err)
	}
	if ai := kc.AuthInfos["corral"]; ai == nil || ai.Token != "fake-bearer-token" {
		t.Errorf("kubeconfig must carry the minted bearer token, got %+v", ai)
	}
	cl := kc.Clusters["corral"]
	if cl == nil || cl.Server != "https://api.example:6443" || string(cl.CertificateAuthorityData) != "FAKE-CA-DATA" {
		t.Errorf("kubeconfig cluster must embed server + CA, got %+v", cl)
	}

	// Cleanup tears down the SA, the CRB, and the kubeconfig file (LIFO on exit).
	if err := c.Cleanup(ctx); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := cs.CoreV1().ServiceAccounts("corral").Get(ctx, saName, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("cleanup must delete the SA, got %v", err)
	}
	if crbs2, _ := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); len(crbs2.Items) != 0 {
		t.Errorf("cleanup must delete the CRB, %d left", len(crbs2.Items))
	}
	if _, err := os.Stat(c.Mounts[0].Src); !os.IsNotExist(err) {
		t.Errorf("cleanup must remove the kubeconfig file, got %v", err)
	}
}

// --- preProvisioned mode: corral creates only the per-session identity ---

// The happy path of the mode a developer holding just the stock namespace-scoped `edit`
// role can run: SA + revocation Secret + a token bound to that Secret, and not one RBAC
// object or namespace mutation anywhere.
func TestKubernetesMintPreProvisioned(t *testing.T) {
	cfg := Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a", TokenLifetime: "8h"}
	k, cs := fakeK8s(t, cfg, ns("corral-team-a"))
	seen := spyTokenRequests(cs)
	stampSecretUID(t, cs, "secret-uid-1")
	ctx := context.Background()

	c, err := k.Mint(ctx, spec.Session{User: "alice", ID: "sess1"}, false)
	if err != nil {
		t.Fatal(err)
	}

	// corral manages no RBAC in this mode — nothing bound, nothing created but the identity.
	if acts := rbacActions(cs); len(acts) != 0 {
		t.Errorf("preProvisioned mode must touch no RBAC and never create a namespace, got %v", acts)
	}

	base := "corral-alice-sess1"
	sa, err := cs.CoreV1().ServiceAccounts("corral-team-a").Get(ctx, base, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("service account not created: %v", err)
	}
	secret, err := cs.CoreV1().Secrets("corral-team-a").Get(ctx, base, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("revocation secret not created: %v", err)
	}
	if secret.Type != corev1.SecretTypeOpaque || len(secret.Data) != 0 {
		t.Errorf("the revocation secret is a handle, not storage: type=%q data=%v", secret.Type, secret.Data)
	}
	for name, lbls := range map[string]map[string]string{"ServiceAccount": sa.Labels, "Secret": secret.Labels} {
		if lbls[labelManaged] != "true" || lbls[labelUser] != "alice" || lbls[labelSession] != "sess1" {
			t.Errorf("%s provenance labels wrong (GC finds orphans by these): %v", name, lbls)
		}
	}

	// The token is bound to the Secret, so deleting the Secret revokes it immediately.
	ref := seen.Spec.BoundObjectRef
	if ref == nil {
		t.Fatal("preProvisioned mode must bind the token to the revocation secret")
	}
	if ref.Kind != "Secret" || ref.APIVersion != "v1" || ref.Name != base || string(ref.UID) != "secret-uid-1" {
		t.Errorf("BoundObjectRef must name the per-session secret incl. its UID, got %+v", ref)
	}

	// Status/AgentNotes must say the permissions are the admin's, not corral's, and point
	// the agent at the one way to discover them — without leaking the token.
	if len(c.Status) != 1 || !strings.Contains(c.Status[0], "pre-provisioned") {
		t.Errorf("Status must flag the RBAC as pre-provisioned, got %v", c.Status)
	}
	if len(c.AgentNotes) != 1 {
		t.Fatalf("expected one AgentNotes line, got %v", c.AgentNotes)
	}
	for _, want := range []string{
		"KUBECONFIG", "https://api.example:6443", "corral-team-a/" + base, "8h",
		"pre-provisioned by the cluster admin", "system:serviceaccounts:corral-team-a",
		"NOT managed by corral", "kubectl auth can-i --list",
	} {
		if !strings.Contains(c.AgentNotes[0], want) {
			t.Errorf("AgentNotes should mention %q: %q", want, c.AgentNotes[0])
		}
	}
	for _, s := range append(append([]string{}, c.Status...), c.AgentNotes[0], c.CleanupHint) {
		if strings.Contains(s, "fake-bearer-token") {
			t.Errorf("the minted token must never be surfaced: %q", s)
		}
	}
	if !strings.Contains(c.CleanupHint, "corral gc") || !strings.Contains(c.CleanupHint, "Secret") {
		t.Errorf("CleanupHint should name the revocation Secret and the `corral gc` backstop: %q", c.CleanupHint)
	}

	// The kubeconfig is the same minimal, parseable artifact as in managed mode.
	data, err := os.ReadFile(c.Mounts[0].Src)
	if err != nil {
		t.Fatalf("kubeconfig not written: %v", err)
	}
	kc, err := clientcmd.Load(data)
	if err != nil {
		t.Fatalf("kubeconfig not parseable: %v", err)
	}
	if ai := kc.AuthInfos["corral"]; ai == nil || ai.Token != "fake-bearer-token" {
		t.Errorf("kubeconfig must carry the minted bearer token, got %+v", ai)
	}
	if ctxt := kc.Contexts["corral"]; ctxt == nil || ctxt.Namespace != "corral-team-a" {
		t.Errorf("kubeconfig context should default to the pre-provisioned namespace, got %+v", ctxt)
	}

	// Cleanup revokes: SA + Secret gone (either kills the token), kubeconfig removed.
	if err := c.Cleanup(ctx); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := cs.CoreV1().ServiceAccounts("corral-team-a").Get(ctx, base, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("cleanup must delete the SA, got %v", err)
	}
	if _, err := cs.CoreV1().Secrets("corral-team-a").Get(ctx, base, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("cleanup must delete the revocation secret (that is the token revocation), got %v", err)
	}
	if _, err := os.Stat(c.Mounts[0].Src); !os.IsNotExist(err) {
		t.Errorf("cleanup must remove the kubeconfig file, got %v", err)
	}
}

// A missing pre-provisioned namespace is fatal: corral must never create it (a namespace
// corral made carries none of the admin's group bindings, so the session would silently
// have no permissions at all).
func TestKubernetesMintPreProvisionedNamespaceMissing(t *testing.T) {
	cfg := Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a"}
	k, cs := fakeK8s(t, cfg) // namespace not seeded
	_, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false)
	if err == nil {
		t.Fatal("Mint must fail closed when the namespace is not pre-provisioned")
	}
	if !strings.Contains(err.Error(), "not pre-provisioned") {
		t.Errorf("the error must be actionable (ask an admin), got %v", err)
	}
	if acts := rbacActions(cs); len(acts) != 0 {
		t.Errorf("a missing namespace must not be created, got %v", acts)
	}
	if sas, _ := cs.CoreV1().ServiceAccounts("corral-team-a").List(context.Background(), metav1.ListOptions{}); len(sas.Items) != 0 {
		t.Errorf("no service account may be created once the namespace check failed, got %d", len(sas.Items))
	}
}

// An unreadable namespace is warn-and-allow: `edit` grants no get on the namespace object,
// so Forbidden says nothing about whether the namespace exists.
func TestKubernetesMintPreProvisionedNamespaceForbidden(t *testing.T) {
	cfg := Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a"}
	k, cs := fakeK8s(t, cfg)
	cs.PrependReactor("get", "namespaces", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "corral-team-a", errors.New("no get on namespaces"))
	})
	stampSecretUID(t, cs, "secret-uid-1")

	c, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false)
	if err != nil {
		t.Fatalf("a forbidden namespace read must warn and proceed, got %v", err)
	}
	if warn := strings.Join(c.Warnings, "\n"); !strings.Contains(warn, "forbidden") || !strings.Contains(warn, "corral-team-a") {
		t.Errorf("the warn-and-allow notice must name the namespace: %q", warn)
	}
	if _, err := cs.CoreV1().ServiceAccounts("corral-team-a").Get(context.Background(), "corral-alice-s1", metav1.GetOptions{}); err != nil {
		t.Errorf("Mint must proceed to create the SA: %v", err)
	}
}

// A failed Mint keeps the warnings gathered before the failure in its error.
func TestKubernetesMintFailureKeepsWarnings(t *testing.T) {
	cfg := Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a"}
	k, cs := fakeK8s(t, cfg)
	cs.PrependReactor("get", "namespaces", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "namespaces"}, "corral-team-a", errors.New("no get on namespaces"))
	})
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewForbidden(schema.GroupResource{Resource: "serviceaccounts"}, "x", errors.New("no create"))
	})

	_, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false)
	if err == nil {
		t.Fatal("Mint must fail when the ServiceAccount cannot be created")
	}
	if !strings.Contains(err.Error(), "create service account") || !strings.Contains(err.Error(), "\nwarning: kubernetes cannot read namespace \"corral-team-a\" (forbidden)") {
		t.Errorf("the error must carry the failure and the pending warning: %q", err)
	}
}

// Fail-closed rollback covers the Secret too: a failed token leaves neither the SA nor the
// revocation handle behind.
func TestKubernetesMintPreProvisionedRollsBack(t *testing.T) {
	cfg := Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a"}
	k, cs := fakeK8s(t, cfg, ns("corral-team-a"))
	stampSecretUID(t, cs, "secret-uid-1")
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "token" {
			return true, nil, errors.New("token minting denied")
		}
		return false, nil, nil
	})
	ctx := context.Background()

	if _, err := k.Mint(ctx, spec.Session{User: "alice", ID: "s1"}, false); err == nil {
		t.Fatal("Mint must fail closed when token minting fails")
	}
	sel := metav1.ListOptions{LabelSelector: labelManaged + "=true"}
	if sas, _ := cs.CoreV1().ServiceAccounts("corral-team-a").List(ctx, sel); len(sas.Items) != 0 {
		t.Errorf("failed Mint must roll back its ServiceAccount, found %d", len(sas.Items))
	}
	if secrets, _ := cs.CoreV1().Secrets("corral-team-a").List(ctx, sel); len(secrets.Items) != 0 {
		t.Errorf("failed Mint must roll back its revocation Secret, found %d", len(secrets.Items))
	}
}

// GC in preProvisioned mode stays inside the one namespace and the two kinds that mode
// creates: a NamespaceAll or cluster-scoped list would only earn a Forbidden for an
// `edit`-scoped identity.
func TestKubernetesGCPreProvisionedScope(t *testing.T) {
	lbls := map[string]string{labelManaged: "true", labelUser: "alice", labelSession: "s1"}
	cfg := Config{Mode: ModePreProvisioned, ServiceAccountNamespace: "corral-team-a"}
	k, cs := fakeK8s(t, cfg,
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-s1", Namespace: "corral-team-a", Labels: lbls}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-s1", Namespace: "corral-team-a", Labels: lbls}},
		// Unmanaged, and managed-but-elsewhere: neither is this config's business.
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "corral-team-a"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "app-secret", Namespace: "corral-team-a"}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "corral-bob-s2", Namespace: "other", Labels: lbls}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-s1-0", Labels: lbls}},
	)
	ctx := context.Background()

	orphans, err := k.GC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 2 {
		t.Fatalf("want 2 orphans (the SA + Secret of the configured namespace), got %d: %+v", len(orphans), orphans)
	}
	for _, o := range orphans {
		if !strings.Contains(o.ID, "|corral-team-a|") {
			t.Errorf("orphan must live in the configured namespace: %q", o.ID)
		}
	}
	for _, a := range cs.Actions() {
		if a.GetVerb() != "list" {
			continue
		}
		if res := a.GetResource().Resource; res != "serviceaccounts" && res != "secrets" {
			t.Errorf("preProvisioned GC must not list %s (cluster-scoped/RBAC rights it lacks)", res)
		}
		if a.GetNamespace() != "corral-team-a" {
			t.Errorf("preProvisioned GC must not list across namespaces, got namespace %q", a.GetNamespace())
		}
	}

	if err := k.Reap(ctx, orphans); err != nil {
		t.Fatalf("reap: %v", err)
	}
	if _, err := cs.CoreV1().Secrets("corral-team-a").Get(ctx, "corral-alice-s1", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("reap must delete the revocation Secret, got %v", err)
	}
	if _, err := cs.CoreV1().Secrets("corral-team-a").Get(ctx, "app-secret", metav1.GetOptions{}); err != nil {
		t.Errorf("reap must not touch unmanaged secrets: %v", err)
	}
	if _, err := cs.CoreV1().ServiceAccounts("other").Get(ctx, "corral-bob-s2", metav1.GetOptions{}); err != nil {
		t.Errorf("reap must not touch another namespace's objects: %v", err)
	}
}

// --- the token's actual expiry (both modes) ---

// The cluster can cap the requested lifetime silently
// (--service-account-max-token-expiration returns only an API warning), so the banner,
// AgentNote and CleanupHint must report status.expirationTimestamp — and a shortened token
// must warn, or the operator sizes the session against a validity it does not have.
func TestKubernetesTokenExpiryFromServer(t *testing.T) {
	serveExpiry := func(cs *fake.Clientset, in time.Duration) {
		cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
			if a.GetSubresource() != "token" {
				return false, nil, nil
			}
			return true, &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{
				Token:               "fake-bearer-token",
				ExpirationTimestamp: metav1.NewTime(time.Now().Add(in)),
			}}, nil
		})
	}

	// Server shortened 8h to 1h: every surface reports 1h, plus a visible warning naming
	// both durations.
	cfg := Config{ServiceAccountNamespace: "corral", TokenLifetime: "8h"}
	k, cs := fakeK8s(t, cfg, ns("corral"))
	serveExpiry(cs, time.Hour)
	c, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	for _, got := range []string{c.Status[0], c.AgentNotes[0], c.CleanupHint} {
		if !strings.Contains(got, "1h0m0s") || strings.Contains(got, "8h") {
			t.Errorf("the server's expiry must replace the requested lifetime, got %q", got)
		}
	}
	if warn := strings.Join(c.Warnings, "\n"); !strings.Contains(warn, "1h0m0s") || !strings.Contains(warn, "8h") {
		t.Errorf("a shortened lifetime must warn with both durations, got %q", warn)
	}

	// Server honored the request: same output as before, and no warning.
	k2, cs2 := fakeK8s(t, cfg, ns("corral"))
	serveExpiry(cs2, 8*time.Hour)
	if c, err = k2.Mint(context.Background(), spec.Session{User: "alice", ID: "s2"}, false); err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if !strings.Contains(c.Status[0], "8h0m0s") {
		t.Errorf("an honored request must report the full lifetime, got %q", c.Status[0])
	}
	if len(c.Warnings) != 0 {
		t.Errorf("an honored request must not warn, got %q", c.Warnings)
	}
}

func TestKubernetesMintNamespaceSelector(t *testing.T) {
	cfg := Config{
		ServiceAccountNamespace: "corral",
		Permissions: []Permission{{
			NamespaceSelector: &LabelSelector{MatchLabels: map[string]string{"team": "platform"}},
			ClusterRole:       "edit",
		}},
	}
	k, cs := fakeK8s(t, cfg,
		ns("corral"),
		nsLabeled("app1", map[string]string{"team": "platform"}),
		nsLabeled("app2", map[string]string{"team": "platform"}),
		nsLabeled("other", map[string]string{"team": "ops"}),
	)
	ctx := context.Background()

	c, err := k.Mint(ctx, spec.Session{User: "bob", ID: "s2"}, false)
	if err != nil {
		t.Fatal(err)
	}
	// The AgentNote names the role and the concretely matched namespaces — only the
	// launcher can resolve the selector, so this is the model's one view of its scope.
	if len(c.AgentNotes) != 1 || !strings.Contains(c.AgentNotes[0], "ClusterRole edit in app1, app2") {
		t.Errorf("AgentNotes should render the namespaced grant, got %v", c.AgentNotes)
	}
	for _, target := range []string{"app1", "app2"} {
		rbs, _ := cs.RbacV1().RoleBindings(target).List(ctx, metav1.ListOptions{})
		if len(rbs.Items) != 1 {
			t.Fatalf("want 1 RoleBinding in matched namespace %s, got %d", target, len(rbs.Items))
		}
		if rbs.Items[0].RoleRef.Kind != "ClusterRole" || rbs.Items[0].RoleRef.Name != "edit" {
			t.Errorf("RoleBinding in %s should reference ClusterRole edit, got %+v", target, rbs.Items[0].RoleRef)
		}
	}
	if rbs, _ := cs.RbacV1().RoleBindings("other").List(ctx, metav1.ListOptions{}); len(rbs.Items) != 0 {
		t.Errorf("unmatched namespace 'other' must get no RoleBinding, got %d", len(rbs.Items))
	}
	if crbs, _ := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); len(crbs.Items) != 0 {
		t.Errorf("a namespaced permission must not create a ClusterRoleBinding, got %d", len(crbs.Items))
	}
}

// TestKubernetesMintBindingRoleRefReplacement locks the concurrent-session isolation
// argument end-to-end through Mint. Two sessions that (cryptographically implausibly)
// collide on a binding name must not corrupt each other — because roleRef is immutable, a
// second Mint carrying a different roleRef under the same name must delete-then-recreate the
// binding, and a third Mint carrying an identical roleRef must be a no-op (no
// delete+recreate).
func TestKubernetesMintBindingRoleRefReplacement(t *testing.T) {
	ctx := context.Background()
	// Same user+session ID across all three Mints → same deterministic resource name
	// (corral-<user>-<session>), forcing the colliding-name path the issue is about.
	sess := spec.Session{User: "alice", ID: "s1"}
	crbName := "corral-alice-s1-0" // base + per-permission index "-0"

	// deletes counts CRB delete actions recorded on the shared clientset, the
	// discriminator between the delete-then-recreate path and the idempotent no-op.
	var cs *fake.Clientset
	deletes := func() int {
		n := 0
		for _, a := range cs.Actions() {
			if a.GetVerb() == "delete" && a.GetResource().Resource == "clusterrolebindings" {
				n++
			}
		}
		return n
	}

	// First session: cluster-wide bind to the `view` ClusterRole.
	viewCfg := Config{
		ServiceAccountNamespace: "corral",
		Permissions:             []Permission{{ClusterWide: true, ClusterRole: "view"}},
	}
	var k1 *k8s
	k1, cs = fakeK8s(t, viewCfg, ns("corral"))
	if _, err := k1.Mint(ctx, sess, false); err != nil {
		t.Fatalf("first Mint: %v", err)
	}
	first, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, crbName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("first Mint must create CRB %s: %v", crbName, err)
	}
	if first.RoleRef.Name != "view" {
		t.Fatalf("first CRB should reference the view ClusterRole, got %q", first.RoleRef.Name)
	}
	if d := deletes(); d != 0 {
		t.Fatalf("a fresh Mint must not delete any CRB, got %d", d)
	}

	// Second session: same name, different roleRef (`edit`). roleRef is immutable, so
	// applyClusterRoleBinding must delete-then-recreate. Reuse k1's connect so both
	// providers act on the same fake cluster (mirrors two real sessions, one cluster).
	editCfg := viewCfg
	editCfg.Permissions = []Permission{{ClusterWide: true, ClusterRole: "edit"}}
	k2 := &k8s{cfg: editCfg, home: k1.home, connect: k1.connect}
	if _, err := k2.Mint(ctx, sess, false); err != nil {
		t.Fatalf("second Mint (roleRef mismatch) must succeed via delete-then-recreate: %v", err)
	}
	crbs, _ := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if len(crbs.Items) != 1 {
		t.Fatalf("replacement must leave exactly one CRB, got %d", len(crbs.Items))
	}
	if got := crbs.Items[0]; got.Name != crbName || got.RoleRef.Name != "edit" {
		t.Errorf("CRB must be replaced in place with the new roleRef, got name=%q roleRef=%q", got.Name, got.RoleRef.Name)
	}
	if d := deletes(); d != 1 {
		t.Errorf("roleRef mismatch must delete the stale CRB exactly once, got %d", d)
	}

	// Third session: same name and same roleRef as the second — must be an idempotent
	// no-op (binding left intact, no further delete+recreate).
	k3 := &k8s{cfg: editCfg, home: k1.home, connect: k1.connect}
	if _, err := k3.Mint(ctx, sess, false); err != nil {
		t.Fatalf("third Mint (identical roleRef) must be a no-op success: %v", err)
	}
	if d := deletes(); d != 1 {
		t.Errorf("an identical re-mint must NOT delete+recreate the CRB, saw %d total deletes (want 1)", d)
	}
	if crbs, _ := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); len(crbs.Items) != 1 || crbs.Items[0].RoleRef.Name != "edit" {
		t.Errorf("identical re-mint must leave the single edit CRB intact, got %+v", crbs.Items)
	}
}

func TestKubernetesEnsuresNamespace(t *testing.T) {
	cfg := Config{ServiceAccountNamespace: "corral", TokenLifetime: "8h"}
	k, cs := fakeK8s(t, cfg) // namespace not seeded
	if _, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false); err != nil {
		t.Fatalf("Mint should create the missing SA namespace: %v", err)
	}
	if _, err := cs.CoreV1().Namespaces().Get(context.Background(), "corral", metav1.GetOptions{}); err != nil {
		t.Errorf("SA namespace must be created when missing: %v", err)
	}
}

func TestKubernetesMintFailClosedRollsBack(t *testing.T) {
	cfg := Config{ServiceAccountNamespace: "corral", TokenLifetime: "8h"}
	k, cs := fakeK8s(t, cfg, ns("corral"))
	// Token minting fails → Mint must fail closed and roll back the SA + CRB it made.
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "token" {
			return true, nil, errors.New("token minting denied")
		}
		return false, nil, nil
	})
	if _, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false); err == nil {
		t.Fatal("Mint must fail closed when token minting fails")
	}
	left, _ := cs.CoreV1().ServiceAccounts("corral").List(context.Background(), metav1.ListOptions{LabelSelector: labelManaged + "=true"})
	if len(left.Items) != 0 {
		t.Errorf("failed Mint must roll back its ServiceAccount, found %d", len(left.Items))
	}
	if crbs, _ := cs.RbacV1().ClusterRoleBindings().List(context.Background(), metav1.ListOptions{}); len(crbs.Items) != 0 {
		t.Errorf("failed Mint must roll back its ClusterRoleBinding, found %d", len(crbs.Items))
	}
}

// A successful TokenRequest that carries an empty token must fail closed (an empty
// bearer token would build a non-functional kubeconfig that only breaks inside the
// sandbox), and must roll back the SA/CRB it already created.
func TestKubernetesMintRejectsEmptyToken(t *testing.T) {
	cfg := Config{ServiceAccountNamespace: "corral", TokenLifetime: "8h"}
	k, cs := fakeK8s(t, cfg, ns("corral"))
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetSubresource() == "token" {
			return true, &authnv1.TokenRequest{Status: authnv1.TokenRequestStatus{Token: ""}}, nil
		}
		return false, nil, nil
	})
	if _, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false); err == nil {
		t.Fatal("Mint must fail closed when the API returns an empty token")
	}
	left, _ := cs.CoreV1().ServiceAccounts("corral").List(context.Background(), metav1.ListOptions{LabelSelector: labelManaged + "=true"})
	if len(left.Items) != 0 {
		t.Errorf("failed Mint must roll back its ServiceAccount, found %d", len(left.Items))
	}
}

// The kubeconfig holds a bearer token, so it must be written 0600 (not group/world
// readable) — it is mounted into the sandbox at its own host path.
func TestKubernetesKubeconfigPerms(t *testing.T) {
	cfg := Config{ServiceAccountNamespace: "corral", TokenLifetime: "8h"}
	k, _ := fakeK8s(t, cfg, ns("corral"))
	c, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, false)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(c.Mounts[0].Src)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("kubeconfig must be 0600 (it carries a bearer token), got %o", perm)
	}
}

func TestKubernetesReaperGCAndReap(t *testing.T) {
	lbls := map[string]string{labelManaged: "true", labelUser: "alice", labelSession: "s1"}
	k, cs := fakeK8s(t, Config{},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-s1", Namespace: "corral", Labels: lbls}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-s1-0", Labels: lbls}},
		&rbacv1.RoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-s1-1", Namespace: "app1", Labels: lbls}},
		// Unmanaged resource — must not be collected or reaped.
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "corral"}},
	)
	ctx := context.Background()

	orphans, err := k.GC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(orphans) != 3 {
		t.Fatalf("want 3 managed orphans (SA + CRB + RB), got %d: %+v", len(orphans), orphans)
	}
	for _, o := range orphans {
		if o.Provider != "kubernetes" || o.ID == "" || o.Describe == "" {
			t.Errorf("malformed orphan: %+v", o)
		}
	}

	if err := k.Reap(ctx, orphans); err != nil {
		t.Fatalf("reap: %v", err)
	}
	if left, _ := cs.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: labelManaged + "=true"}); len(left.Items) != 0 {
		t.Errorf("managed SA not reaped: %d", len(left.Items))
	}
	if crbs, _ := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{}); len(crbs.Items) != 0 {
		t.Errorf("CRB not reaped: %d", len(crbs.Items))
	}
	// The unmanaged SA must survive.
	if _, err := cs.CoreV1().ServiceAccounts("corral").Get(ctx, "default", metav1.GetOptions{}); err != nil {
		t.Errorf("reap must not touch unmanaged resources: %v", err)
	}
}

// A SIGKILLed launcher never runs its in-session Cleanup, so the 0600 kubeconfig holding
// the session's bearer token survives. `corral gc` must remove it along with the cluster
// objects — but only for the sessions the operator approved: a concurrent live session's
// kubeconfig must not be deleted.
func TestKubernetesReapRemovesStaleKubeconfig(t *testing.T) {
	const dead, live = "4711-dead0001", "4712-beef0002"
	deadLbls := map[string]string{labelManaged: "true", labelUser: "alice", labelSession: dead}
	liveLbls := map[string]string{labelManaged: "true", labelUser: "alice", labelSession: live}
	k, cs := fakeK8s(t, Config{},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-" + dead, Namespace: "corral", Labels: deadLbls}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-" + dead + "-0", Labels: deadLbls}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "corral-alice-" + live, Namespace: "corral", Labels: liveLbls}},
	)
	ctx := context.Background()

	deadPath, livePath := kubeconfigPathFor(k.home, dead), kubeconfigPathFor(k.home, live)
	for _, p := range []string{deadPath, livePath} {
		if err := writeKubeconfig(p, []byte("token: fake-bearer-token\n")); err != nil {
			t.Fatal(err)
		}
	}

	orphans, err := k.GC(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Approve the dead session's objects only — the live session is left running.
	var approved []spec.Orphan
	for _, o := range orphans {
		if _, session, err := decodeResource(o.ID); err == nil && session == dead {
			approved = append(approved, o)
		}
	}
	if len(approved) != 2 {
		t.Fatalf("want 2 approved orphans (SA + CRB) for session %s, got %d of %+v", dead, len(approved), orphans)
	}

	if err := k.Reap(ctx, approved); err != nil {
		t.Fatalf("reap: %v", err)
	}
	if _, err := os.Stat(deadPath); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("gc must remove the reaped session's kubeconfig (it holds a bearer token), stat: %v", err)
	}
	if _, err := os.Stat(livePath); err != nil {
		t.Errorf("gc must not touch a non-approved session's kubeconfig: %v", err)
	}
	if _, err := cs.CoreV1().ServiceAccounts("corral").Get(ctx, "corral-alice-"+dead, metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Errorf("approved SA must be reaped, got err %v", err)
	}
	if _, err := cs.CoreV1().ServiceAccounts("corral").Get(ctx, "corral-alice-"+live, metav1.GetOptions{}); err != nil {
		t.Errorf("non-approved SA must survive: %v", err)
	}
	// Reaping again is idempotent: the file is already gone, which is not an error.
	if err := k.Reap(ctx, approved); err != nil {
		t.Errorf("second reap must ignore an already-removed kubeconfig: %v", err)
	}
}

func TestKubernetesImplementsReaper(t *testing.T) {
	if _, ok := New(Config{}, t.TempDir()).(spec.Reaper); !ok {
		t.Error("kubernetes provider must implement Reaper so `corral gc` can collect its orphans")
	}
}

func TestKubernetesAvailable(t *testing.T) {
	// No discoverable kubeconfig → unavailable (skip safely, never error).
	t.Setenv("KUBECONFIG", filepath.Join(t.TempDir(), "does-not-exist"))
	if New(Config{}, t.TempDir()).Available(context.Background()) {
		t.Error("no kubeconfig → provider must be unavailable")
	}
	// A kubeconfig that defines a cluster → available.
	dir := t.TempDir()
	kc := clientcmdapi.NewConfig()
	kc.Clusters["c"] = &clientcmdapi.Cluster{Server: "https://x:6443"}
	data, err := clientcmd.Write(*kc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
	if !New(Config{}, dir).Available(context.Background()) {
		t.Error("a kubeconfig with a cluster → provider must be available")
	}
}

func TestSanitizeDNS(t *testing.T) {
	for in, want := range map[string]string{
		"alice":       "alice",
		"Alice":       "alice",
		"user.name":   "user-name",
		"UPPER_CASE":  "upper-case",
		"--weird--":   "weird",
		"":            "x",
		"123-abcdef0": "123-abcdef0",
	} {
		if got := sanitizeDNS(in); got != want {
			t.Errorf("sanitizeDNS(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestKubernetesMintRejectsSideEffectFree guards the Provider contract: provisioning a
// ServiceAccount + RBAC + token is a sequence of live API calls — irreducible side effects
// — so Mint must fail loudly when asked for a side-effect-free contribution, returning
// before it ever connects to the cluster.
func TestKubernetesMintRejectsSideEffectFree(t *testing.T) {
	k, cs := fakeK8s(t, Config{ServiceAccountNamespace: "corral"}, ns("corral"))

	if _, err := k.Mint(context.Background(), spec.Session{User: "alice", ID: "s1"}, true); err == nil {
		t.Fatal("k8s.Mint must reject dryRun=true (it cannot provision without API calls)")
	}
	// The guard must return before any cluster mutation — no SA/token actions recorded.
	if acts := cs.Actions(); len(acts) != 0 {
		t.Errorf("a side-effect-free Mint must make no API calls, got %d actions", len(acts))
	}
}

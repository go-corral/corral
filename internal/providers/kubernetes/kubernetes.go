// Package kubernetes implements the kubernetes credential-minter provider: a per-session
// ServiceAccount + RBAC bindings with a short-lived TokenRequest token, torn down on exit and
// reapable cross-session via `corral gc`.
package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	// Register client-go's legacy in-tree auth provider plugins (gcp/oidc/azure); modern
	// exec-credential plugins need no import. These run on the host during Mint/GC.
	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"github.com/go-corral/corral/internal/providers/spec"
	"github.com/go-corral/corral/internal/sandbox"
)

// Labels stamped on every corral-provisioned resource so the Reaper rediscovers orphans by label,
// not name-parsing (the minting launcher is long dead by GC time).
const (
	labelManaged = "corral.dev/managed"
	labelUser    = "corral.dev/user"
	labelSession = "corral.dev/session"
)

type k8s struct {
	cfg  Config
	home string
	// workDir anchors a relative kubeconfig.path.
	workDir string
	// approved maps a gated kubeconfig file (see Kubeconfig.Files) to the hex SHA-256 the operator
	// approved.
	approved map[string]string
	// connect returns one cluster's API client and the rest.Config it was built from. Overridable
	// for tests.
	connect func(c ResolvedCluster) (kubernetes.Interface, *rest.Config, error)
}

// New builds the provider. workDir anchors a relative kubeconfig.path. approved maps a kubeconfig
// file (from Kubeconfig.Files(workDir)) to the hex SHA-256 the operator approved; a cluster whose
// file is in it loads only from bytes with that hash.
func New(cfg Config, home, workDir string, approved map[string]string) spec.Provider {
	k := &k8s{cfg: cfg, home: home, workDir: workDir, approved: approved}
	k.connect = k.connectHost
	return k
}

func (k *k8s) Name() string { return "kubernetes" }

// Available reports whether a host kubeconfig defines a cluster. Declared clusters are checked
// one by one in Mint. API reachability is deferred to Mint, which fails the launch closed on
// error (unless optional).
func (k *k8s) Available(ctx context.Context) bool {
	if len(k.cfg.Clusters) > 0 {
		return true
	}
	raw, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil || raw == nil {
		return false
	}
	return len(raw.Clusters) > 0
}

// restConfig loads the cluster's kubeconfig: a gated file from the bytes whose hash matched, any
// other path (or the default loading rules for an empty one) from disk. client-go merges several
// files only when it reads them itself, so a gated file among several fails the load.
func (k *k8s) restConfig(c ResolvedCluster) (*rest.Config, error) {
	overrides := &clientcmd.ConfigOverrides{CurrentContext: c.Kubeconfig.Context}
	files := c.Kubeconfig.Files(k.workDir)
	gated := slices.IndexFunc(files, func(f string) bool { _, ok := k.approved[f]; return ok })
	var cc clientcmd.ClientConfig
	switch {
	case gated >= 0 && len(files) > 1:
		hint := "set kubeconfig.path to the one file this cluster uses"
		if c.Implicit {
			hint = "set KUBECONFIG to one file"
		}
		return nil, fmt.Errorf("load kubeconfig: KUBECONFIG names several files and %s is in a sandbox-writable location; %s", files[gated], hint)
	case gated >= 0:
		raw, err := loadApproved(files[0], k.approved[files[0]])
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig: %w", err)
		}
		cc = clientcmd.NewNonInteractiveClientConfig(*raw, c.Kubeconfig.Context, overrides, nil)
	default:
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		rules.ExplicitPath = c.Kubeconfig.ResolvedPath(k.workDir)
		cc = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)
	}
	rc, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if c.Config.As != "" {
		rc.Impersonate = rest.ImpersonationConfig{UserName: c.Config.As}
	}
	return rc, nil
}

// loadApproved reads the kubeconfig once and parses it only when its hash matches sum, so a file
// changed after the approval gate never reaches the client. An empty sum marks a file without an
// approval for its current content.
func loadApproved(path, sum string) (*clientcmdapi.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("unreadable: %w", err)
	}
	if sum == "" {
		return nil, fmt.Errorf("%s is not approved; `corral run` asks to approve it", path)
	}
	got := sha256.Sum256(data)
	if hex.EncodeToString(got[:]) != sum {
		return nil, fmt.Errorf("%s changed after it was approved; `corral run` asks to approve it again", path)
	}
	raw, err := clientcmd.Load(data)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	// The loading rules resolve relative file references against the kubeconfig's directory.
	for _, a := range raw.AuthInfos {
		a.LocationOfOrigin = path
	}
	for _, cl := range raw.Clusters {
		cl.LocationOfOrigin = path
	}
	if err := clientcmd.ResolveLocalPaths(raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return raw, nil
}

func (k *k8s) connectHost(c ResolvedCluster) (kubernetes.Interface, *rest.Config, error) {
	rc, err := k.restConfig(c)
	if err != nil {
		return nil, nil, err
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, nil, fmt.Errorf("build kubernetes client: %w", err)
	}
	return cs, rc, nil
}

type k8sResource struct {
	kind      string // "ServiceAccount" | "Secret" | "ClusterRoleBinding" | "RoleBinding"
	namespace string // empty for cluster-scoped
	name      string
}

// loadedCluster is a cluster whose kubeconfig loaded in the first phase of Mint.
type loadedCluster struct {
	c  ResolvedCluster
	cs kubernetes.Interface
	rc *rest.Config
}

// mintedCluster is the session identity that mintCluster created on one cluster.
type mintedCluster struct {
	c       ResolvedCluster
	cs      kubernetes.Interface
	created []k8sResource
	context kubeContext
	status  string
	note    string
	hint    string
}

// label prefixes this cluster's errors, warnings, and status lines. The implicit cluster keeps
// the single-cluster text.
func (c ResolvedCluster) label() string {
	if c.Implicit {
		return ""
	}
	return "cluster " + c.Key + ": "
}

// skippable reports whether Mint drops this cluster on failure. The engine already skips an
// optional implicit cluster like any optional provider.
func (c ResolvedCluster) skippable() bool {
	return c.Config.Optional && !c.Implicit
}

// Mint provisions the per-session identity + token on every enabled cluster and returns one
// Contribution with one kubeconfig. It loads every cluster before it mints on any. A required
// cluster's error rolls back every cluster and fails closed; an optional cluster's error rolls
// back that cluster and warns.
func (k *k8s) Mint(ctx context.Context, sess spec.Session, dryRun bool) (*spec.Contribution, error) {
	if dryRun {
		return nil, spec.ErrNoDryRun("kubernetes", "provision a ServiceAccount + token without live API calls")
	}

	var warnings []string
	// A failed Mint returns no Contribution, so its pending warnings travel in the error.
	withWarnings := func(e error) error {
		for _, w := range warnings {
			e = errors.Join(e, errors.New("warning: "+w))
		}
		return e
	}
	skip := func(c ResolvedCluster, err error) {
		warnings = append(warnings, fmt.Sprintf("kubernetes cluster %s skipped (optional): %v", c.Key, err))
	}

	var loaded []loadedCluster
	servers := map[string]string{}
	for _, c := range k.cfg.EffectiveClusters() {
		if !c.Config.Enabled {
			continue
		}
		cs, rc, err := k.connect(c)
		if err != nil {
			if c.skippable() {
				skip(c, err)
				continue
			}
			return nil, withWarnings(fmt.Errorf("%s%w", c.label(), err))
		}
		// One server twice would give both clusters the same corral-<user>-<session> objects. Even
		// with different service-account namespaces, the cluster-scoped ClusterRoleBindings
		// corral-<user>-<session>-<i> collide.
		server := normalizeServer(rc.Host)
		if first, ok := servers[server]; ok {
			return nil, withWarnings(fmt.Errorf("clusters %s and %s use the same API server %s; enable only one of them", first, c.Key, rc.Host))
		}
		servers[server] = c.Key
		loaded = append(loaded, loadedCluster{c: c, cs: cs, rc: rc})
	}

	kubeconfigPath := kubeconfigPathFor(k.home, sess.ID)
	var minted []mintedCluster
	fail := func(e error) (*spec.Contribution, error) {
		rbCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		_ = teardownAll(rbCtx, minted, kubeconfigPath)
		return nil, withWarnings(e)
	}
	for _, l := range loaded {
		m, warn, err := k.mintCluster(ctx, sess, l.c, l.cs, l.rc)
		for _, w := range warn {
			warnings = append(warnings, l.c.label()+w)
		}
		if err != nil {
			if l.c.skippable() {
				skip(l.c, err)
				continue
			}
			return fail(fmt.Errorf("%s%w", l.c.label(), err))
		}
		minted = append(minted, m)
	}
	if len(minted) == 0 {
		return &spec.Contribution{Warnings: warnings}, nil
	}

	var current string
	contexts := make([]kubeContext, len(minted))
	status := make([]string, len(minted))
	notes := make([]string, len(minted))
	hints := make([]string, len(minted))
	for i, m := range minted {
		if m.c.Default {
			current = m.c.Key
		}
		contexts[i] = m.context
		status[i] = m.c.label() + m.status
		notes[i] = m.note
		hints[i] = m.c.label() + m.hint
	}
	kubeconfig, err := buildKubeconfig(contexts, current)
	if err != nil {
		return fail(err)
	}
	if err := writeKubeconfig(kubeconfigPath, kubeconfig); err != nil {
		return fail(err)
	}

	opening := fmt.Sprintf("KUBECONFIG points at a kubeconfig minted for this session with one context per cluster; `kubectl` uses context `%s` unless you pass `--context <name>`:", current)
	if current == "" {
		opening = "KUBECONFIG points at a kubeconfig minted for this session with one context per cluster and no current context, so `kubectl` needs `--context <name>`:"
	}

	cleanup := func(ctx context.Context) error { return teardownAll(ctx, minted, kubeconfigPath) }
	return &spec.Contribution{
		// Own-path read-only mount: macOS Seatbelt cannot bind-remap and denies host $TMPDIR/tmp,
		// so the kubeconfig lives under ~/.cache/corral.
		Mounts:      []sandbox.Mount{{Src: kubeconfigPath, Dst: kubeconfigPath, ReadOnly: true}},
		Env:         map[string]string{"KUBECONFIG": kubeconfigPath},
		Status:      status,
		AgentNotes:  []string{opening + "\n  - " + strings.Join(notes, "\n  - ")},
		CleanupHint: strings.Join(hints, "; "),
		Cleanup:     cleanup,
		Warnings:    warnings,
	}, nil
}

// mintCluster provisions the identity + token on one cluster. On error it rolls back what it
// created on this cluster. It returns the warnings it collected, also on error.
func (k *k8s) mintCluster(ctx context.Context, sess spec.Session, c ResolvedCluster, cs kubernetes.Interface, rc *rest.Config) (mintedCluster, []string, error) {
	cfg := c.Config
	preProvisioned := cfg.EffectiveMode() == ModePreProvisioned
	ns := cfg.EffectiveServiceAccountNamespace()
	// base names the SA and its bindings corral-<user>-<session>. The session ID is
	// <pid>-<4 random hex bytes>, so concurrent launches yield distinct names. GC reaps by label,
	// never by parsing this name; the binding appliers delete-recreate a same-named binding whose
	// immutable roleRef differs rather than failing.
	base := resourceName("corral-" + sanitizeDNS(sess.User) + "-" + sanitizeDNS(sess.ID))
	lbls := map[string]string{
		labelManaged: "true",
		labelUser:    spec.SanitizeLabel(sess.User),
		labelSession: spec.SanitizeLabel(sess.ID),
	}

	var created []k8sResource
	var warnings []string
	fail := func(e error) (mintedCluster, []string, error) {
		rbCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		_ = teardown(rbCtx, cs, created)
		return mintedCluster{}, warnings, e
	}

	if preProvisioned {
		warn, err := k.requireNamespace(ctx, cs, ns)
		if err != nil {
			return fail(err)
		}
		warnings = append(warnings, warn...)
	} else if err := k.ensureNamespace(ctx, cs, ns); err != nil {
		return fail(err)
	}

	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: base, Namespace: ns, Labels: lbls}}
	if _, err := cs.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fail(fmt.Errorf("create service account %s/%s: %w", ns, base, hintRBAC(cfg, ns, err)))
		}
		// A pre-existing SA with this exact per-session name is unexpected; reuse it but do not
		// register it for teardown. Safe because the credential is revoked (short-lived token
		// expires; in preProvisioned mode it's bound to the revocation Secret we create), and the
		// bindings we add are torn down on cleanup. `corral gc` reaps it by label.
	} else {
		created = append(created, k8sResource{"ServiceAccount", ns, base})
	}

	var grants []string
	var boundObject *authnv1.BoundObjectReference
	if preProvisioned {
		// An empty Opaque Secret used purely as a revocation handle: the token binds to it, so
		// deleting it at teardown invalidates the token at once. Created before the TokenRequest
		// because the bind needs its server-assigned UID.
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: base, Namespace: ns, Labels: lbls},
			Type:       corev1.SecretTypeOpaque,
		}
		out, err := cs.CoreV1().Secrets(ns).Create(ctx, secret, metav1.CreateOptions{})
		if err != nil {
			// No AlreadyExists tolerance: adopting a foreign same-named object would hand our
			// revocation handle to someone else.
			return fail(fmt.Errorf("create revocation secret %s/%s (run `corral gc` if a crashed session left one behind): %w", ns, base, hintRBAC(cfg, ns, err)))
		}
		created = append(created, k8sResource{"Secret", ns, base})
		boundObject = &authnv1.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: base, UID: out.UID}
	} else {
		for i, p := range cfg.EffectivePermissions() {
			name := base + "-" + strconv.Itoa(i)
			subj := rbacv1.Subject{Kind: "ServiceAccount", Name: base, Namespace: ns}
			if p.ClusterWide {
				crb := &rbacv1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: name, Labels: lbls},
					RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: p.ClusterRole},
					Subjects:   []rbacv1.Subject{subj},
				}
				if err := k.applyClusterRoleBinding(ctx, cs, crb); err != nil {
					return fail(fmt.Errorf("bind ClusterRole %q cluster-wide: %w", p.ClusterRole, err))
				}
				created = append(created, k8sResource{"ClusterRoleBinding", "", name})
				grants = append(grants, fmt.Sprintf("ClusterRole %s cluster-wide", p.ClusterRole))
				continue
			}
			namespaces, warn, err := k.matchNamespaces(ctx, cs, p.NamespaceSelector)
			if err != nil {
				return fail(err)
			}
			warnings = append(warnings, warn...)
			ref := roleRef(p)
			for _, target := range namespaces {
				rb := &rbacv1.RoleBinding{
					ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: target, Labels: lbls},
					RoleRef:    ref,
					Subjects:   []rbacv1.Subject{subj},
				}
				if err := k.applyRoleBinding(ctx, cs, rb); err != nil {
					return fail(fmt.Errorf("bind %s %q in namespace %q: %w", ref.Kind, ref.Name, target, err))
				}
				created = append(created, k8sResource{"RoleBinding", target, name})
			}
			if len(namespaces) > 0 {
				targets := strings.Join(namespaces, ", ")
				if len(namespaces) > 4 {
					targets = fmt.Sprintf("%d namespaces", len(namespaces))
				}
				grants = append(grants, fmt.Sprintf("%s %s in %s", ref.Kind, ref.Name, targets))
			}
		}
		if len(grants) == 0 {
			grants = append(grants, "no RBAC grants (no namespace matched the selector)")
		}
	}

	// Mint the short-lived token. Audiences omitted on purpose, targeting the API server's
	// default audience (as `kubectl create token` does).
	exp := int64(cfg.EffectiveTokenLifetime().Seconds())
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{ExpirationSeconds: &exp, BoundObjectRef: boundObject}}
	resp, err := cs.CoreV1().ServiceAccounts(ns).CreateToken(ctx, base, tr, metav1.CreateOptions{})
	if err != nil {
		return fail(fmt.Errorf("mint token for %s/%s: %w", ns, base, hintRBAC(cfg, ns, err)))
	}
	if resp.Status.Token == "" {
		return fail(fmt.Errorf("kubernetes API returned an empty token for %s/%s", ns, base))
	}
	requested := cfg.EffectiveTokenLifetime()
	lifetime := tokenValidity(requested, resp)
	if lifetime < requested-time.Minute {
		warnings = append(warnings, fmt.Sprintf("kubernetes shortened the token lifetime to %s (requested %s) — the cluster caps it (--service-account-max-token-expiration)", lifetime, requested))
	}

	cluster, err := kubeCluster(rc)
	if err != nil {
		return fail(err)
	}

	name := "`" + c.Key + "`"
	kubectl := "kubectl --context " + c.Key
	if c.Default {
		name += " (default)"
		kubectl = "kubectl"
	}
	m := mintedCluster{
		c:       c,
		cs:      cs,
		created: created,
		context: kubeContext{name: c.Key, cluster: cluster, namespace: ns, token: resp.Status.Token},
	}
	if preProvisioned {
		m.status = fmt.Sprintf("minted service account %s/%s (token lifetime %s; RBAC pre-provisioned, not managed by corral)", ns, base, lifetime)
		m.note = fmt.Sprintf("%s: API server %s, ServiceAccount %s/%s (token expires in %s). Its permissions are pre-provisioned by the cluster admin — bound to the group system:serviceaccounts:%s, NOT managed by corral and not visible in corral's config — so discover them with `%s auth can-i --list`.",
			name, rc.Host, ns, base, lifetime, ns, kubectl)
		m.hint = fmt.Sprintf("ServiceAccount/revocation Secret for %s/%s may remain; the token dies with either one and expires within its %s lifetime regardless — run `corral gc` to reap them now",
			ns, base, lifetime)
	} else {
		nBindings := 0
		for _, r := range created {
			if strings.HasSuffix(r.kind, "Binding") {
				nBindings++
			}
		}
		m.status = fmt.Sprintf("minted service account %s/%s (token lifetime %s; %d RBAC binding(s))", ns, base, lifetime, nBindings)
		m.note = fmt.Sprintf("%s: API server %s, ServiceAccount %s/%s (token expires in %s), granted %s.",
			name, rc.Host, ns, base, lifetime, strings.Join(grants, "; "))
		m.hint = fmt.Sprintf("ServiceAccount/bindings for %s/%s may remain; the bound token expires within its %s lifetime — run `corral gc` to reap them now",
			ns, base, lifetime)
	}
	return m, warnings, nil
}

// normalizeServer makes API server URLs comparable: lowercase scheme and host, no trailing '/'.
func normalizeServer(host string) string {
	host = strings.TrimRight(host, "/")
	u, err := url.Parse(host)
	if err != nil || u.Host == "" {
		return strings.ToLower(host)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String()
}

// teardownAll tears down every minted cluster and removes the session kubeconfig.
func teardownAll(ctx context.Context, minted []mintedCluster, kubeconfigPath string) error {
	var errs []error
	for _, m := range minted {
		if err := teardown(ctx, m.cs, m.created); err != nil {
			errs = append(errs, fmt.Errorf("%s%w", m.c.label(), err))
		}
	}
	if err := teardown(ctx, nil, nil, kubeconfigPath); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// tokenValidity reports how long the minted token is really valid: the server's
// status.expirationTimestamp if present, else the requested duration. A cluster capping lifetime
// via --service-account-max-token-expiration shortens the request silently. Rounded to the minute
// so the round-trip doesn't look like a cap.
func tokenValidity(requested time.Duration, resp *authnv1.TokenRequest) time.Duration {
	if resp.Status.ExpirationTimestamp.IsZero() {
		return requested
	}
	actual := time.Until(resp.Status.ExpirationTimestamp.Time).Round(time.Minute)
	if actual <= 0 {
		return requested
	}
	return actual
}

// hintRBAC annotates a Forbidden error with the missing RBAC. In preProvisioned mode that is
// the namespace-scoped `edit` role, so name it. Managed mode passes through unchanged.
func hintRBAC(cfg Config, ns string, err error) error {
	if !apierrors.IsForbidden(err) || cfg.EffectiveMode() != ModePreProvisioned {
		return err
	}
	return fmt.Errorf("%w (mode %s needs the namespace-scoped `edit` role — serviceaccounts, secrets, serviceaccounts/token — in namespace %q)", err, ModePreProvisioned, ns)
}

// ensureNamespace gets the SA's namespace, creating it if missing. A namespace created here is
// not rolled back on a later Mint failure and not enumerated by GC: deleting one cascades to every
// object in it and races a concurrent launch sharing it, while an empty leftover is harmless.
func (k *k8s) ensureNamespace(ctx context.Context, cs kubernetes.Interface, ns string) error {
	if _, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{}); err == nil {
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("look up namespace %q: %w", ns, err)
	}
	obj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns, Labels: map[string]string{labelManaged: "true"}}}
	if _, err := cs.CoreV1().Namespaces().Create(ctx, obj, metav1.CreateOptions{}); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		if apierrors.IsForbidden(err) {
			return fmt.Errorf("namespace %q does not exist and creating it is forbidden; set providers.kubernetes.serviceAccountNamespace to an existing namespace: %w", ns, err)
		}
		return fmt.Errorf("create namespace %q: %w", ns, err)
	}
	return nil
}

// requireNamespace checks the pre-provisioned namespace without ever creating it: it carries the
// admin's group binding, so a corral-created one would have no permissions.
// NotFound → fail closed; Forbidden → warn and proceed (edit lacks get on the namespace object,
// so unreadability says nothing about existence — the SA create right after fails closed if missing).
func (k *k8s) requireNamespace(ctx context.Context, cs kubernetes.Interface, ns string) (warnings []string, err error) {
	_, err = cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	switch {
	case err == nil:
		return nil, nil
	case apierrors.IsNotFound(err):
		return nil, fmt.Errorf("namespace %q is not pre-provisioned; ask a cluster admin to create it and bind the target-namespace roles to group system:serviceaccounts:%s, point providers.kubernetes.serviceAccountNamespace at the namespace they prepared, or switch providers.kubernetes.mode to %s", ns, ns, ModeManaged)
	case apierrors.IsForbidden(err):
		return []string{fmt.Sprintf("kubernetes cannot read namespace %q (forbidden) — assuming it is pre-provisioned and continuing", ns)}, nil
	default:
		return nil, fmt.Errorf("look up namespace %q: %w", ns, err)
	}
}

func (k *k8s) matchNamespaces(ctx context.Context, cs kubernetes.Interface, sel *LabelSelector) (names, warnings []string, err error) {
	ls := toLabelSelector(sel)
	selStr, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid namespaceSelector: %w", err)
	}
	if selStr.Empty() {
		warnings = append(warnings, "kubernetes namespaceSelector is empty — binding in ALL namespaces")
	}
	list, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: selStr.String()})
	if err != nil {
		return nil, nil, fmt.Errorf("list namespaces for selector %q: %w", selStr.String(), err)
	}
	for _, n := range list.Items {
		names = append(names, n.Name)
	}
	if len(names) == 0 {
		warnings = append(warnings, fmt.Sprintf("kubernetes namespaceSelector %q matched no namespaces — no bindings created", selStr.String()))
	}
	return names, warnings, nil
}

// bindingClient is the subset of the typed RBAC binding clients that applyBindingImmutableRef needs.
type bindingClient[T any] interface {
	Create(ctx context.Context, obj *T, opts metav1.CreateOptions) (*T, error)
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*T, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
}

// applyBindingImmutableRef create-or-replaces a binding whose roleRef is immutable: create it; if
// one already exists with a different roleRef, delete and recreate it. Shared by the ClusterRoleBinding
// and RoleBinding appliers so the two stay in lockstep.
func applyBindingImmutableRef[T any](ctx context.Context, api bindingClient[T], obj *T, name string, roleRef func(*T) rbacv1.RoleRef) error {
	_, err := api.Create(ctx, obj, metav1.CreateOptions{})
	if err == nil || !apierrors.IsAlreadyExists(err) {
		return err
	}
	old, getErr := api.Get(ctx, name, metav1.GetOptions{})
	if getErr != nil {
		return getErr
	}
	if roleRef(old) == roleRef(obj) {
		return nil
	}
	if err := api.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return err
	}
	_, err = api.Create(ctx, obj, metav1.CreateOptions{})
	return err
}

func (k *k8s) applyClusterRoleBinding(ctx context.Context, cs kubernetes.Interface, crb *rbacv1.ClusterRoleBinding) error {
	return applyBindingImmutableRef(ctx, cs.RbacV1().ClusterRoleBindings(), crb, crb.Name,
		func(b *rbacv1.ClusterRoleBinding) rbacv1.RoleRef { return b.RoleRef })
}

func (k *k8s) applyRoleBinding(ctx context.Context, cs kubernetes.Interface, rb *rbacv1.RoleBinding) error {
	return applyBindingImmutableRef(ctx, cs.RbacV1().RoleBindings(rb.Namespace), rb, rb.Name,
		func(b *rbacv1.RoleBinding) rbacv1.RoleRef { return b.RoleRef })
}

// gcCluster is the cluster that GC and Reap work on: the enabled default cluster, else the first
// enabled cluster in key order. Only the kubeconfigs of enabled clusters pass the trust gate.
func (k *k8s) gcCluster() (ResolvedCluster, error) {
	enabled := slices.DeleteFunc(k.cfg.EffectiveClusters(), func(c ResolvedCluster) bool { return !c.Config.Enabled })
	if len(enabled) == 0 {
		return ResolvedCluster{}, errors.New("no kubernetes cluster is enabled")
	}
	if i := slices.IndexFunc(enabled, func(c ResolvedCluster) bool { return c.Default }); i >= 0 {
		return enabled[i], nil
	}
	return enabled[0], nil
}

// GC lists the corral-managed resources (label corral.dev/managed=true) on gcCluster. It does not
// enumerate Namespaces: deleting one cascades and races a concurrent launch, and an empty leftover
// is harmless. GC never deletes: `corral gc` previews and Reap deletes the operator-approved subset.
func (k *k8s) GC(ctx context.Context) ([]spec.Orphan, error) {
	c, err := k.gcCluster()
	if err != nil {
		return nil, err
	}
	cs, _, err := k.connect(c)
	if err != nil {
		return nil, fmt.Errorf("%s%w", c.label(), err)
	}
	sel := labelManaged + "=true"
	var orphans []spec.Orphan
	add := func(r k8sResource, lbls map[string]string) {
		orphans = append(orphans, spec.Orphan{
			Provider: k.Name(),
			ID:       encodeResource(r, lbls[labelSession]),
			Describe: describeResource(r, lbls),
		})
	}

	if c.Config.EffectiveMode() == ModePreProvisioned {
		// Namespaced lists only: a cross-namespace or cluster-scoped list needs rights this mode
		// lacks, turning `corral gc` into a Forbidden error instead of a preview.
		ns := c.Config.EffectiveServiceAccountNamespace()
		sas, err := cs.CoreV1().ServiceAccounts(ns).List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err != nil {
			return nil, fmt.Errorf("list service accounts in namespace %q: %w", ns, err)
		}
		for _, sa := range sas.Items {
			add(k8sResource{"ServiceAccount", ns, sa.Name}, sa.Labels)
		}
		secrets, err := cs.CoreV1().Secrets(ns).List(ctx, metav1.ListOptions{LabelSelector: sel})
		if err != nil {
			return nil, fmt.Errorf("list secrets in namespace %q: %w", ns, err)
		}
		for _, s := range secrets.Items {
			add(k8sResource{"Secret", ns, s.Name}, s.Labels)
		}
		return orphans, nil
	}

	sas, err := cs.CoreV1().ServiceAccounts(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	for _, sa := range sas.Items {
		add(k8sResource{"ServiceAccount", sa.Namespace, sa.Name}, sa.Labels)
	}
	crbs, err := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, fmt.Errorf("list cluster role bindings: %w", err)
	}
	for _, crb := range crbs.Items {
		add(k8sResource{"ClusterRoleBinding", "", crb.Name}, crb.Labels)
	}
	rbs, err := cs.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, metav1.ListOptions{LabelSelector: sel})
	if err != nil {
		return nil, fmt.Errorf("list role bindings: %w", err)
	}
	for _, rb := range rbs.Items {
		add(k8sResource{"RoleBinding", rb.Namespace, rb.Name}, rb.Labels)
	}
	return orphans, nil
}

// Reap deletes the approved orphans (NotFound ignored) and removes each approved session's minted
// kubeconfig (a SIGKILLed launcher never runs in-session Cleanup, so that 0600 bearer-token file
// outlives the session). Only approved sessions are touched, never the kube/ directory as a whole.
func (k *k8s) Reap(ctx context.Context, approved []spec.Orphan) error {
	c, err := k.gcCluster()
	if err != nil {
		return err
	}
	cs, _, err := k.connect(c)
	if err != nil {
		return fmt.Errorf("%s%w", c.label(), err)
	}
	var resources []k8sResource
	var kubeconfigs []string
	seen := map[string]bool{}
	for _, o := range approved {
		r, session, err := decodeResource(o.ID)
		if err != nil {
			return err
		}
		resources = append(resources, r)
		// One kubeconfig per session, not per resource. A resource carrying no session label is
		// skipped rather than guessed at — sanitizeDNS("") is a valid filename component.
		if session != "" && !seen[session] {
			seen[session] = true
			kubeconfigs = append(kubeconfigs, kubeconfigPathFor(k.home, session))
		}
	}
	return teardown(ctx, cs, resources, kubeconfigs...)
}

// teardown deletes the resources (best-effort, ignoring NotFound) and removes the kubeconfig at
// each path. Used by both in-session Cleanup and Reap. An empty path is skipped.
func teardown(ctx context.Context, cs kubernetes.Interface, resources []k8sResource, kubeconfigPaths ...string) error {
	var errs []string
	for _, r := range resources {
		if err := deleteResource(ctx, cs, r); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Sprintf("%s %s/%s: %v", r.kind, r.namespace, r.name, err))
		}
	}
	for _, kubeconfigPath := range kubeconfigPaths {
		if kubeconfigPath == "" {
			continue
		}
		if err := os.Remove(kubeconfigPath); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("remove %s: %v", kubeconfigPath, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("kubernetes teardown: %s", strings.Join(errs, "; "))
	}
	return nil
}

func deleteResource(ctx context.Context, cs kubernetes.Interface, r k8sResource) error {
	switch r.kind {
	case "ServiceAccount":
		return cs.CoreV1().ServiceAccounts(r.namespace).Delete(ctx, r.name, metav1.DeleteOptions{})
	case "Secret":
		// preProvisioned revocation handle: deleting it invalidates the bound token.
		return cs.CoreV1().Secrets(r.namespace).Delete(ctx, r.name, metav1.DeleteOptions{})
	case "ClusterRoleBinding":
		return cs.RbacV1().ClusterRoleBindings().Delete(ctx, r.name, metav1.DeleteOptions{})
	case "RoleBinding":
		return cs.RbacV1().RoleBindings(r.namespace).Delete(ctx, r.name, metav1.DeleteOptions{})
	default:
		return fmt.Errorf("unknown resource kind %q", r.kind)
	}
}

const rollbackTimeout = 15 * time.Second

func roleRef(p Permission) rbacv1.RoleRef {
	kind := "ClusterRole"
	name := p.ClusterRole
	if p.Role != "" {
		kind = "Role"
		name = p.Role
	}
	return rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: kind, Name: name}
}

func toLabelSelector(sel *LabelSelector) *metav1.LabelSelector {
	if sel == nil {
		return &metav1.LabelSelector{}
	}
	out := &metav1.LabelSelector{MatchLabels: sel.MatchLabels}
	for _, e := range sel.MatchExpressions {
		out.MatchExpressions = append(out.MatchExpressions, metav1.LabelSelectorRequirement{
			Key:      e.Key,
			Operator: metav1.LabelSelectorOperator(e.Operator),
			Values:   e.Values,
		})
	}
	return out
}

// kubeContext is one context of the sandbox kubeconfig, named by the cluster key.
type kubeContext struct {
	name      string
	cluster   *clientcmdapi.Cluster
	namespace string
	token     string
}

// kubeCluster is the sandbox kubeconfig's cluster entry: server + embedded CA. The CA is read from
// CAFile when the host config used a path, since that path won't exist in-sandbox.
func kubeCluster(rc *rest.Config) (*clientcmdapi.Cluster, error) {
	caData := rc.CAData
	if len(caData) == 0 && rc.CAFile != "" {
		b, err := os.ReadFile(rc.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read cluster CA %s: %w", rc.CAFile, err)
		}
		caData = b
	}
	cluster := &clientcmdapi.Cluster{Server: rc.Host}
	if len(caData) > 0 {
		cluster.CertificateAuthorityData = caData
	} else if rc.Insecure {
		cluster.InsecureSkipTLSVerify = true
	}
	return cluster, nil
}

// buildKubeconfig assembles a minimal kubeconfig: per context, a cluster and one user with the
// minted bearer token — no exec plugin, so it works in the sandbox with no host helpers. An empty
// current leaves current-context unset.
func buildKubeconfig(contexts []kubeContext, current string) ([]byte, error) {
	cfg := clientcmdapi.NewConfig()
	for _, c := range contexts {
		cfg.Clusters[c.name] = c.cluster
		cfg.AuthInfos[c.name] = &clientcmdapi.AuthInfo{Token: c.token}
		cfg.Contexts[c.name] = &clientcmdapi.Context{Cluster: c.name, AuthInfo: c.name, Namespace: c.namespace}
	}
	cfg.CurrentContext = current
	out, err := clientcmd.Write(*cfg)
	if err != nil {
		return nil, fmt.Errorf("serialize kubeconfig: %w", err)
	}
	return out, nil
}

func writeKubeconfig(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create kubeconfig dir: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write kubeconfig %s: %w", path, err)
	}
	return nil
}

// kubeconfigPathFor is the host path of a session's minted kubeconfig. Mint writes it and Reap
// reconstructs it from the corral.dev/session label. The filename uses sanitizeDNS(sess.ID), the
// label spec.SanitizeLabel(sess.ID), and sanitizeDNS(SanitizeLabel(id)) == sanitizeDNS(id) for
// every session ID. A path that doesn't round-trip is simply skipped — never names a foreign file.
func kubeconfigPathFor(home, sessionID string) string {
	return filepath.Join(home, ".cache", "corral", "kube", "config-"+sanitizeDNS(sessionID))
}

// encodeResource/decodeResource round-trip a k8sResource plus its session ID through Orphan.ID.
// Neither a DNS-1123 name nor a sanitized label can contain '|'.
func encodeResource(r k8sResource, session string) string {
	return r.kind + "|" + r.namespace + "|" + r.name + "|" + session
}

func decodeResource(id string) (k8sResource, string, error) {
	parts := strings.SplitN(id, "|", 4)
	if len(parts) != 4 {
		return k8sResource{}, "", fmt.Errorf("malformed orphan id %q", id)
	}
	return k8sResource{kind: parts[0], namespace: parts[1], name: parts[2]}, parts[3], nil
}

func describeResource(r k8sResource, lbls map[string]string) string {
	loc := r.name
	if r.namespace != "" {
		loc = r.namespace + "/" + r.name
	}
	return fmt.Sprintf("%s %s (user=%s session=%s)", r.kind, loc, lbls[labelUser], lbls[labelSession])
}

// sanitizeDNS lowercases s, collapses runs of DNS-1123-invalid characters to '-', trims
// leading/trailing '-', and caps length.
func sanitizeDNS(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = strings.Trim(out[:40], "-")
	}
	if out == "" {
		out = "x"
	}
	return out
}

func resourceName(s string) string {
	if len(s) > 253 {
		s = strings.Trim(s[:253], "-")
	}
	return s
}

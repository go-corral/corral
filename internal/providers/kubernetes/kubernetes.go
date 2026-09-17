// Package kubernetes implements the kubernetes credential-minter provider: a per-session
// ServiceAccount + RBAC bindings with a short-lived TokenRequest token, torn down on exit and
// reapable cross-session via `corral gc`.
package kubernetes

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
	// connect returns the API client and the rest.Config it was built from. Overridable for tests.
	connect func() (kubernetes.Interface, *rest.Config, error)
}

func New(cfg Config, home string) spec.Provider {
	k := &k8s{cfg: cfg, home: home}
	k.connect = k.connectHost
	return k
}

func (k *k8s) Name() string { return "kubernetes" }

// Available reports whether a host kubeconfig defines a cluster. API reachability is deferred to
// Mint, which fails the launch closed on error (unless optional).
func (k *k8s) Available(ctx context.Context) bool {
	raw, err := clientcmd.NewDefaultClientConfigLoadingRules().Load()
	if err != nil || raw == nil {
		return false
	}
	return len(raw.Clusters) > 0
}

func (k *k8s) restConfig() (*rest.Config, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, &clientcmd.ConfigOverrides{})
	rc, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("load kubeconfig: %w", err)
	}
	if k.cfg.As != "" {
		rc.Impersonate = rest.ImpersonationConfig{UserName: k.cfg.As}
	}
	return rc, nil
}

func (k *k8s) connectHost() (kubernetes.Interface, *rest.Config, error) {
	rc, err := k.restConfig()
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

// Mint provisions the per-session identity + token and returns the Contribution. On any error it
// rolls back what it created and fails closed.
func (k *k8s) Mint(ctx context.Context, sess spec.Session, dryRun bool) (*spec.Contribution, error) {
	if dryRun {
		return nil, spec.ErrNoDryRun("kubernetes", "provision a ServiceAccount + token without live API calls")
	}
	cs, rc, err := k.connect()
	if err != nil {
		return nil, err
	}

	preProvisioned := k.cfg.EffectiveMode() == ModePreProvisioned
	ns := k.cfg.EffectiveServiceAccountNamespace()
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
	kubeconfigPath := kubeconfigPathFor(k.home, sess.ID)
	fail := func(e error) (*spec.Contribution, error) {
		rbCtx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
		defer cancel()
		_ = teardown(rbCtx, cs, created, kubeconfigPath)
		return nil, e
	}

	if preProvisioned {
		if err := k.requireNamespace(ctx, cs, ns); err != nil {
			return fail(err)
		}
	} else if err := k.ensureNamespace(ctx, cs, ns); err != nil {
		return fail(err)
	}

	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: base, Namespace: ns, Labels: lbls}}
	if _, err := cs.CoreV1().ServiceAccounts(ns).Create(ctx, sa, metav1.CreateOptions{}); err != nil {
		if !apierrors.IsAlreadyExists(err) {
			return fail(fmt.Errorf("create service account %s/%s: %w", ns, base, k.hintRBAC(ns, err)))
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
			return fail(fmt.Errorf("create revocation secret %s/%s (run `corral gc` if a crashed session left one behind): %w", ns, base, k.hintRBAC(ns, err)))
		}
		created = append(created, k8sResource{"Secret", ns, base})
		boundObject = &authnv1.BoundObjectReference{APIVersion: "v1", Kind: "Secret", Name: base, UID: out.UID}
	} else {
		for i, p := range k.cfg.EffectivePermissions() {
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
			namespaces, err := k.matchNamespaces(ctx, cs, p.NamespaceSelector)
			if err != nil {
				return fail(err)
			}
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
	exp := int64(k.cfg.EffectiveTokenLifetime().Seconds())
	tr := &authnv1.TokenRequest{Spec: authnv1.TokenRequestSpec{ExpirationSeconds: &exp, BoundObjectRef: boundObject}}
	resp, err := cs.CoreV1().ServiceAccounts(ns).CreateToken(ctx, base, tr, metav1.CreateOptions{})
	if err != nil {
		return fail(fmt.Errorf("mint token for %s/%s: %w", ns, base, k.hintRBAC(ns, err)))
	}
	if resp.Status.Token == "" {
		return fail(fmt.Errorf("kubernetes API returned an empty token for %s/%s", ns, base))
	}
	lifetime := tokenValidity(k.cfg.EffectiveTokenLifetime(), resp)

	kubeconfig, err := buildKubeconfig(rc, ns, resp.Status.Token)
	if err != nil {
		return fail(err)
	}
	if err := writeKubeconfig(kubeconfigPath, kubeconfig); err != nil {
		return fail(err)
	}

	var status, note, hint string
	if preProvisioned {
		status = fmt.Sprintf("minted service account %s/%s (token lifetime %s; RBAC pre-provisioned, not managed by corral)", ns, base, lifetime)
		note = fmt.Sprintf("KUBECONFIG points at a kubeconfig minted for this session: API server %s, ServiceAccount %s/%s (token expires in %s). Its permissions are pre-provisioned by the cluster admin — bound to the group system:serviceaccounts:%s, NOT managed by corral and not visible in corral's config — so discover them with `kubectl auth can-i --list`.",
			rc.Host, ns, base, lifetime, ns)
		hint = fmt.Sprintf("ServiceAccount/revocation Secret for %s/%s may remain; the token dies with either one and expires within its %s lifetime regardless — run `corral gc` to reap them now",
			ns, base, lifetime)
	} else {
		nBindings := 0
		for _, r := range created {
			if strings.HasSuffix(r.kind, "Binding") {
				nBindings++
			}
		}
		status = fmt.Sprintf("minted service account %s/%s (token lifetime %s; %d RBAC binding(s))", ns, base, lifetime, nBindings)
		note = fmt.Sprintf("KUBECONFIG points at a kubeconfig minted for this session: API server %s, ServiceAccount %s/%s (token expires in %s), granted %s.",
			rc.Host, ns, base, lifetime, strings.Join(grants, "; "))
		hint = fmt.Sprintf("ServiceAccount/bindings for %s/%s may remain; the bound token expires within its %s lifetime — run `corral gc` to reap them now",
			ns, base, lifetime)
	}

	cleanup := func(ctx context.Context) error { return teardown(ctx, cs, created, kubeconfigPath) }
	return &spec.Contribution{
		// Own-path read-only mount: macOS Seatbelt cannot bind-remap and denies host $TMPDIR/tmp,
		// so the kubeconfig lives under ~/.cache/corral.
		Mounts:      []sandbox.Mount{{Src: kubeconfigPath, Dst: kubeconfigPath, ReadOnly: true}},
		Env:         map[string]string{"KUBECONFIG": kubeconfigPath},
		Status:      []string{status},
		AgentNotes:  []string{note},
		CleanupHint: hint,
		Cleanup:     cleanup,
	}, nil
}

// tokenValidity reports how long the minted token is really valid: the server's
// status.expirationTimestamp if present, else the requested duration. A cluster capping lifetime
// via --service-account-max-token-expiration shortens the request silently, so a shortened token
// warns on stderr. Rounded to the minute so the round-trip doesn't look like a cap.
func tokenValidity(requested time.Duration, resp *authnv1.TokenRequest) time.Duration {
	if resp.Status.ExpirationTimestamp.IsZero() {
		return requested
	}
	actual := time.Until(resp.Status.ExpirationTimestamp.Time).Round(time.Minute)
	if actual <= 0 {
		return requested
	}
	if actual < requested-time.Minute {
		fmt.Fprintf(os.Stderr, "corral: kubernetes shortened the token lifetime to %s (requested %s) — the cluster caps it (--service-account-max-token-expiration)\n", actual, requested)
	}
	return actual
}

// hintRBAC annotates a Forbidden error with the missing RBAC. In preProvisioned mode that is
// the namespace-scoped `edit` role, so name it. Managed mode passes through unchanged.
func (k *k8s) hintRBAC(ns string, err error) error {
	if !apierrors.IsForbidden(err) || k.cfg.EffectiveMode() != ModePreProvisioned {
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
func (k *k8s) requireNamespace(ctx context.Context, cs kubernetes.Interface, ns string) error {
	_, err := cs.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
	switch {
	case err == nil:
		return nil
	case apierrors.IsNotFound(err):
		return fmt.Errorf("namespace %q is not pre-provisioned; ask a cluster admin to create it and bind the target-namespace roles to group system:serviceaccounts:%s, point providers.kubernetes.serviceAccountNamespace at the namespace they prepared, or switch providers.kubernetes.mode to %s", ns, ns, ModeManaged)
	case apierrors.IsForbidden(err):
		fmt.Fprintf(os.Stderr, "corral: kubernetes cannot read namespace %q (forbidden) — assuming it is pre-provisioned and continuing\n", ns)
		return nil
	default:
		return fmt.Errorf("look up namespace %q: %w", ns, err)
	}
}

func (k *k8s) matchNamespaces(ctx context.Context, cs kubernetes.Interface, sel *LabelSelector) ([]string, error) {
	ls := toLabelSelector(sel)
	selStr, err := metav1.LabelSelectorAsSelector(ls)
	if err != nil {
		return nil, fmt.Errorf("invalid namespaceSelector: %w", err)
	}
	if selStr.Empty() {
		fmt.Fprintln(os.Stderr, "corral: kubernetes namespaceSelector is empty — binding in ALL namespaces")
	}
	list, err := cs.CoreV1().Namespaces().List(ctx, metav1.ListOptions{LabelSelector: selStr.String()})
	if err != nil {
		return nil, fmt.Errorf("list namespaces for selector %q: %w", selStr.String(), err)
	}
	out := make([]string, 0, len(list.Items))
	for _, n := range list.Items {
		out = append(out, n.Name)
	}
	if len(out) == 0 {
		fmt.Fprintf(os.Stderr, "corral: kubernetes namespaceSelector %q matched no namespaces — no bindings created\n", selStr.String())
	}
	return out, nil
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

// GC lists the corral-managed resources (label corral.dev/managed=true). It does not enumerate
// Namespaces: deleting one cascades and races a concurrent launch, and an empty leftover is
// harmless. GC never deletes: `corral gc` previews and Reap deletes the operator-approved subset.
func (k *k8s) GC(ctx context.Context) ([]spec.Orphan, error) {
	cs, _, err := k.connect()
	if err != nil {
		return nil, err
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

	if k.cfg.EffectiveMode() == ModePreProvisioned {
		// Namespaced lists only: a cross-namespace or cluster-scoped list needs rights this mode
		// lacks, turning `corral gc` into a Forbidden error instead of a preview.
		ns := k.cfg.EffectiveServiceAccountNamespace()
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
	cs, _, err := k.connect()
	if err != nil {
		return err
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

// buildKubeconfig assembles a minimal kubeconfig: cluster (server + embedded CA) and one user with
// the minted bearer token — no exec plugin, so it works in the sandbox with no host helpers. CA is
// embedded (read from CAFile when the host config used a path) since that path won't exist in-sandbox.
func buildKubeconfig(rc *rest.Config, namespace, token string) ([]byte, error) {
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
	cfg := clientcmdapi.NewConfig()
	cfg.Clusters["corral"] = cluster
	cfg.AuthInfos["corral"] = &clientcmdapi.AuthInfo{Token: token}
	cfg.Contexts["corral"] = &clientcmdapi.Context{Cluster: "corral", AuthInfo: "corral", Namespace: namespace}
	cfg.CurrentContext = "corral"
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

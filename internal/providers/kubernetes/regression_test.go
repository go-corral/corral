package kubernetes

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/go-corral/corral/internal/providers/spec"
)

// --- Kubernetes Regression Tests ---

// writeKubeconfig must create the directory 0o700 and the file 0o600 — a token-bearing
// file must not be world-readable.
func TestK8sWriteKubeconfigPerms(t *testing.T) {
	tmpDir := t.TempDir()
	kubeconfigPath := filepath.Join(tmpDir, "nested", "deep", "config")
	kubedata := []byte("apiVersion: v1\nkind: Config\n")

	if err := writeKubeconfig(kubeconfigPath, kubedata); err != nil {
		t.Fatalf("writeKubeconfig: %v", err)
	}

	// Check directory perms (should be 0o700).
	dirPath := filepath.Dir(kubeconfigPath)
	dirInfo, err := os.Stat(dirPath)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	dirPerms := dirInfo.Mode() & os.ModePerm
	if dirPerms != 0o700 {
		t.Errorf("kubeconfig dir perms should be 0o700, got 0o%o", dirPerms)
	}

	// Check file perms (should be 0o600).
	fileInfo, err := os.Stat(kubeconfigPath)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	filePerms := fileInfo.Mode() & os.ModePerm
	if filePerms != 0o600 {
		t.Errorf("kubeconfig file perms should be 0o600, got 0o%o", filePerms)
	}
}

// Input with no alphanumerics (all symbols) filters to 'x' (the fallback).
func TestK8sSanitizeDNSEmpty(t *testing.T) {
	testCases := []string{
		"!!!",      // all symbols
		"-_-",      // only dashes/underscores (invalid in DNS)
		"---",      // only dashes
		"@#$%^&*(", // hostile symbols
	}
	for _, input := range testCases {
		result := sanitizeDNS(input)
		if result != "x" {
			t.Errorf("sanitizeDNS(%q) should return 'x', got %q", input, result)
		}
	}
}

// Input with no valid label characters (only symbols) filters to 'unknown' (the fallback).
func TestK8sSanitizeLabelEmpty(t *testing.T) {
	testCases := []string{
		"!!!",  // all symbols
		"@#$%", // hostile symbols
		"---",  // only dashes (invalid as label)
		"___",  // only underscores (invalid as label start/end)
	}
	for _, input := range testCases {
		result := spec.SanitizeLabel(input)
		if result != "unknown" {
			t.Errorf("spec.SanitizeLabel(%q) should return 'unknown', got %q", input, result)
		}
	}
}

// 100 valid label characters exceed the 63-char limit and truncate to exactly 63.
func TestK8sSanitizeLabelOverlong(t *testing.T) {
	input := strings.Repeat("a", 100)
	result := spec.SanitizeLabel(input)
	if len(result) != 63 {
		t.Errorf("sanitizeLabel result must be exactly 63 chars for overlong alphanumeric input, got %d: %q", len(result), result)
	}
}

// A 300-char assembled resource name exceeds the DNS-1123 subdomain limit of 253 and must
// truncate to <=253 chars.
func TestK8sResourceNameLimit(t *testing.T) {
	input := strings.Repeat("a-", 150) // will be 300 chars (2*150)
	if len(input) <= 253 {
		t.Fatalf("test setup: input must be > 253 chars, got %d", len(input))
	}
	result := resourceName(input)
	if len(result) > 253 {
		t.Errorf("resourceName result must be <=253 chars, got %d: %q", len(result), result)
	}
	// Verify truncation actually happened for over-long input.
	if len(input) > 253 && len(result) >= len(input) {
		t.Errorf("resourceName must truncate input of length %d to <=253 chars, but result has length %d", len(input), len(result))
	}
	// Result should still be a valid DNS name (no trailing dashes).
	if strings.HasSuffix(result, "-") {
		t.Errorf("resourceName must trim trailing dashes, got %q", result)
	}
}

// A rest.Config whose CAFile is set but missing must fail closed — the read error is
// wrapped and returned.
func TestK8sBuildKubeconfigCAFileReadError(t *testing.T) {
	nonexistent := "/path/that/does/not/exist/ca.crt"
	rc := &rest.Config{
		Host: "https://api.example:6443",
		TLSClientConfig: rest.TLSClientConfig{
			CAFile: nonexistent,
		},
	}

	_, err := buildKubeconfig(rc, "default", "fake-token")
	if err == nil {
		t.Fatal("buildKubeconfig must fail closed when CAFile is unreadable")
	}
	if !strings.Contains(err.Error(), "read cluster CA") {
		t.Errorf("error should mention 'read cluster CA', got %v", err)
	}
}

// A rest.Config with neither CAData nor CAFile (an insecure cluster) must set
// InsecureSkipTLSVerify.
func TestK8sBuildKubeconfigInsecureCluster(t *testing.T) {
	rc := &rest.Config{
		Host: "http://api.example:6443",
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: true,
			// No CAData, no CAFile
		},
	}

	kubeconfig, err := buildKubeconfig(rc, "default", "fake-token")
	if err != nil {
		t.Fatalf("buildKubeconfig insecure: %v", err)
	}

	// Parse and verify InsecureSkipTLSVerify is set.
	cfg, err := clientcmd.Load(kubeconfig)
	if err != nil {
		t.Fatalf("parse kubeconfig: %v", err)
	}
	cl := cfg.Clusters["corral"]
	if cl == nil || !cl.InsecureSkipTLSVerify {
		t.Errorf("insecure cluster must set InsecureSkipTLSVerify: %+v", cl)
	}
}

// A ClusterRoleBinding with the same name and same roleRef is idempotent: return nil, no
// delete+recreate.
func TestK8sApplyClusterRoleBindingIdempotent(t *testing.T) {
	cfg := Config{ServiceAccountNamespace: "corral"}
	crb1 := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "test-crb"},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "view"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sa", Namespace: "ns"}},
	}

	k, cs := fakeK8s(t, cfg, crb1)
	ctx := context.Background()

	// Applying the same CRB again should return nil (already exists with same roleRef).
	err := k.applyClusterRoleBinding(ctx, cs, crb1)
	if err != nil {
		t.Errorf("applying an identical CRB should succeed idempotently, got %v", err)
	}

	// Should still have exactly one CRB.
	crbs, _ := cs.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if len(crbs.Items) != 1 {
		t.Errorf("should have 1 CRB after idempotent apply, got %d", len(crbs.Items))
	}
}

// A RoleBinding with a different roleRef (an immutable field) must delete-then-recreate:
// the binding is replaced.
func TestK8sApplyRoleBindingConflict(t *testing.T) {
	cfg := Config{ServiceAccountNamespace: "corral"}
	ns := "test-ns"
	oldRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "test-rb", Namespace: ns},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "old-role"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sa", Namespace: ns}},
	}
	nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}

	k, cs := fakeK8s(t, cfg, oldRB, nsObj)
	ctx := context.Background()

	// Try to apply a new RoleBinding with the same name but different roleRef.
	newRB := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "test-rb", Namespace: ns},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "Role", Name: "new-role"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "sa", Namespace: ns}},
	}

	err := k.applyRoleBinding(ctx, cs, newRB)
	if err != nil {
		t.Errorf("applyRoleBinding conflict resolution: %v", err)
	}

	// The RoleBinding should be replaced with the new one.
	rb, _ := cs.RbacV1().RoleBindings(ns).Get(ctx, "test-rb", metav1.GetOptions{})
	if rb.RoleRef.Name != "new-role" {
		t.Errorf("RoleBinding should be replaced with new roleRef, got %q", rb.RoleRef.Name)
	}
}

// A malformed Orphan.ID (fewer than four |-parts) must return an error so Reap aborts
// safely.
func TestK8sDecodeResourceMalformed(t *testing.T) {
	malformedIDs := []string{
		"ServiceAccount|only-two", // 2 parts, not 4
		"ServiceAccount|ns|name",  // 3 parts: no session field
		"Kind",                    // 1 part
		"",                        // empty
	}

	for _, id := range malformedIDs {
		_, _, err := decodeResource(id)
		if err == nil {
			t.Errorf("decodeResource(%q) must fail closed, got nil", id)
		}
		if !strings.Contains(err.Error(), "malformed") {
			t.Errorf("error should mention 'malformed', got %v", err)
		}
	}
	// A session-less resource encodes as a trailing empty field, not a missing one, so it
	// still decodes: "Kind|ns|name|" is len 4 with session "" (Reap then skips its kubeconfig).
	if _, session, err := decodeResource("ServiceAccount|ns|name|"); err != nil || session != "" {
		t.Errorf("an empty session field must decode, got session %q err %v", session, err)
	}
	// SplitN with max 4 still creates 4 parts even if there are more delimiters.
	// "Kind|ns|name|s|extra" splits into ["Kind", "ns", "name", "s|extra"], which is len 4
	// and valid. This is actually correct — the code doesn't reject it, which is fine.
}

// An unknown resource kind must return an "unknown resource kind" error so teardown/Reap
// abort safely.
func TestK8sDeleteResourceUnknownKind(t *testing.T) {
	cfg := Config{ServiceAccountNamespace: "corral"}
	_, cs := fakeK8s(t, cfg)
	ctx := context.Background()

	unknownResource := k8sResource{kind: "UnknownKind", namespace: "ns", name: "obj"}
	err := deleteResource(ctx, cs, unknownResource)
	if err == nil {
		t.Fatal("deleteResource must fail closed on unknown kind")
	}
	if !strings.Contains(err.Error(), "unknown resource kind") {
		t.Errorf("error should mention 'unknown resource kind', got %v", err)
	}
}

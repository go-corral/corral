package policy_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/config"
	"github.com/go-corral/corral/internal/policy"
)

// TestSecretClassifierMatchesAlwaysBlocked is the drift guard for the coupling documented at
// config.AlwaysBlockedPaths and policy's secretDirComponents/secretDirPairs: the path-segment
// classifier must carry exactly the always-blocked directory names. A name added to the hard block
// but not the classifier would go unrecognized as a secret store outside $HOME; one added only to
// the classifier would flag a directory corral does not hard-block. Both sets are derived here from
// AlwaysBlockedPaths, so this test rather than prose enforces agreement.
func TestSecretClassifierMatchesAlwaysBlocked(t *testing.T) {
	wantComponents := map[string]bool{}
	wantPairs := map[string]bool{}
	for _, p := range config.AlwaysBlockedPaths {
		rel, ok := strings.CutPrefix(p, "~/")
		if !ok {
			t.Fatalf("AlwaysBlockedPaths entry %q is not ~/-relative; the classifier keys off home-relative segments — extend this test if that changes", p)
		}
		segs := strings.Split(strings.ToLower(rel), "/") // the classifier lowercases before lookup
		switch len(segs) {
		case 1:
			wantComponents[segs[0]] = true
		case 2:
			wantPairs[segs[0]+"/"+segs[1]] = true
		default:
			t.Fatalf("AlwaysBlockedPaths entry %q has %d path segments; the classifier models only 1 (secretDirComponents) or 2 (secretDirPairs) — extend both and this test", p, len(segs))
		}
	}

	gotComponents := map[string]bool{}
	for k := range policy.SecretDirComponents {
		gotComponents[k] = true
	}
	gotPairs := map[string]bool{}
	for k := range policy.SecretDirPairs {
		gotPairs[k[0]+"/"+k[1]] = true
	}

	diffSecretSet(t, "secretDirComponents", wantComponents, gotComponents)
	diffSecretSet(t, "secretDirPairs", wantPairs, gotPairs)
}

// diffSecretSet fails when want and got differ, naming both directions so the fix is unambiguous: a
// name in AlwaysBlockedPaths but not the classifier must be added to the classifier; a name in the
// classifier but not AlwaysBlockedPaths must be added to AlwaysBlockedPaths (or dropped from the
// classifier).
func diffSecretSet(t *testing.T, name string, want, got map[string]bool) {
	t.Helper()
	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%s is missing names present in config.AlwaysBlockedPaths: %v — add them to the classifier", name, missing)
	}
	if len(extra) > 0 {
		t.Errorf("%s has names absent from config.AlwaysBlockedPaths: %v — add them to AlwaysBlockedPaths or drop them from the classifier", name, extra)
	}
}

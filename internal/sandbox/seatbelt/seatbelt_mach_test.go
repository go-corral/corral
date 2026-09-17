package seatbelt

import (
	"strings"
	"testing"
)

// Open (opt-out) mach posture: allow-default mach-lookup with the scoped escape denies, never a
// blanket deny.
func TestSeatbeltMachOpenMode(t *testing.T) {
	profile, err := macBackend().profile(withTok(fixedMacSpec(), macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(profile, `(global-name-regex #"^com\.apple\.coreservices\.launchservices")`) {
		t.Error("open mode must keep the LaunchServices escape deny")
	}
	if strings.Contains(profile, "(deny mach-lookup)\n") {
		t.Error("open mode must not deny mach-lookup by default")
	}
}

// Strict mach posture: deny-default mach-lookup re-allowing the embedded allowlist + user additions,
// with the escape/exfil services denied by absence (no allow entry, and the open-mode escape denies
// dropped as redundant).
func TestSeatbeltMachStrictMode(t *testing.T) {
	b := Backend{Path: "sandbox-exec", resolve: noResolve{}, cfg: Config{Mach: Mach{
		Lookup: "strict",
		Allow:  []string{"com.example.custom", "com.example.family.*"},
	}}}
	profile, err := b.profile(withTok(fixedMacSpec(), macTestTokens()))
	if err != nil {
		t.Fatal(err)
	}

	for _, s := range []string{
		`(deny mach-lookup (with message "corral-mach"))`, // deny-default, tagged for log filtering
		"(allow mach-lookup\n",                            // re-allow block
		`(global-name "com.apple.trustd")`,                // an embedded allow (TLS)
		`(global-name "com.example.custom")`,              // user exact entry
		`(global-name-prefix "com.example.family.")`,      // user "*" → prefix
	} {
		if !strings.Contains(profile, s) {
			t.Errorf("strict profile missing %q", s)
		}
	}

	// The escape/exfil services must be denied by absence, not present as allow entries. The
	// explanatory comment legitimately names them, so scope the check to the allow block itself.
	allow := profile[strings.Index(profile, "(allow mach-lookup\n"):]
	allow = allow[:strings.Index(allow, "\n)\n")]
	for _, forbidden := range []string{"appleevents", "launchservicesd", "pasteboard", "metadata.mds", "analyticsd"} {
		if strings.Contains(allow, forbidden) {
			t.Errorf("strict allow block must not contain %q", forbidden)
		}
	}
	// The open-mode multi-line escape deny is redundant under deny-default and must not appear.
	if strings.Contains(profile, "(deny mach-lookup\n") {
		t.Error("strict mode must not emit the open-mode escape deny block")
	}
}

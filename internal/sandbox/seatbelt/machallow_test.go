package seatbelt

import (
	"strings"
	"testing"
)

func TestEmbeddedMachAllowLoads(t *testing.T) {
	got := machAllowlist
	if len(got) == 0 {
		t.Fatal("embedded mach allowlist is empty")
	}
	// A couple of load-bearing services must be present, or TLS/DNS break under strict.
	want := map[string]bool{"com.apple.trustd": false, "com.apple.dnssd.service": false}
	for _, s := range got {
		if _, ok := want[s.Name]; ok {
			want[s.Name] = true
		}
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("embedded allowlist is missing required service %q", n)
		}
	}
}

// TestMachAllowlistExcludesEscapeAndExfilServices is the load-bearing invariant: the strict
// allowlist re-allows services by name, so an entry matching an escape (LaunchServices/appleevents),
// a data-reach (pasteboard/mds), or a telemetry/privacy (analyticsd/contactsd/AddressBook) service
// would silently re-open under strict exactly what strict exists to close. Guard against it drifting in.
func TestMachAllowlistExcludesEscapeAndExfilServices(t *testing.T) {
	forbidden := []string{
		"launchservices", "quarantine", "appleevents", // escape
		"pasteboard", "pboard", "metadata.mds", // data-reach
		"windowserver", "tccd", // screen/input, TCC enforcer
		"analyticsd", "contactsd", "addressbook", // telemetry / privacy
	}
	for _, s := range machAllowlist {
		low := strings.ToLower(s.Name)
		for _, f := range forbidden {
			if strings.Contains(low, f) {
				t.Errorf("strict mach allowlist must not contain %q (matches forbidden %q)", s.Name, f)
			}
		}
	}
}

func TestLoadMachAllowRejects(t *testing.T) {
	cases := map[string]string{
		"empty":         `{"services":[]}`,
		"no name":       `{"services":[{"description":"x"}]}`,
		"no desc":       `{"services":[{"name":"com.apple.x"}]}`,
		"bad kind":      `{"services":[{"name":"com.apple.x","kind":"glob","description":"x"}]}`,
		"whitespace":    `{"services":[{"name":"com.apple x","description":"x"}]}`,
		"quote":         `{"services":[{"name":"com.apple.\"x","description":"x"}]}`,
		"duplicate":     `{"services":[{"name":"com.apple.x","description":"a"},{"name":"com.apple.x","description":"b"}]}`,
		"unknown field": `{"services":[{"name":"com.apple.x","description":"x","archs":["macos"]}]}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadMachAllow([]byte(js)); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}

func TestMachServiceSBPL(t *testing.T) {
	cases := []struct {
		svc  machService
		want string
	}{
		{machService{Name: "com.apple.trustd"}, `(global-name "com.apple.trustd")`},
		{machService{Name: "com.apple.trustd", Kind: "name"}, `(global-name "com.apple.trustd")`},
		{machService{Name: "com.apple.foo.", Kind: "prefix"}, `(global-name-prefix "com.apple.foo.")`},
		{machService{Name: `^com\.apple\.foo`, Kind: "regex"}, `(global-name-regex #"^com\.apple\.foo")`},
	}
	for _, c := range cases {
		if got := c.svc.sbpl(); got != c.want {
			t.Errorf("sbpl(%+v) = %q, want %q", c.svc, got, c.want)
		}
	}
}

func TestMachAllowEntry(t *testing.T) {
	if got := machAllowEntry("com.example.foo"); got.Kind != "name" || got.Name != "com.example.foo" {
		t.Errorf("plain entry = %+v, want name/com.example.foo", got)
	}
	if got := machAllowEntry("com.example.bar.*"); got.Kind != "prefix" || got.Name != "com.example.bar." {
		t.Errorf("wildcard entry = %+v, want prefix/com.example.bar.", got)
	}
}

// A bare "*" (and, defensively, any entry compiling to an empty prefix) must be rejected: it would
// emit (global-name-prefix "") and re-open every mach-lookup under strict. A normal wildcard and a
// plain name still pass.
func TestConfigValidateRejectsMatchAllWildcard(t *testing.T) {
	if err := (Config{Mach: Mach{Lookup: "strict", Allow: []string{"*"}}}).Validate(); err == nil {
		t.Error("bare '*' must be rejected (it matches every Mach service)")
	}
	if err := (Config{Mach: Mach{Lookup: "strict", Allow: []string{"com.apple.foo", "com.apple.bar.*"}}}).Validate(); err != nil {
		t.Errorf("explicit names and a scoped wildcard must pass, got %v", err)
	}
}

package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/audit"
	"github.com/go-corral/corral/internal/providers/block"
	"github.com/go-corral/corral/internal/providers/home"
	"github.com/go-corral/corral/internal/providers/paths"
)

// === P1: always-blocked path drift ===
// Invariant: AlwaysBlockedPaths are always added first, then config
// BlockedPaths deduped. Even if config lists ~/.ssh, result contains exactly
// one ~/.ssh entry; floor presence cannot be negated.

func TestAlwaysBlockedNoDuplicationWhenConfigReplicates(t *testing.T) {
	home := "/home/alice"
	cfg, _, err := loadFrom(t, home, "providers: {block: {directories: [~/.ssh, /data/secrets]}}", "", "")
	if err != nil {
		t.Fatal(err)
	}
	eff := cfg.EffectiveBlockedPaths(home)

	// Count SSH entries: must be exactly 1 (floor + config duplicate de-duped).
	sshCount := 0
	for _, p := range eff {
		if p == "/home/alice/.ssh" {
			sshCount++
		}
	}
	if sshCount != 1 {
		t.Errorf("always-blocked ~/ssh appears %d times in EffectiveBlockedPaths, want 1; dedup failed: %v", sshCount, eff)
	}
}

func TestAlwaysBlockedExpandedBeforeMerge(t *testing.T) {
	home := "/home/bob"
	// Config lists absolute path; floor is tilde. After expansion and dedup,
	// must resolve to the same path.
	cfg, _, err := loadFrom(t, home, "providers: {block: {directories: [/home/bob/.gnupg]}}", "", "")
	if err != nil {
		t.Fatal(err)
	}
	eff := cfg.EffectiveBlockedPaths(home)

	gnupgCount := 0
	for _, p := range eff {
		if p == "/home/bob/.gnupg" {
			gnupgCount++
		}
	}
	if gnupgCount != 1 {
		t.Errorf("absolute ~/.gnupg appears %d times, want 1: %v", gnupgCount, eff)
	}
}

func TestAlwaysBlockedCannotBeNegated(t *testing.T) {
	home := "/home/u"
	// Config grants only one blocked path (not the floor); floor is still present.
	cfg, _, err := loadFrom(t, home, "providers: {block: {directories: [/custom/blocked]}}", "", "")
	if err != nil {
		t.Fatal(err)
	}
	eff := cfg.EffectiveBlockedPaths(home)

	// All three floor paths must be present regardless of what config lists.
	floorPaths := []string{"/home/u/.ssh", "/home/u/.gnupg", "/home/u/.aws"}
	for _, floor := range floorPaths {
		found := false
		for _, p := range eff {
			if p == floor {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("always-blocked path %q missing from EffectiveBlockedPaths: %v", floor, eff)
		}
	}
}

// === P2: always-blocked path validation ===
// Invariant: Any path under ~/.ssh, ~/.gnupg, or ~/.aws is rejected by
// Validate with an 'overlaps the always-blocked path' error.

func TestAlwaysBlockedPathGrantRejected(t *testing.T) {
	home := "/home/u"
	// Attempt to grant a path nested under a floor directory.
	for _, path := range []string{"~/.ssh/config", "~/.gnupg/keys", "~/.aws/credentials"} {
		if _, _, err := loadFrom(t, home, "providers:\n  paths:\n    rw: ["+path+"]\n", "", ""); err == nil ||
			!strings.Contains(err.Error(), "always-blocked path") {
			t.Errorf("path %q under an always-blocked dir should be rejected with an 'always-blocked path' error, got %v", path, err)
		}
	}
}

func TestAlwaysBlockedAbsolutePathGrantRejected(t *testing.T) {
	home := "/home/u"
	// Same test but with absolute paths (after expansion, they must still fail).
	if _, _, err := loadFrom(t, home, "providers:\n  paths:\n    ro: [/home/u/.ssh/authorized_keys]\n", "", ""); err == nil ||
		!strings.Contains(err.Error(), "always-blocked path") {
		t.Fatalf("absolute path /home/u/.ssh/authorized_keys should be rejected, got %v", err)
	}
}

// === P2b: the floor mask follows a symlinked floor dir ===
// Invariant: when a floor dir is itself a host symlink (dotfiles-managed ~/.ssh), the FS
// mask covers its real path too — otherwise an unrelated grant that reaches the target
// re-exposes the secrets under their real name, on both backends. The hook cannot cover
// this case (inside the sandbox the floor path is an empty tmpfs / denied, so there is no
// symlink left to follow), which makes the mask the authoritative layer here.

func TestAlwaysBlockedMaskFollowsSymlinkedDir(t *testing.T) {
	home := t.TempDir()
	real := filepath.Join(home, "dotfiles", "ssh")
	if err := os.MkdirAll(real, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(home, ".ssh")); err != nil {
		t.Fatal(err)
	}
	// t.TempDir can itself sit under a symlink (macOS /var/folders), so compare resolved.
	wantReal, err := filepath.EvalSymlinks(real)
	if err != nil {
		t.Fatal(err)
	}

	mask := AlwaysBlockedMaskPaths(home)
	if !slices.Contains(mask, filepath.Join(home, ".ssh")) {
		t.Errorf("mask must keep the lexical floor path; got %v", mask)
	}
	if !slices.Contains(mask, wantReal) {
		t.Errorf("mask must also cover the symlink target %q; got %v", wantReal, mask)
	}
	// The floor itself is never shortened — config can only add to it.
	for _, p := range AlwaysBlockedExpanded(home) {
		if !slices.Contains(mask, p) {
			t.Errorf("mask dropped floor path %q; got %v", p, mask)
		}
	}
}

// A floor with no symlinks must produce exactly the lexical floor: the resolved form is
// de-duplicated away, so the generated bwrap argv / SBPL profile stays byte-identical for
// every normal home (this is what keeps the goldens from moving).
func TestAlwaysBlockedMaskIdenticalWhenNoSymlinks(t *testing.T) {
	// On macOS t.TempDir() sits under /var, a firmlink to /private/var, so the mask emits both
	// the lexical and resolved paths. Resolve the base to exercise the no-symlink case the test
	// name promises; on Linux EvalSymlinks is a no-op.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{".ssh", ".gnupg", ".aws"} {
		if err := os.Mkdir(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := AlwaysBlockedMaskPaths(home), AlwaysBlockedExpanded(home); !slices.Equal(got, want) {
		t.Errorf("AlwaysBlockedMaskPaths = %v, want the plain floor %v", got, want)
	}
}

// A floor dir that does not exist at all resolves to itself — no phantom entries, no
// duplicates (this is the common case for ~/.aws on most hosts).
func TestAlwaysBlockedMaskAbsentDirs(t *testing.T) {
	home := t.TempDir()
	if got, want := AlwaysBlockedMaskPaths(home), AlwaysBlockedExpanded(home); !slices.Equal(got, want) {
		t.Errorf("AlwaysBlockedMaskPaths = %v, want the plain floor %v", got, want)
	}
}

// === P5: always-blocked paths covered ===
// Invariant: AlwaysBlockedExpanded(home) returns the full always-blocked set,
// absolute and expanded — SSH, GPG, the three cloud CLIs, and kubeconfig. Pinned
// as literals so an accidental removal from the set fails loudly here.

func TestAlwaysBlockedExpansion(t *testing.T) {
	home := "/home/alice"
	floorPaths := AlwaysBlockedExpanded(home)

	if len(floorPaths) != 6 {
		t.Fatalf("AlwaysBlockedExpanded must return 6 paths, got %d: %v", len(floorPaths), floorPaths)
	}

	expected := []string{
		"/home/alice/.ssh",
		"/home/alice/.gnupg",
		"/home/alice/.aws",
		"/home/alice/.kube",
		"/home/alice/.config/gcloud",
		"/home/alice/.azure",
	}
	for _, exp := range expected {
		found := false
		for _, p := range floorPaths {
			if p == exp {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AlwaysBlockedExpanded missing %q: %v", exp, floorPaths)
		}
	}
}

func TestAlwaysBlockedAbsolute(t *testing.T) {
	home := "/tmp/testcorral"
	floorPaths := AlwaysBlockedExpanded(home)

	for _, p := range floorPaths {
		if !filepath.IsAbs(p) {
			t.Errorf("AlwaysBlockedExpanded must return absolute paths, got %q", p)
		}
		if strings.Contains(p, "~") {
			t.Errorf("AlwaysBlockedExpanded must expand tilde, got %q", p)
		}
	}
}

// === P3: always-blocked overlap rejection is prefix-safe (gate level) ===
// Invariant: Config.Validate rejects a paths grant that is equal to or nested under an
// always-blocked dir, but must not reject a mere prefix-sibling (~/.ssh-backup is not
// ~/.ssh). This drives the real gate (not the containment helper in isolation) so the
// prefix-safety guarantee is locked where it matters; the helper itself is covered by
// pathutil.TestAtOrUnder. The nested case is also covered by TestAlwaysBlockedPathGrantRejected.
func TestAlwaysBlockedOverlapPrefixSafe(t *testing.T) {
	for _, tc := range []struct {
		name     string
		grant    string // a paths.rw entry, ~-expanded against /home/u
		rejected bool
	}{
		{"equal-to-floor", "~/.ssh", true},
		{"nested-under-floor", "~/.ssh/keys", true},
		{"prefix-sibling-allowed", "~/.ssh-backup", false},
	} {
		_, _, err := loadFrom(t, "/home/u", "providers:\n  paths:\n    rw: ["+tc.grant+"]\n", "", "")
		overlaps := err != nil && strings.Contains(err.Error(), "always-blocked path")
		if overlaps != tc.rejected {
			t.Errorf("%s: paths.rw %q always-blocked overlap rejected=%v, want %v (err=%v)", tc.name, tc.grant, overlaps, tc.rejected, err)
		}
	}
}

// === P4: expandTilde absolute path handling ===
// Invariant: expandTilde('~', home) == home;
// expandTilde('~/file', home) == home+'/file';
// expandTilde('/abs', home) == '/abs';
// expandTilde('~user/x', home) == '~user/x' (unchanged, not a user-expansion tool).

func TestExpandTilde(t *testing.T) {
	home := "/home/u"
	for _, tc := range []struct {
		path string
		want string
	}{
		{"~", "/home/u"},
		{"~/file", "/home/u/file"},
		{"~/dir/subfile", "/home/u/dir/subfile"},
		{"/abs/path", "/abs/path"},
		{"rel/path", "rel/path"},
		{"~user/x", "~user/x"},
		{"~root/.bashrc", "~root/.bashrc"},
		{"", ""},
	} {
		got := expandTilde(tc.path, home)
		if got != tc.want {
			t.Errorf("expandTilde(%q, %q) = %q, want %q", tc.path, home, got, tc.want)
		}
	}
}

// === P8: Audit path relative validation ===
// Invariant: policy.audit.path with relative path is rejected;
// absolute path is accepted; empty string is accepted.

func TestAuditPathRelativeRejected(t *testing.T) {
	for _, relPath := range []string{"logs/file.jsonl", "audit.jsonl", "var/log/corral.jsonl"} {
		yml := "policy:\n  audit:\n    path: " + relPath + "\n"
		if _, _, err := loadFrom(t, "/home/u", yml, "", ""); err == nil ||
			!strings.Contains(err.Error(), "absolute") {
			t.Errorf("relative audit path %q should be rejected, got %v", relPath, err)
		}
	}
}

func TestAuditPathAbsoluteAccepted(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "policy:\n  audit:\n    path: /var/log/corral.jsonl\n", "", ""); err != nil {
		t.Errorf("absolute audit path should be accepted, got %v", err)
	}
}

func TestAuditPathEmptyAccepted(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "policy:\n  audit:\n    path: \"\"\n", "", ""); err != nil {
		t.Errorf("empty audit path should be accepted, got %v", err)
	}
}

// === P9: Home provider path relative validation ===
// Invariant: providers.home.path with relative path is rejected;
// absolute path is accepted; empty string is accepted.

func TestHomePathRelativeRejected(t *testing.T) {
	for _, relPath := range []string{"my-home", "cache/home", ".cache/corral/home"} {
		yml := "providers:\n  home:\n    path: " + relPath + "\n"
		if _, _, err := loadFrom(t, "/home/u", yml, "", ""); err == nil ||
			!strings.Contains(err.Error(), "absolute") {
			t.Errorf("relative home path %q should be rejected, got %v", relPath, err)
		}
	}
}

func TestHomePathAbsoluteAccepted(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "providers:\n  home:\n    path: /cache/home\n", "", ""); err != nil {
		t.Errorf("absolute home path should be accepted, got %v", err)
	}
}

func TestHomePathEmptyAccepted(t *testing.T) {
	if _, _, err := loadFrom(t, "/home/u", "providers:\n  home:\n    path: \"\"\n", "", ""); err != nil {
		t.Errorf("empty home path should be accepted, got %v", err)
	}
}

// === P12: Kubernetes permission validation loop ===
// Invariant: Invalid permission entry fails validation with error mentioning
// the index (e.g., 'permissions[0]').

func TestKubernetesPermissionValidationIndex(t *testing.T) {
	yml := `providers:
  kubernetes:
    enabled: true
    permissions:
      - clusterWide: true
        clusterRole: view
      - clusterWide: true
        role: invalid
`
	_, _, err := loadFrom(t, "/home/u", yml, "", "")
	if err == nil {
		t.Fatal("expected validation error for invalid permission entry")
	}
	// Error should mention the index.
	if !strings.Contains(err.Error(), "permissions[1]") {
		t.Errorf("error should mention 'permissions[1]', got: %v", err)
	}
}

func TestKubernetesPermissionValidationFirstEntry(t *testing.T) {
	yml := `providers:
  kubernetes:
    enabled: true
    permissions:
      - clusterWide: false
        namespaceSelector: null
        clusterRole: view
`
	_, _, err := loadFrom(t, "/home/u", yml, "", "")
	if err == nil {
		t.Fatal("expected validation error for invalid first permission")
	}
	if !strings.Contains(err.Error(), "permissions[0]") {
		t.Errorf("error should mention 'permissions[0]', got: %v", err)
	}
}

// === P10: Load default global path with XDG_CONFIG_HOME ===
// Invariant: With XDG_CONFIG_HOME set, defaultGlobalPath returns
// $XDG_CONFIG_HOME/corral/config.yml; unset, returns home/.config/corral/config.yml.

func TestDefaultGlobalPathWithXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/etc/xdg")
	got := defaultGlobalPath("/home/alice")
	want := "/etc/xdg/corral/config.yml"
	if got != want {
		t.Errorf("defaultGlobalPath with XDG_CONFIG_HOME set = %q, want %q", got, want)
	}
}

func TestDefaultGlobalPathWithoutXDG(t *testing.T) {
	// defaultGlobalPath treats an empty XDG_CONFIG_HOME as unset; t.Setenv restores it.
	t.Setenv("XDG_CONFIG_HOME", "")
	got := defaultGlobalPath("/home/alice")
	want := "/home/alice/.config/corral/config.yml"
	if got != want {
		t.Errorf("defaultGlobalPath without XDG_CONFIG_HOME = %q, want %q", got, want)
	}
}

// === P13: parseYAMLMap empty and whitespace cases ===
// Invariant: parseYAMLMap([]byte('')) returns map[string]any{};
// parseYAMLMap([]byte('   \n  ')) returns map[string]any{}.

func TestParseYAMLMapEmpty(t *testing.T) {
	m, err := parseYAMLMap([]byte(""))
	if err != nil {
		t.Fatalf("parseYAMLMap empty should not error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("parseYAMLMap empty = %v, want empty map", m)
	}
}

func TestParseYAMLMapWhitespace(t *testing.T) {
	m, err := parseYAMLMap([]byte("   \n  \t  \n"))
	if err != nil {
		t.Fatalf("parseYAMLMap whitespace should not error: %v", err)
	}
	if len(m) != 0 {
		t.Errorf("parseYAMLMap whitespace = %v, want empty map", m)
	}
}

// === P11: Load home fallback with os.UserHomeDir ===
// Invariant: Load(LoadOptions{}) with valid $HOME succeeds;
// error from UserHomeDir is returned as 'resolve home' error.

func TestLoadHomeFallbackSuccess(t *testing.T) {
	dir := t.TempDir()
	// Create a config with a tilde path to verify the fallback home is used for expansion.
	globalYAML := "providers:\n  paths:\n    rw: [~/work]\n"
	if err := os.WriteFile(filepath.Join(dir, "global.yml"), []byte(globalYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	// Load with no Home option: should resolve from os.UserHomeDir() and expand paths.
	cfg, _, err := Load(LoadOptions{
		GlobalPath: filepath.Join(dir, "global.yml"),
		ProjectDir: dir,
	})
	if err != nil {
		t.Fatalf("Load with fallback home should succeed, got error: %v", err)
	}
	if cfg == nil {
		t.Fatal("Load succeeded but returned nil config")
	}
	// Verify that paths were expanded using the fallback home.
	// If the fallback worked, RW[0] should be an absolute path starting with /home or /root.
	if len(cfg.Providers.Paths.RW) != 1 {
		t.Errorf("expected 1 RW path, got %d", len(cfg.Providers.Paths.RW))
	}
	if !filepath.IsAbs(cfg.Providers.Paths.RW[0]) {
		t.Errorf("fallback home not used: RW[0] is not absolute: %q", cfg.Providers.Paths.RW[0])
	}
	if !strings.Contains(cfg.Providers.Paths.RW[0], "work") {
		t.Errorf("tilde expansion failed: RW[0] does not contain 'work': %q", cfg.Providers.Paths.RW[0])
	}
}

// === Additional regression: parseYAMLMap with valid content ===
// Ensure parseYAMLMap correctly parses valid YAML.

func TestParseYAMLMapValid(t *testing.T) {
	yml := []byte("hostname: test\nnet: open\n")
	m, err := parseYAMLMap(yml)
	if err != nil {
		t.Fatalf("parseYAMLMap valid YAML should not error: %v", err)
	}
	if m["hostname"] != "test" || m["net"] != "open" {
		t.Errorf("parseYAMLMap parsed incorrectly: %v", m)
	}
}

// === Additional regression: expandPaths mutation ===
// Ensure expandPaths correctly expands and cleans all path fields.

func TestExpandPathsInPlace(t *testing.T) {
	homeDir := "/home/alice"
	cfg := &Config{
		Policy: Policy{
			SecretScan: SecretScan{
				SkipPaths: []string{"~/vault/"},
			},
			Audit: audit.Config{
				Path: "~/logs/audit.jsonl",
			},
		},
		Providers: Providers{
			Paths: paths.Config{
				RW: []string{"~/work", "/abs/path/"},
				RO: []string{"~/read", "/other/"},
			},
			Block: block.Config{Directories: []string{"~/.ssh/../.ssh", "/blocked/"}},
			Home: home.Config{
				Path: "~/.cache/corral/home",
			},
		},
	}
	cfg.expandPaths(homeDir)

	// Check Paths.RW
	if len(cfg.Providers.Paths.RW) != 2 {
		t.Fatalf("Paths.RW has %d entries, want 2", len(cfg.Providers.Paths.RW))
	}
	if cfg.Providers.Paths.RW[0] != "/home/alice/work" {
		t.Errorf("Paths.RW[0] not expanded: got %q, want /home/alice/work", cfg.Providers.Paths.RW[0])
	}
	if cfg.Providers.Paths.RW[1] != "/abs/path" {
		t.Errorf("Paths.RW[1] not cleaned: got %q, want /abs/path", cfg.Providers.Paths.RW[1])
	}

	// Check Paths.RO
	if len(cfg.Providers.Paths.RO) != 2 {
		t.Fatalf("Paths.RO has %d entries, want 2", len(cfg.Providers.Paths.RO))
	}
	if cfg.Providers.Paths.RO[0] != "/home/alice/read" {
		t.Errorf("Paths.RO[0] not expanded: got %q, want /home/alice/read", cfg.Providers.Paths.RO[0])
	}
	if cfg.Providers.Paths.RO[1] != "/other" {
		t.Errorf("Paths.RO[1] not cleaned: got %q, want /other", cfg.Providers.Paths.RO[1])
	}

	// Check Block.Directories
	if len(cfg.Providers.Block.Directories) != 2 {
		t.Fatalf("Block.Directories has %d entries, want 2", len(cfg.Providers.Block.Directories))
	}
	if cfg.Providers.Block.Directories[0] != "/home/alice/.ssh" {
		t.Errorf("Block.Directories[0] not expanded/cleaned: got %q, want /home/alice/.ssh", cfg.Providers.Block.Directories[0])
	}
	if cfg.Providers.Block.Directories[1] != "/blocked" {
		t.Errorf("Block.Directories[1] not cleaned: got %q, want /blocked", cfg.Providers.Block.Directories[1])
	}

	// Check Policy.SecretScan.SkipPaths
	if len(cfg.Policy.SecretScan.SkipPaths) != 1 {
		t.Fatalf("SkipPaths has %d entries, want 1", len(cfg.Policy.SecretScan.SkipPaths))
	}
	if cfg.Policy.SecretScan.SkipPaths[0] != "/home/alice/vault" {
		t.Errorf("SkipPaths[0] not expanded: got %q, want /home/alice/vault", cfg.Policy.SecretScan.SkipPaths[0])
	}

	// Check Policy.Audit.Path
	if cfg.Policy.Audit.Path != "/home/alice/logs/audit.jsonl" {
		t.Errorf("Audit.Path not expanded: got %q, want /home/alice/logs/audit.jsonl", cfg.Policy.Audit.Path)
	}

	// Check Providers.Home.Path
	if cfg.Providers.Home.Path != "/home/alice/.cache/corral/home" {
		t.Errorf("Home.Path not expanded: got %q, want /home/alice/.cache/corral/home", cfg.Providers.Home.Path)
	}
}

// === Additional regression: EffectiveBlockedPaths ordering ===
// Invariant: Floor paths come first, then config paths, no duplicates.

func TestEffectiveBlockedPathsOrdering(t *testing.T) {
	home := "/home/u"
	cfg := &Config{
		Providers: Providers{Block: block.Config{Directories: []string{"~/.ssh", "/custom1", "/custom2"}}},
	}
	eff := cfg.EffectiveBlockedPaths(home)

	// Floor must come before custom paths.
	floorIdx := -1
	customIdx := -1
	for i, p := range eff {
		if p == "/home/u/.ssh" {
			floorIdx = i
		}
		if p == "/custom1" {
			customIdx = i
		}
	}
	if floorIdx == -1 || customIdx == -1 {
		t.Errorf("floor or custom path missing: %v", eff)
	}
	if floorIdx >= customIdx {
		t.Errorf("floor path should come before custom paths: %v", eff)
	}
}

// === Additional regression: EffectiveBlockedPaths empty config ===
// When config has no BlockedPaths, result is just the floor.

func TestEffectiveBlockedPathsFloorOnly(t *testing.T) {
	home := "/home/alice"
	cfg := &Config{Providers: Providers{Block: block.Config{Directories: []string{}}}}
	eff := cfg.EffectiveBlockedPaths(home)

	if len(eff) != 6 {
		t.Errorf("empty config should yield the always-blocked set only (6 paths), got %d: %v", len(eff), eff)
	}

	expected := map[string]bool{
		"/home/alice/.ssh":           true,
		"/home/alice/.gnupg":         true,
		"/home/alice/.aws":           true,
		"/home/alice/.kube":          true,
		"/home/alice/.config/gcloud": true,
		"/home/alice/.azure":         true,
	}
	for _, p := range eff {
		if !expected[p] {
			t.Errorf("unexpected path in floor-only result: %q", p)
		}
	}
}

// === Phase 1 file blocking: block.{directories,files} split accessors ===
// The FS mask consumes the floor (DefaultSpec) and the config dirs/files (block
// provider) separately; the hook deny roots consume the union. A file must never
// land in the dir set, and the floor must never leak into the config-only sets.

func TestEffectiveBlockedSplit(t *testing.T) {
	home := "/home/u"
	cfg := &Config{Providers: Providers{Block: block.Config{
		Directories: []string{"/custom/dir"},
		Files:       []string{"/repo/.env", "/repo/config.local"},
	}}}

	dirs := cfg.ConfigBlockedDirs(home)
	if len(dirs) != 1 || !containsStr(dirs, "/custom/dir") {
		t.Errorf("ConfigBlockedDirs must be exactly the config-added dirs (the floor is DefaultSpec's, not the provider's): %v", dirs)
	}
	if containsStr(dirs, "/repo/.env") {
		t.Errorf("ConfigBlockedDirs must not contain a file: %v", dirs)
	}

	files := cfg.ConfigBlockedFiles(home)
	if len(files) != 2 || !containsStr(files, "/repo/.env") {
		t.Errorf("ConfigBlockedFiles wrong: %v", files)
	}
	if containsStr(files, "/home/u/.ssh") {
		t.Errorf("the directory-only floor must not appear in ConfigBlockedFiles: %v", files)
	}

	all := cfg.EffectiveBlockedPaths(home)
	for _, want := range []string{"/home/u/.ssh", "/custom/dir", "/repo/.env", "/repo/config.local"} {
		if !containsStr(all, want) {
			t.Errorf("EffectiveBlockedPaths (hook deny roots) missing %q: %v", want, all)
		}
	}
}

// A block.files entry at/under an always-blocked directory is redundant (the mask covers
// the whole tree) and signals a mistake; Validate rejects it.
func TestBlockFileUnderAlwaysBlockedDirRejected(t *testing.T) {
	_, _, err := loadFrom(t, "/home/u", "providers: {block: {files: [~/.ssh/id_rsa]}}", "", "")
	if err == nil || !strings.Contains(err.Error(), "always-blocked path") {
		t.Fatalf("block.files under an always-blocked path must be rejected, got %v", err)
	}
}

// aiignore.sources merges additively over the built-in defaults (config can add a borrowed
// source like .gitignore but never drop a default); EffectiveSources surfaces the union.
func TestAIIgnoreSourcesAdditiveMerge(t *testing.T) {
	cfg, _, err := loadFrom(t, "/home/u", "providers: {aiignore: {sources: [.gitignore]}}", "", "")
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.Providers.AIIgnore.EffectiveSources()
	for _, want := range []string{".aiignore", ".aiexclude", ".gitignore"} {
		if !containsStr(got, want) {
			t.Errorf("EffectiveSources missing %q: %v", want, got)
		}
	}
}

// An aiignore.sources entry with a path separator can never match a walked-up filename, so
// it is rejected rather than silently never-matching.
func TestAIIgnoreSourceFilenameValidation(t *testing.T) {
	_, _, err := loadFrom(t, "/home/u", "providers: {aiignore: {sources: [sub/dir/.gitignore]}}", "", "")
	if err == nil || !strings.Contains(err.Error(), "bare filename") {
		t.Fatalf("a source with a path separator must be rejected, got %v", err)
	}
}

// === Additional regression: Validate multiple path types ===
// Ensure Validate checks all path fields for relativity.

func TestValidateMultiplePathTypes(t *testing.T) {
	home := "/home/u"
	tests := []struct {
		name, yml string
		wantErr   bool
	}{
		{"block.directories relative", "providers: {block: {directories: [rel/path]}}", true},
		{"paths.rw relative", "providers:\n  paths:\n    rw: [rel/path]", true},
		{"paths.ro relative", "providers:\n  paths:\n    ro: [rel/path]", true},
		{"all absolute", "providers:\n  block: {directories: [/blocked]}\n  paths:\n    rw: [/rw]\n    ro: [/ro]", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := loadFrom(t, home, tc.yml, "", "")
			if tc.wantErr && err == nil {
				t.Errorf("expected validation error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

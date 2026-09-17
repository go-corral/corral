package sandbox

import (
	"path/filepath"
	"testing"
)

func reachTokens() map[string]string {
	return map[string]string{"HOME": "/home/u", "AGENT_CONFIG_DIR": "/home/u/.claude"}
}

// TestPathReachableInCorralLinux covers the cases `corral sync` cares about: a binary
// under a baseline directory subtree is reachable; one outside every mount is not.
func TestPathReachableInCorralLinux(t *testing.T) {
	tok := reachTokens()
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/local/bin/corral", true}, // under /usr (subtree)
		{"/usr/bin/corral", true},
		{"/bin/corral", true},
		{"/opt/corral/corral", true},
		{"/home/u/.local/bin/corral", true},         // $HOME/.local/bin (subtree)
		{"/home/u/projects/repo/bin/corral", false}, // a dev build under the project — not baseline
		{"/home/u/corral", false},                   // bare $HOME is not mounted
		{"/srv/corral", false},
		{"/etc/hosts", false}, // recursive:false single-node rule — nothing is "under" it
	}
	for _, c := range cases {
		if got := PathReachableInCorral(c.path, tok, "linux"); got != c.want {
			t.Errorf("PathReachableInCorral(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestPathReachableInCorralPrefixSafe guards against a substring false-positive:
// /usr-local must not be considered "within" /usr.
func TestPathReachableInCorralPrefixSafe(t *testing.T) {
	if PathReachableInCorral("/usr-local/bin/corral", reachTokens(), "linux") {
		t.Error("/usr-local must not match the /usr mount")
	}
}

// TestPathReachableInCorralUnknownOS fails safe: an OS with no backend models no mounts,
// so nothing is reachable and sync would warn rather than stay silent.
func TestPathReachableInCorralUnknownOS(t *testing.T) {
	if PathReachableInCorral("/usr/bin/corral", reachTokens(), "plan9") {
		t.Error("an unmodeled OS must report nothing reachable")
	}
}

// TestBaselineDirsSkipsRulesAndTokens confirms BaselineDirs drops single-node and
// regex rules, and skips a rule whose token is empty (it would not be mounted).
func TestBaselineDirsSkipsRulesAndTokens(t *testing.T) {
	dirs := BaselineDirs(reachTokens(), "linux")
	for _, d := range dirs {
		if d == "/etc/hosts" {
			t.Error("recursive:false node rule /etc/hosts must not be a reachable subtree")
		}
	}
	// $AGENT_CONFIG_DIR expands here; with an empty token it must be skipped entirely.
	empty := BaselineDirs(map[string]string{"HOME": "/home/u"}, "linux")
	for _, d := range empty {
		if d == filepath.Clean("/.claude") || d == "" {
			t.Errorf("rule with empty token must be skipped, got %q", d)
		}
	}
}

//go:build darwin

package seatbelt

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/sandbox"
)

// Under the generated profile, the code subtrees of /Library and the Xcode license file stay
// usable while the rest of /Library cannot be listed or read, and realpath walks through the
// ungranted ancestors /Library and /private/etc.
func TestGeneratedProfileLibraryAccess(t *testing.T) {
	if os.Getenv(sandbox.SandboxEnvVar) != "" {
		t.Skip("running inside corral: nested sandbox-exec is denied, cannot apply a test profile")
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not found")
	}
	if out, err := exec.Command("sandbox-exec", "-p", "(version 1)\n(allow default)\n", "/usr/bin/true").CombinedOutput(); err != nil {
		t.Skipf("control profile cannot run /usr/bin/true: %v\n%s", err, out)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := New("", Config{}).profile(sandbox.SandboxSpec{Tokens: map[string]string{"HOME": home}})
	if err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		out, err := exec.Command("sandbox-exec", append([]string{"-p", profile}, args...)...).CombinedOutput()
		return string(out), err
	}
	exists := func(p string) bool {
		_, err := os.Stat(p)
		return err == nil
	}

	denied := [][]string{
		{"/bin/ls", "/Library"},
		{"/bin/ls", "/Library/Application Support"},
		{"/bin/ls", "/Library/Preferences"},
	}
	if p := "/Library/Preferences/SystemConfiguration/preferences.plist"; exists(p) {
		denied = append(denied, []string{"/bin/cat", p})
	}
	for _, args := range denied {
		if out, err := run(args...); err == nil {
			t.Errorf("%v must fail under the profile; got:\n%s", args, out)
		}
	}

	allowed := [][]string{{"/usr/bin/stat", "/Library"}}
	if exists("/Library/Developer/CommandLineTools") {
		allowed = append(allowed, []string{"/usr/bin/env", "DEVELOPER_DIR=/Library/Developer/CommandLineTools", "/usr/bin/xcrun", "--show-sdk-path"})
	}
	// java_home must find a JDK whose link in /Library/Java resolves into a granted path, such as
	// /opt/homebrew. A JDK linked into an ungranted path, such as the runner tool cache under
	// $HOME, stays unreachable.
	if out, err := exec.Command("/usr/libexec/java_home").Output(); err == nil {
		if jdk, err := filepath.EvalSymlinks(strings.TrimSpace(string(out))); err == nil &&
			sandbox.PathReachableInCorral(jdk, map[string]string{"HOME": home}, "darwin") {
			allowed = append(allowed, []string{"/usr/libexec/java_home"})
		}
	}
	if p := "/Library/Preferences/com.apple.dt.Xcode.plist"; exists(p) {
		allowed = append(allowed, []string{"/bin/cat", p})
	}
	// With Xcode.app selected, xcrun checks the license acceptance in the Xcode plist.
	if dir, err := exec.Command("xcode-select", "-p").Output(); err == nil && strings.Contains(string(dir), "Xcode") &&
		exec.Command("xcrun", "--show-sdk-path").Run() == nil {
		allowed = append(allowed, []string{"/usr/bin/xcrun", "--show-sdk-path"})
	}
	for _, args := range allowed {
		if out, err := run(args...); err != nil {
			t.Errorf("%v must succeed under the profile: %v\n%s", args, err, out)
		}
	}

	if exists("/bin/realpath") {
		out, err := run("/bin/realpath", "/etc/ssl/cert.pem")
		if err != nil || strings.TrimSpace(out) != "/private/etc/ssl/cert.pem" {
			t.Errorf("realpath /etc/ssl/cert.pem must print /private/etc/ssl/cert.pem: %v\n%s", err, out)
		}
	}
}

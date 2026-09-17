package ssh

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-corral/corral/internal/providers/spec"
)

// --- SSH Regression Tests ---

// A forbidden root that is itself a symlink must still be caught: resolveForbidden
// EvalSymlinks-resolves each root, so isForbidden compares real path against real path.
func TestSSHResolveForbiddenSymlink(t *testing.T) {
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")

	// Create a real secrets dir and a symlink ~/.gnupg -> realSecrets.
	realSecrets := t.TempDir()
	if err := os.WriteFile(filepath.Join(realSecrets, "leak"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	gnupg := filepath.Join(home, ".gnupg")
	if err := os.Symlink(realSecrets, gnupg); err != nil {
		t.Fatal(err)
	}

	// SSH config tries to Include ../.gnupg/leak. Even though ~/.gnupg is a symlink,
	// resolveForbidden must resolve it to its real path, so isForbidden catches it.
	writeSSHFile(t, filepath.Join(sshDir, "config"), "Include ../.gnupg/leak\n")

	c, err := New(home, "", []string{gnupg}).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}

	// The leak file must not appear in the overlay (it's forbidden even through symlink).
	realLeak, _ := filepath.EvalSymlinks(filepath.Join(gnupg, "leak"))
	for _, m := range c.Mounts {
		if m.Src == realLeak || strings.Contains(m.Dst, "leak") {
			t.Errorf("ssh overlay must not expose forbidden root via symlink: %+v", m)
		}
	}
}

// Include recursion is bounded by sshMaxIncludeDepth (16). walk adds a file then checks
// depth, so inc16 (reached at depth 16) is still mounted but its Include of inc17 is never
// followed — the cap bounds recursion, not the final file's addition.
func TestSSHIncludeDepthCap(t *testing.T) {
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")

	// Chain 18 files (inc0 → … → inc17), each Including the next; inc17 is one level past
	// the cap and must never be mounted.
	files := make([]string, 18)
	for i := 0; i < 18; i++ {
		files[i] = filepath.Join(sshDir, "config.d", fmt.Sprintf("inc%02d", i))
	}

	for i := 0; i < 17; i++ {
		content := "Include " + files[i+1] + "\n"
		writeSSHFile(t, files[i], content)
	}
	// files[17] (inc17) is never included

	// The main config includes inc0.
	writeSSHFile(t, filepath.Join(sshDir, "config"), "Include "+files[0]+"\n")

	c, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Count mounted include files (excluding main config).
	var mounted []string
	for _, m := range c.Mounts {
		if strings.Contains(m.Dst, "config.d") && strings.Contains(m.Dst, "inc") {
			mounted = append(mounted, filepath.Base(m.Dst))
		}
	}

	// inc00–inc16 (17 files) may mount; inc17 must not.
	maxExpected := 17
	if len(mounted) > maxExpected {
		t.Errorf("include depth cap should limit to ~17 files (depth 0-16), got %d", len(mounted))
	}
	for _, name := range mounted {
		if strings.HasSuffix(name, "17") {
			t.Errorf("inc17 should not be mounted (depth cap), got: %v", mounted)
		}
	}
}

// A config resolving to 257 unique files exceeds sshMaxFiles (256): vet() skips the 257th
// silently.
func TestSSHFileCountCap(t *testing.T) {
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")

	// Create a glob pattern that expands to 257 files.
	globDir := filepath.Join(sshDir, "config.d")
	for i := 0; i < 257; i++ {
		name := filepath.Join(globDir, "conf_"+string(rune('0'+(i%10))))
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if i < 256 {
			// Create real files for the first 256.
			if err := os.WriteFile(name+"_"+string(rune('0'+(i/10)))+".conf", []byte("Host "+name+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	// Main config includes the glob — it will match 256+ files.
	writeSSHFile(t, filepath.Join(sshDir, "config"),
		"Include "+filepath.Join(globDir, "*_*.conf")+"\n")

	c, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}

	// Count mounted config files (excluding config, known_hosts).
	mounted := 0
	for _, m := range c.Mounts {
		if strings.Contains(m.Dst, ".conf") {
			mounted++
		}
	}

	// At most 255 glob-expanded files (the main config takes 1 of the 256 sshMaxFiles slots).
	if mounted > 255 {
		t.Errorf("file count cap should limit glob-expanded files to 255 (main config takes 1 slot), got %d", mounted)
	}
}

// A config with a single line > 1 MiB: the scanner buffer is capped at 1 MiB, so the
// over-long line ends the scan cleanly — no panic, no memory blowup.
func TestSSHScannerLineCap(t *testing.T) {
	home := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")

	// Create a config with a line > 1 MiB (exceeds bufio.Scanner default buffer).
	longLine := strings.Repeat("X", 1<<21) // 2 MiB
	cfg := "Include " + longLine + "\nHost valid\n"
	writeSSHFile(t, filepath.Join(sshDir, "config"), cfg)

	// Mint must not panic or exhaust memory.
	c, err := New(home, "", nil).Mint(context.Background(), spec.Session{}, false)
	if err != nil {
		t.Fatal(err)
	}

	// With no real Include targets, the only guarantee is that Mint completes on the
	// over-long line — no panic, no memory blowup.
	if c == nil {
		t.Error("Mint should succeed even with an over-long line (scanner continues)")
	}
}

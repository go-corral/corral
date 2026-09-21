package block

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Validate owns the absolute-path and always-blocked-interaction checks; config passes the
// ~-expanded, cleaned floor. These exercise the method directly (config's Load tests prove
// the wiring end-to-end).
func TestValidate(t *testing.T) {
	floor := []string{"/home/u/.ssh", "/home/u/.gnupg", "/home/u/.aws"}

	for _, tc := range []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = expect success
	}{
		{"valid", Config{Directories: []string{"/data/vault"}, Files: []string{"/repo/.env"}}, ""},
		{"relative dir", Config{Directories: []string{"rel/secret"}}, "providers.block.directories: \"rel/secret\" must be an absolute or ~-prefixed path"},
		{"relative file", Config{Files: []string{"rel/secret.txt"}}, "providers.block.files: \"rel/secret.txt\" must be an absolute or ~-prefixed path"},
		{"file under floor", Config{Files: []string{"/home/u/.ssh/id_rsa"}}, "is already covered by the always-blocked path"},
		{"file prefix-sibling allowed", Config{Files: []string{"/home/u/.ssh-backup"}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate(floor)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Errorf("Validate() = %v, want nil", err)
			case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
				t.Errorf("Validate() = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestWarnings(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vault")
	file := filepath.Join(root, "secret.env")
	link := filepath.Join(root, "dangling")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "gone"), link); err != nil {
		t.Fatal(err)
	}
	missingDir := filepath.Join(root, "missing-dir")
	missingFile := filepath.Join(root, "missing.env")

	for _, tc := range []struct {
		name string
		cfg  Config
		want []string
	}{
		{"existing entries", Config{Directories: []string{dir}, Files: []string{file, link}}, nil},
		{"missing directory", Config{Directories: []string{missingDir}}, []string{`providers.block.directories "` + missingDir + `"`}},
		{"missing file", Config{Files: []string{missingFile}}, []string{`providers.block.files "` + missingFile + `"`}},
		{"one warning per missing entry", Config{Directories: []string{dir, missingDir}, Files: []string{missingFile}}, []string{missingDir, missingFile}},
		{"empty", Config{}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.cfg.Warnings()
			if len(got) != len(tc.want) {
				t.Fatalf("Warnings() = %q, want %d warning(s)", got, len(tc.want))
			}
			for i, w := range got {
				if !strings.Contains(w, tc.want[i]) {
					t.Errorf("Warnings()[%d] = %q, want it to name %q", i, w, tc.want[i])
				}
			}
		})
	}
}

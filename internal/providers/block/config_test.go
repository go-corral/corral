package block

import (
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

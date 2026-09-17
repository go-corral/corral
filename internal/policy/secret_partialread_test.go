package policy

import (
	"strings"
	"testing"
)

// Partial-read coverage. A PEM key detected only by its BEGIN header slips through any
// read that drops the first line: `tail`, `grep -v BEGIN`, offset `sed`/`dd`, or a
// mid-stream chunk. The detector therefore also fires on the END footer and on a base64
// body fragment. These fixtures assemble the PEM markers at runtime (split
// string concatenation) so no contiguous PEM marker sits in this source file — otherwise the
// scanner under test would block reading/writing the file itself.
func TestScanSecretsPartialPEMRead(t *testing.T) {
	// Split so the literal "-----BEGIN … PRIVATE KEY-----" never appears contiguously here.
	begin := "-----BEGIN OPENSSH PRIVATE " + "KEY-----"
	end := "-----END OPENSSH PRIVATE " + "KEY-----"
	bodyLine1 := strings.Repeat("A", 64)
	bodyLine2 := strings.Repeat("b", 70) + "=="
	body := bodyLine1 + "\n" + bodyLine2

	cases := []struct {
		name    string
		data    string
		wantHit bool
		wantKnd SecretKind
	}{
		{"begin header (head)", begin + "\n" + body, true, KindPEMPrivateKey},
		{"end footer only (tail)", strings.Repeat("Zm9v", 6) + "\n" + end, true, KindPEMPrivateKey},
		{"body fragment, no markers (grep -v / sed)", "noise\n" + body + "\ntail", true, KindPEMBody},
		// FP guards: a single long base64 line, and an inline integrity hash, must not match.
		{"single base64 line is not a key body", "prefix\n" + bodyLine1 + "\nsuffix", false, ""},
		{"inline integrity hash", `  "integrity": "sha512-` + strings.Repeat("A", 80) + `==",`, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, hit := scanSecrets([]byte(tc.data), 0) // entropy off: known-format detectors only
			if hit != tc.wantHit {
				t.Fatalf("hit=%v, want %v (kind=%q)", hit, tc.wantHit, res.kind)
			}
			if hit && res.kind != tc.wantKnd {
				t.Errorf("kind=%q, want %q", res.kind, tc.wantKnd)
			}
		})
	}
}

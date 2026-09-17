package policy

import (
	"strings"
	"testing"
)

// ScanPromptText catches a known-format secret in a prompt and reports kind only.
func TestScanPromptTextKnownFormat(t *testing.T) {
	kind, hit := ScanPromptText([]byte("paste: "+awsKeyFixture), 0, 0)
	if !hit {
		t.Fatalf("a known-format AWS key in the prompt must be detected")
	}
	if kind != KindAWSKey {
		t.Errorf("kind = %q, want %q", kind, KindAWSKey)
	}
}

// The entropy heuristic is opt-in (entropyThreshold > 0), mirroring the tool-call scans:
// a high-entropy non-known-format token is flagged only when a threshold is set.
func TestScanPromptTextEntropyGated(t *testing.T) {
	const token = "Zk7Qp2Lx9Rm4Ts6Vw1Yb8Nc3Df5Gh0J" // 32 mixed chars, high entropy, not a known format
	if _, hit := ScanPromptText([]byte("token "+token), 0, 0); hit {
		t.Errorf("entropy disabled (0) must NOT flag a non-known-format token")
	}
	if _, hit := ScanPromptText([]byte("token "+token), 3.0, 0); !hit {
		t.Errorf("entropy threshold 3.0 must flag the high-entropy token")
	}
}

// The scan is capped: a secret beyond maxScanBytes is not seen; within the cap it is.
func TestScanPromptTextCapsBytes(t *testing.T) {
	// A space before the key so the AWS-key regex's leading \b word boundary holds
	// (the detector requires it); the key starts at offset 51.
	text := []byte(strings.Repeat("x", 50) + " " + awsKeyFixture)
	if _, hit := ScanPromptText(text, 0, 10); hit {
		t.Errorf("a secret beyond maxScanBytes must not be detected")
	}
	if _, hit := ScanPromptText(text, 0, int64(len(text))); !hit {
		t.Errorf("a secret within maxScanBytes must be detected")
	}
}

// An empty prompt never hits.
func TestScanPromptTextEmpty(t *testing.T) {
	if _, hit := ScanPromptText(nil, 0, 0); hit {
		t.Errorf("empty prompt must not hit")
	}
}

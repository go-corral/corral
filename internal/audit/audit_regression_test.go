package audit

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLogMarshalSuccess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false)

	r := Record{Action: "deny"}
	if err := l.Log(r); err != nil {
		t.Fatalf("Log should succeed: %v", err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	var decoded Record
	if err := json.Unmarshal(bytes.TrimSpace(data), &decoded); err != nil {
		t.Fatalf("invalid JSON written: %v", err)
	}

	if decoded.Action != "deny" {
		t.Errorf("expected Action='deny', got %q", decoded.Action)
	}
}

func TestLogMkdirAllError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses filesystem permission checks")
	}
	dir := t.TempDir()
	readOnlyDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(readOnlyDir, 0o500); err != nil {
		t.Fatalf("failed to create read-only dir: %v", err)
	}
	p := filepath.Join(readOnlyDir, "subdir", "audit.jsonl")

	l := newLogger(p, time.Hour, 24*time.Hour, false)
	r := Record{Action: "deny"}
	err := l.Log(r)

	if err == nil {
		t.Fatal("expected error from MkdirAll")
	}
	if _, statErr := os.Stat(p + ".lock"); statErr == nil {
		t.Error("lock file should not be created when MkdirAll fails")
	}
	if _, statErr := os.Stat(p); statErr == nil {
		t.Error("log file should not be created when MkdirAll fails")
	}
}

func TestLogLockFileOpenError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")

	// Create the audit directory
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("failed to create audit dir: %v", err)
	}

	// Plant a symlink at l.path+".lock" to trigger O_NOFOLLOW rejection
	lockPath := p + ".lock"
	targetPath := filepath.Join(dir, "target")
	if err := os.WriteFile(targetPath, []byte("target"), 0o644); err != nil {
		t.Fatalf("failed to create symlink target: %v", err)
	}
	if err := os.Symlink(targetPath, lockPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	l := newLogger(p, time.Hour, 24*time.Hour, false)
	r := Record{Action: "deny"}
	err := l.Log(r)

	if err == nil {
		t.Fatal("expected error from O_NOFOLLOW rejection of symlink at lock path")
	}

	if _, statErr := os.Stat(p); statErr == nil {
		t.Error("log file should not be created when lock file open fails")
	}
}

func TestLogFileOpenError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")

	// Create the audit directory
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("failed to create audit dir: %v", err)
	}

	// Plant a symlink at l.path to trigger O_NOFOLLOW rejection
	targetPath := filepath.Join(dir, "target")
	if err := os.WriteFile(targetPath, []byte("target"), 0o644); err != nil {
		t.Fatalf("failed to create symlink target: %v", err)
	}
	if err := os.Symlink(targetPath, p); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	l := newLogger(p, time.Hour, 24*time.Hour, false)
	r := Record{Action: "deny"}
	err := l.Log(r)

	if err == nil {
		t.Fatal("expected error from O_NOFOLLOW rejection of symlink at log path")
	}
}

func TestLogOmitEmptyFields(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false)

	r := Record{Action: "deny"}
	if err := l.Log(r); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	line := strings.TrimSpace(string(data))
	var decoded map[string]interface{}
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, hasSessionID := decoded["session_id"]; hasSessionID {
		t.Error("session_id should be omitted when empty")
	}
	if _, hasTool := decoded["tool"]; hasTool {
		t.Error("tool should be omitted when empty")
	}
	if _, hasRule := decoded["rule"]; hasRule {
		t.Error("rule should be omitted when empty")
	}
	if _, hasReason := decoded["reason"]; hasReason {
		t.Error("reason should be omitted when empty")
	}
	if _, hasCwd := decoded["cwd"]; hasCwd {
		t.Error("cwd should be omitted when empty")
	}

	if _, hasTime := decoded["time"]; !hasTime {
		t.Error("time should be present in JSON")
	}
	if _, hasAction := decoded["action"]; !hasAction {
		t.Error("action should be present in JSON")
	}

	var unmarshaled Record
	if err := json.Unmarshal([]byte(line), &unmarshaled); err != nil {
		t.Fatalf("failed to unmarshal Record: %v", err)
	}
	if unmarshaled.SessionID != "" || unmarshaled.Tool != "" || unmarshaled.Rule != "" ||
		unmarshaled.Reason != "" || unmarshaled.Cwd != "" {
		t.Errorf("optional fields should be empty after unmarshal: %+v", unmarshaled)
	}
}

func TestLogSymlinkAtLogPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")

	// Create the audit directory
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("failed to create audit dir: %v", err)
	}

	// Plant a symlink at l.path
	targetPath := filepath.Join(dir, "target")
	if err := os.WriteFile(targetPath, []byte("target"), 0o644); err != nil {
		t.Fatalf("failed to create symlink target: %v", err)
	}
	if err := os.Symlink(targetPath, p); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	l := newLogger(p, time.Hour, 24*time.Hour, false)
	r := Record{Action: "deny"}
	err := l.Log(r)

	if err == nil {
		t.Fatal("expected error from O_NOFOLLOW rejection of symlink")
	}

	targetContent, _ := os.ReadFile(targetPath)
	if string(targetContent) != "target" {
		t.Error("symlink should not have been followed; target should not be modified")
	}
}

func TestLogSymlinkAtLockPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")

	// Create the audit directory
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("failed to create audit dir: %v", err)
	}

	// Plant a symlink at l.path+".lock"
	lockPath := p + ".lock"
	targetPath := filepath.Join(dir, "target")
	if err := os.WriteFile(targetPath, []byte("target"), 0o644); err != nil {
		t.Fatalf("failed to create symlink target: %v", err)
	}
	if err := os.Symlink(targetPath, lockPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	l := newLogger(p, time.Hour, 24*time.Hour, false)
	r := Record{Action: "deny"}
	err := l.Log(r)

	if err == nil {
		t.Fatal("expected error from O_NOFOLLOW rejection of symlink at lock path")
	}

	targetContent, _ := os.ReadFile(targetPath)
	if string(targetContent) != "target" {
		t.Error("symlink should not have been followed; target should not be modified")
	}

	if _, statErr := os.Stat(p); statErr == nil {
		t.Error("log file should not be written when lock symlink is rejected")
	}
}

func TestLogFlockSuccess(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false)

	r := Record{Action: "deny"}
	if err := l.Log(r); err != nil {
		t.Fatalf("Log should succeed: %v", err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	if !bytes.Contains(data, []byte(`"action":"deny"`)) {
		t.Error("expected record to be written")
	}
}

func TestLogOpenFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root bypasses filesystem permission checks")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")

	// Create the audit directory
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatalf("failed to create audit dir: %v", err)
	}

	if err := os.WriteFile(p, []byte(""), 0o444); err != nil {
		t.Fatalf("failed to create read-only file: %v", err)
	}

	l := newLogger(p, time.Hour, 24*time.Hour, false)
	r := Record{Action: "deny"}
	err := l.Log(r)

	if err == nil {
		t.Fatal("expected error from OpenFile on read-only file")
	}
}

// rotateInterval ≤ 0 disables rotation: the log grows as one file, no backups ever appear,
// regardless of how many records (or how much wall time) pass.
func TestRotationDisabledWhenIntervalNonPositive(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Hour} {
		dir := t.TempDir()
		p := filepath.Join(dir, "audit.jsonl")
		l := newLogger(p, interval, 24*time.Hour, false)
		for i := 0; i < 50; i++ {
			if err := l.Log(Record{Action: "allow", Reason: fmt.Sprintf("line-%d", i)}); err != nil {
				t.Fatalf("Log failed: %v", err)
			}
		}
		if got := Backups(p); len(got) != 0 {
			t.Errorf("interval=%s: expected no backups, got %v", interval, got)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("failed to read log: %v", err)
		}
		if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) != 50 {
			t.Errorf("interval=%s: expected 50 lines in the single live log, got %d", interval, len(lines))
		}
	}
}

// The first Log on a non-existent file creates it and never rotates (there is nothing to
// roll yet), so no backup appears on the first write.
func TestRotateNoOpWhenFileAbsent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false)
	if err := l.Log(Record{Action: "allow"}); err != nil {
		t.Fatalf("Log failed: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Errorf("log file should be created: %v", err)
	}
	if got := Backups(p); len(got) != 0 {
		t.Errorf("no backup should exist on first write, got %v", got)
	}
}

// Rotation triggers exactly at the interval boundary: a window younger than rotateInterval
// is kept; a window whose age reaches the interval is rolled.
func TestRotateBoundary(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false)
	start := time.Unix(1700000000, 0).UTC()

	l.now = func() time.Time { return start }
	if err := l.Log(Record{Action: "a"}); err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return start.Add(time.Hour - time.Nanosecond) }
	if err := l.Log(Record{Action: "b"}); err != nil {
		t.Fatal(err)
	}
	if got := Backups(p); len(got) != 0 {
		t.Errorf("age < interval must not rotate, got %v", got)
	}
	l.now = func() time.Time { return start.Add(time.Hour) }
	if err := l.Log(Record{Action: "c"}); err != nil {
		t.Fatal(err)
	}
	if got := Backups(p); len(got) != 1 {
		t.Fatalf("age == interval must rotate to exactly one backup, got %v", got)
	}
}

// Retention prunes backups whose window start is older than retention, at the next
// rotation; younger backups survive. Drives 1h windows under a 3h retention.
func TestRetentionPrunesOldBackups(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 3*time.Hour, false)
	start := time.Unix(1700000000, 0).UTC()

	for i := 0; i < 6; i++ {
		at := start.Add(time.Duration(i) * time.Hour)
		l.now = func() time.Time { return at }
		if err := l.Log(Record{Action: "allow", Reason: fmt.Sprintf("h%d", i)}); err != nil {
			t.Fatalf("Log %d failed: %v", i, err)
		}
	}

	now := start.Add(5 * time.Hour)
	backups := Backups(p)
	if len(backups) == 0 {
		t.Fatal("expected recent backups to survive retention, got none")
	}
	for _, b := range backups {
		ts, ok := parseRotatedStamp(b, p)
		if !ok {
			t.Fatalf("backup %q has no parseable stamp", b)
		}
		if now.Sub(ts) > 3*time.Hour {
			t.Errorf("backup %q (window start %s) is older than retention and should have been pruned", b, ts)
		}
	}
}

// With gzip enabled, a rotated backup is compressed: the .gz exists, the uncompressed
// intermediate is gone, and the gzip stream decompresses back to the original records.
func TestGzipBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, true)
	start := time.Unix(1700000000, 0).UTC()

	l.now = func() time.Time { return start }
	if err := l.Log(Record{Action: "allow", Reason: "first-window"}); err != nil {
		t.Fatal(err)
	}
	l.now = func() time.Time { return start.Add(2 * time.Hour) }
	if err := l.Log(Record{Action: "allow", Reason: "second-window"}); err != nil {
		t.Fatal(err)
	}

	backups := Backups(p)
	if len(backups) != 1 {
		t.Fatalf("expected exactly one rotated backup, got %v", backups)
	}
	gz := backups[0]
	if !strings.HasSuffix(gz, ".gz") {
		t.Errorf("backup should be gzip'd, got %q", gz)
	}
	uncompressed := strings.TrimSuffix(gz, ".gz")
	if _, err := os.Stat(uncompressed); err == nil {
		t.Errorf("uncompressed intermediate %q should be removed after gzip", uncompressed)
	}

	f, err := os.Open(gz)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("backup is not a valid gzip stream: %v", err)
	}
	body, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("reading gzip body: %v", err)
	}
	if !strings.Contains(string(body), "first-window") {
		t.Errorf("gzip'd backup must contain the rotated records, got %q", body)
	}
}

func TestLogPreservesCallerProvidedTime(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false)
	l.now = func() time.Time {
		return time.Unix(2000000000, 0).UTC()
	}

	customTime := "2020-01-15T10:30:45.123Z"
	r := Record{Action: "deny", Time: customTime}
	if err := l.Log(r); err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("failed to read log: %v", err)
	}

	var decoded Record
	if err := json.Unmarshal(bytes.TrimSpace(data), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if decoded.Time != customTime {
		t.Errorf("Time should be preserved; expected %q, got %q", customTime, decoded.Time)
	}
}

func TestRecordJSONFieldNames(t *testing.T) {
	r := Record{
		Time:      "2026-01-01T00:00:00Z",
		SessionID: "sess-123",
		Tool:      "Read",
		Action:    "deny",
		Rule:      "path-pattern",
		Reason:    "test",
		Cwd:       "/home",
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	expectedFields := map[string]bool{
		"time":       true,
		"session_id": true,
		"tool":       true,
		"action":     true,
		"rule":       true,
		"reason":     true,
		"cwd":        true,
	}

	for field := range decoded {
		if !expectedFields[field] {
			t.Errorf("unexpected field in JSON: %s", field)
		}
	}

	for field := range expectedFields {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing expected field in JSON: %s", field)
		}
	}
}

package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLoggerWritesJSONLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false)
	l.now = func() time.Time { return time.Unix(1700000000, 0).UTC() }

	if err := l.Log(Record{Action: "deny", Tool: "Read", Rule: "path-pattern", Reason: "a secret"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Error("each record must be newline-terminated")
	}
	var r Record
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &r); err != nil {
		t.Fatalf("not a valid JSON line: %v", err)
	}
	if r.Action != "deny" || r.Tool != "Read" || r.Rule != "path-pattern" {
		t.Errorf("record fields wrong: %+v", r)
	}
	if r.Time == "" {
		t.Error("Time should be stamped when empty")
	}
}

func TestLoggerRotates(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false)
	start := time.Unix(1700000000, 0).UTC()

	// First window.
	l.now = func() time.Time { return start }
	if err := l.Log(Record{Action: "allow", Tool: "Read", Reason: "in-first-window"}); err != nil {
		t.Fatal(err)
	}
	// Past the interval → the next append rolls the first window to a timestamped backup.
	rotateAt := start.Add(90 * time.Minute)
	l.now = func() time.Time { return rotateAt }
	if err := l.Log(Record{Action: "allow", Tool: "Read", Reason: "in-second-window"}); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(p); err != nil {
		t.Errorf("live log must exist: %v", err)
	}
	backups := Backups(p)
	if len(backups) != 1 {
		t.Fatalf("expected exactly one rotated backup, got %v", backups)
	}
	// The backup carries the first window's records; the live log carries the new one.
	if body, err := os.ReadFile(backups[0]); err != nil || !strings.Contains(string(body), "in-first-window") {
		t.Errorf("backup must hold the first window's records: body=%q err=%v", body, err)
	}
	if body, err := os.ReadFile(p); err != nil || !strings.Contains(string(body), "in-second-window") {
		t.Errorf("live log must hold the new window's records: body=%q err=%v", body, err)
	}
	// The backup is named by its rotation time (when the window was rolled), not the window
	// start — this is what lets retention measure a backup's age from when it was archived.
	if ts, ok := parseRotatedStamp(backups[0], p); !ok || !ts.Equal(rotateAt) {
		t.Errorf("backup must be stamped with the rotation time %s, got %s (ok=%v)", rotateAt, ts, ok)
	}
}

// A newly archived backup is age zero even when its live window sat idle past retention.
func TestLoggerRetentionKeepsFreshlyRotatedAfterIdleGap(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 3*time.Hour, false) // retention 3h
	start := time.Unix(1700000000, 0).UTC()

	l.now = func() time.Time { return start }
	if err := l.Log(Record{Action: "allow", Reason: "before-idle"}); err != nil {
		t.Fatal(err)
	}
	// Resume after a 30-hour idle gap (>> retention). The window rolls; the backup must survive.
	l.now = func() time.Time { return start.Add(30 * time.Hour) }
	if err := l.Log(Record{Action: "allow", Reason: "after-idle"}); err != nil {
		t.Fatal(err)
	}
	backups := Backups(p)
	if len(backups) != 1 {
		t.Fatalf("the just-rotated backup must survive an idle gap, got %v", backups)
	}
	if body, err := os.ReadFile(backups[0]); err != nil || !strings.Contains(string(body), "before-idle") {
		t.Errorf("surviving backup must hold the idle window's records: body=%q err=%v", body, err)
	}
}

func TestLoggerConcurrent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "audit.jsonl")
	l := newLogger(p, time.Hour, 24*time.Hour, false) // long interval: no rotation during the test

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = l.Log(Record{Action: "allow", Reason: fmt.Sprintf("g%02d", i)})
		}(i)
	}
	wg.Wait()

	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Errorf("expected 50 lines, got %d", len(lines))
	}
	for _, ln := range lines {
		var r Record
		if err := json.Unmarshal([]byte(ln), &r); err != nil {
			t.Errorf("interleaved/corrupt line %q: %v", ln, err)
		}
	}
}

func TestLoggerNoOpWhenDisabled(t *testing.T) {
	var nilLogger *Logger
	if err := nilLogger.Log(Record{Action: "allow"}); err != nil {
		t.Errorf("nil logger must no-op, got %v", err)
	}
	if err := newLogger("", time.Hour, 24*time.Hour, false).Log(Record{Action: "allow"}); err != nil {
		t.Errorf("empty-path logger must no-op, got %v", err)
	}
}

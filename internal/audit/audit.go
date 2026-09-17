// Package audit writes corral's structured, time-rotated decision log: every hook decision
// (allow and deny) becomes one JSON line with a structural summary of the tool parameters.
//
// The caller sanitizes Input before it reaches this package: allowlisted structural keys and
// the Bash command are kept verbatim; every other value is reduced to a byte count, so file
// contents and secret argument values never reach the log. Writing is best-effort and
// isolated from enforcement: a logging failure must never change a policy verdict.
package audit

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Record struct {
	Time      string          `json:"time"`
	SessionID string          `json:"session_id,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Action    string          `json:"action"`
	Rule      string          `json:"rule,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Cwd       string          `json:"cwd,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
}

// Logger appends Records to a JSON-lines file, rotating it by time. Safe for concurrent use
// within a process (mu) and across short-lived hook processes (flock'd sidecar lock).
type Logger struct {
	path           string
	rotateInterval time.Duration
	retention      time.Duration
	gzip           bool
	now            func() time.Time
	mu             sync.Mutex
}

func New(cfg Config, path string) *Logger {
	return newLogger(path, cfg.EffectiveRotateInterval(), cfg.EffectiveRetention(), cfg.Gzip)
}

func newLogger(path string, rotateInterval, retention time.Duration, gzip bool) *Logger {
	return &Logger{
		path:           path,
		rotateInterval: rotateInterval,
		retention:      retention,
		gzip:           gzip,
		now:            time.Now,
	}
}

const (
	rotateStampLayout     = "20060102T150405Z"
	rotateStampLayoutNano = "20060102T150405.000000000Z"
)

// Log appends r as one JSON line, stamping r.Time when empty.
func (l *Logger) Log(r Record) error {
	if l == nil || l.path == "" {
		return nil
	}
	if r.Time == "" {
		r.Time = l.now().UTC().Format(time.RFC3339Nano)
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}

	pendingGzip, err := l.appendLocked(line)
	if err != nil {
		return err
	}
	// Compress the backup after releasing the flock: gzipping is slow and would stall hook
	// processes waiting on the lock. Best-effort: on failure the uncompressed backup is kept.
	if pendingGzip != "" {
		if gzipFile(pendingGzip) == nil {
			_ = os.Remove(pendingGzip)
		}
	}
	return nil
}

// appendLocked is the flock-serialized critical section: rotate then append the line. Returns
// the path of a rotated backup awaiting compression (or "" when none).
func (l *Logger) appendLocked(line []byte) (pendingGzip string, err error) {
	// O_NOFOLLOW: the audit dir is writable by the sandboxed agent, so refuse to follow a
	// symlink planted at the log/lock path.
	lock, err := os.OpenFile(l.path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	defer func() { _ = lock.Close() }()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return "", err
	}
	defer func() { _ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN) }()

	pendingGzip = l.rotateByTime()

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(line); err != nil {
		return "", err
	}
	return pendingGzip, nil
}

// rotateByTime rolls the live log to a timestamped backup once its window is at least
// rotateInterval old, then prunes expired backups. Returns the backup awaiting compression
// (gzip on) else "". Best-effort: any error is swallowed so rotation never drops the line.
func (l *Logger) rotateByTime() (pendingGzip string) {
	if l.rotateInterval <= 0 {
		return ""
	}
	// Lstat, never Stat: the audit dir is agent-writable, so a symlink at the log path is hostile.
	fi, err := os.Lstat(l.path)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 || fi.Size() == 0 {
		return ""
	}
	now := l.now().UTC()
	if start, ok := l.windowStart(); ok && now.Sub(start) < l.rotateInterval {
		return ""
	}
	rotated := l.backupName(now)
	if rotated == "" {
		return ""
	}
	if err := os.Rename(l.path, rotated); err != nil {
		return ""
	}
	l.sweepRetention(now)
	if l.gzip {
		return rotated
	}
	return ""
}

// backupName returns a free timestamped backup path for a rotation at now. Checks both the
// uncompressed and .gz form and returns "" rather than clobber an existing backup.
func (l *Logger) backupName(now time.Time) string {
	for _, layout := range []string{rotateStampLayout, rotateStampLayoutNano} {
		cand := l.path + "." + now.Format(layout)
		_, eRaw := os.Lstat(cand)
		_, eGz := os.Lstat(cand + ".gz")
		if eRaw != nil && eGz != nil {
			return cand
		}
	}
	return ""
}

// windowStart reads the first line of the live log and returns its record timestamp. ok=false
// when the file is unreadable or the first line does not carry a parseable time. Bounded read
// (O_NOFOLLOW, 64 KiB cap) so a pathological first line can't turn rotation into a large read.
func (l *Logger) windowStart() (time.Time, bool) {
	f, err := os.OpenFile(l.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return time.Time{}, false
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(io.LimitReader(f, 1<<16)).ReadBytes('\n')
	if len(line) == 0 {
		_ = err
		return time.Time{}, false
	}
	var rec struct {
		Time string `json:"time"`
	}
	if json.Unmarshal(line, &rec) != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, rec.Time)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// sweepRetention prunes rotated backups older than retention, aged from the filename stamp.
// Runs at rotation time, not per append, keeping the hot path fast.
func (l *Logger) sweepRetention(now time.Time) {
	if l.retention <= 0 {
		return
	}
	for _, m := range Backups(l.path) {
		if ts, ok := parseRotatedStamp(m, l.path); ok && now.UTC().Sub(ts) > l.retention {
			_ = os.Remove(m)
		}
	}
}

// Backups returns the log's rotated-backup files: its timestamped siblings (gzip'd or not),
// excluding the live log and .lock. Listing is by directory read + prefix match.
func Backups(logPath string) []string {
	dir := filepath.Dir(logPath)
	prefix := filepath.Base(logPath) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		full := filepath.Join(dir, e.Name())
		if _, ok := parseRotatedStamp(full, logPath); ok {
			out = append(out, full)
		}
	}
	return out
}

// parseRotatedStamp extracts the rotation time from a rotated-backup filename of the form
// <base>.<stamp> or <base>.<stamp>.gz. ok=false for anything else.
func parseRotatedStamp(name, base string) (time.Time, bool) {
	rest, ok := strings.CutPrefix(name, base+".")
	if !ok {
		return time.Time{}, false
	}
	rest = strings.TrimSuffix(rest, ".gz")
	for _, layout := range []string{rotateStampLayout, rotateStampLayoutNano} {
		if t, err := time.Parse(layout, rest); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// gzipFile compresses src to src+".gz" (O_EXCL|O_NOFOLLOW so a planted file is never followed or
// clobbered). On any error it removes a partial .gz and returns the error, leaving src.
func gzipFile(src string) error {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	dst := src + ".gz"
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(out)
	if _, err := io.Copy(zw, in); err != nil {
		_ = zw.Close()
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := zw.Close(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(dst)
		return err
	}
	return nil
}

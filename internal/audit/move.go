package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// MoveLegacy moves the log at from and its rotated backups into the directory of to, then
// removes from's lock file. The live log becomes to when to does not exist, else a rotated
// backup of to. Backups keep their names. It holds the flock of both logs, so a concurrent
// writer of either loses no record. Each file that stays in place, because its rename fails or
// its target name exists, yields one error.
func MoveLegacy(from, to string) []error {
	// Nothing to move must leave no trace, not even the lock files, so check before creating any.
	if len(Backups(from)) == 0 {
		if _, err := os.Lstat(from); err != nil {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o700); err != nil {
		return []error{err}
	}
	releaseTo, err := flockFile(to + ".lock")
	if err != nil {
		return []error{err}
	}
	defer releaseTo()
	releaseFrom, err := flockFile(from + ".lock")
	if err != nil {
		return []error{err}
	}
	defer releaseFrom()

	// Enumerate under the locks: a writer holds the same flock while it appends or rotates, so
	// the view here is the one the renames operate on.
	backups := Backups(from)
	_, liveErr := os.Lstat(from)
	var errs []error
	for _, b := range backups {
		if err := moveFile(b, filepath.Join(filepath.Dir(to), filepath.Base(b))); err != nil {
			errs = append(errs, err)
		}
	}
	if liveErr == nil {
		dst := to
		if _, err := os.Lstat(to); err == nil {
			dst = (&Logger{path: to}).backupName(time.Now().UTC())
		}
		if dst == "" {
			errs = append(errs, fmt.Errorf("move %s: no free backup name next to %s", from, to))
		} else if err := moveFile(from, dst); err != nil {
			errs = append(errs, err)
		}
	}
	_ = os.Remove(from + ".lock")
	return errs
}

// moveFile renames the regular file src to dst unless dst exists.
func moveFile(src, dst string) error {
	fi, err := os.Lstat(src)
	if err != nil {
		return err
	}
	// The logger refuses a symlink at the log path, so a moved symlink would stop logging.
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("move %s: not a regular file", src)
	}
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("move %s: %s already exists", src, dst)
	}
	return os.Rename(src, dst)
}

// flockFile opens path without following a symlink and takes an exclusive flock on it.
// release unlocks and closes it.
func flockFile(path string) (release func(), err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

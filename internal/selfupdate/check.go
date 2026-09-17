package selfupdate

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const DefaultInterval = 24 * time.Hour

func StatePath(home string) string {
	return filepath.Join(home, ".cache", "corral", "update-check.json")
}

type checkState struct {
	LastCheck time.Time `json:"lastCheck"`
	Latest    string    `json:"latest"`
}

// CheckOnStart returns a one-line "newer version available" notice, or "" when corral is
// current, the check is throttled-and-cached, or anything went wrong. Within interval it
// answers from statePath with no network; past it, it probes and rewrites statePath, stamping
// the time even on failure so a down instance is not re-probed every launch.
func CheckOnStart(ctx context.Context, u *Updater, statePath string, interval time.Duration, now time.Time) string {
	st := readState(statePath)
	if !st.LastCheck.IsZero() && now.Sub(st.LastCheck) < interval {
		return noticeFor(st.Latest, u.Current)
	}

	st.LastCheck = now
	rel, err := u.LatestRelease(ctx)
	if err == nil {
		st.Latest = rel.Version()
	}
	writeState(statePath, st)

	if err != nil {
		return ""
	}
	return noticeFor(st.Latest, u.Current)
}

// CachedCheck reports the most recent recorded check from statePath without any network.
func CachedCheck(statePath string) (latest string, when time.Time, ok bool) {
	st := readState(statePath)
	if st.LastCheck.IsZero() {
		return "", time.Time{}, false
	}
	return st.Latest, st.LastCheck, true
}

func RecordCheck(statePath, latest string, now time.Time) {
	writeState(statePath, checkState{LastCheck: now, Latest: latest})
}

func noticeFor(latest, current string) string {
	if !IsNewer(latest, current) {
		return ""
	}
	return fmt.Sprintf("a newer corral is available: %s → %s — run 'corral update'", current, latest)
}

func readState(path string) checkState {
	var st checkState
	data, err := os.ReadFile(path)
	if err != nil {
		return checkState{}
	}
	if json.Unmarshal(data, &st) != nil {
		return checkState{}
	}
	return st
}

func writeState(path string, st checkState) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

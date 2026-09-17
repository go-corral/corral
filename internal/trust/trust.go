// Package trust records which repo-discovered corral config files the operator has approved,
// making a repo-shipped .corral.yml / .corral.local.yml approve-once: the first `corral run`/
// `corral sync` in a repo, and any later config change, needs a one-time interactive approval
// before corral consumes it. Without it a cloned repo's committed config could enable
// providers, add rw grants, or run host commands via the hooks provider on a bare `corral run`.
//
// Global config (user-owned, outside the repo) is trusted and never gated; only the
// project/local layers reach here. State lives under $XDG_STATE_HOME, not the cache, so
// `corral gc` cannot silently re-arm the gate.
package trust

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Entry struct {
	Path   string
	SHA256 string
}

type State string

const (
	StateNew      State = "new"
	StateChanged  State = "changed"
	StateApproved State = "approved"
)

type Result struct {
	Path       string
	State      State
	ApprovedAt time.Time
}

func (r Result) NeedsApproval() bool { return r.State != StateApproved }

type Store struct {
	dir string
	now func() time.Time
}

func NewStore(dir string) *Store {
	return &Store{dir: dir, now: time.Now}
}

func DefaultDir(home string) string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "corral", "trust")
	}
	return filepath.Join(home, ".local", "state", "corral", "trust")
}

type record struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	ApprovedAt string `json:"approvedAt"`
}

func (s *Store) fileFor(path string) string {
	sum := sha256.Sum256([]byte(path))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

// read loads the stored record for a path. Missing/unreadable/corrupt files report
// (record{}, false): fail toward re-prompt, never toward silent trust.
func (s *Store) read(path string) (record, bool) {
	data, err := os.ReadFile(s.fileFor(path))
	if err != nil {
		return record{}, false
	}
	var rec record
	if err := json.Unmarshal(data, &rec); err != nil {
		return record{}, false
	}
	if rec.SHA256 == "" {
		return record{}, false
	}
	return rec, true
}

func (s *Store) Check(entries []Entry) []Result {
	out := make([]Result, 0, len(entries))
	for _, e := range entries {
		rec, ok := s.read(e.Path)
		switch {
		case !ok:
			out = append(out, Result{Path: e.Path, State: StateNew})
		case rec.SHA256 != e.SHA256:
			out = append(out, Result{Path: e.Path, State: StateChanged})
		default:
			t, _ := time.Parse(time.RFC3339, rec.ApprovedAt)
			out = append(out, Result{Path: e.Path, State: StateApproved, ApprovedAt: t})
		}
	}
	return out
}

func (s *Store) Pending(entries []Entry) []Result {
	var out []Result
	for _, r := range s.Check(entries) {
		if r.NeedsApproval() {
			out = append(out, r)
		}
	}
	return out
}

func (s *Store) Approve(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	now := s.now().UTC().Format(time.RFC3339)
	for _, e := range entries {
		data, err := json.Marshal(record{Path: e.Path, SHA256: e.SHA256, ApprovedAt: now})
		if err != nil {
			return err
		}
		if err := os.WriteFile(s.fileFor(e.Path), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

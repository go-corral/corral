package selfupdate

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// errTransport fails the test on any network request.
type errTransport struct{ t *testing.T }

func (e errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	e.t.Error("network was touched on a throttled cache hit")
	return nil, fmt.Errorf("network must not be touched on a cache hit")
}

func TestCheckOnStartNoticeWhenNewer(t *testing.T) {
	u := fakeRelease(t, "0.4.0", "0.3.0", buildArchive(t, "x"), nil, true)
	state := filepath.Join(t.TempDir(), "update-check.json")
	now := time.Unix(1_700_000_000, 0)

	if latest := CheckOnStart(context.Background(), u, state, DefaultInterval, now); latest != "0.4.0" {
		t.Errorf("CheckOnStart = %q, want 0.4.0", latest)
	}
	latest, when, ok := CachedCheck(state)
	if !ok || latest != "0.4.0" || !when.Equal(now) {
		t.Errorf("CachedCheck = (%q, %v, %v), want (0.4.0, %v, true)", latest, when, ok, now)
	}
}

func TestCheckOnStartNoNoticeWhenCurrent(t *testing.T) {
	u := fakeRelease(t, "0.3.0", "0.3.0", buildArchive(t, "x"), nil, true)
	state := filepath.Join(t.TempDir(), "update-check.json")
	if latest := CheckOnStart(context.Background(), u, state, DefaultInterval, time.Unix(1_700_000_000, 0)); latest != "" {
		t.Errorf("CheckOnStart = %q, want empty (up to date)", latest)
	}
}

func TestCheckOnStartThrottledUsesCache(t *testing.T) {
	state := filepath.Join(t.TempDir(), "update-check.json")
	base := time.Unix(1_700_000_000, 0)
	RecordCheck(state, "0.9.0", base) // a fresh cached result saying 0.9.0 is out

	u := &Updater{
		Source:  Source{APIBase: "http://127.0.0.1:0", Owner: "go-corral", Repo: "corral"},
		Client:  &http.Client{Transport: errTransport{t}},
		Current: "0.3.0",
	}
	if latest := CheckOnStart(context.Background(), u, state, DefaultInterval, base.Add(time.Hour)); latest != "0.9.0" {
		t.Errorf("CheckOnStart = %q, want 0.9.0 from cache with no network", latest)
	}
}

// Failed checks are throttled to avoid probing a down service on every launch.
func TestCheckOnStartFailureStampsTimeNoNotice(t *testing.T) {
	state := filepath.Join(t.TempDir(), "update-check.json")
	now := time.Unix(1_700_000_000, 0)
	u := New(Source{APIBase: "http://127.0.0.1:1", Owner: "go-corral", Repo: "corral"}, "0.3.0")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if latest := CheckOnStart(ctx, u, state, DefaultInterval, now); latest != "" {
		t.Errorf("CheckOnStart = %q, want empty on a failed probe", latest)
	}
	_, when, ok := CachedCheck(state)
	if !ok || !when.Equal(now) {
		t.Errorf("CachedCheck after failure = (%v, %v), want time stamped to now", when, ok)
	}
}

func TestCachedCheckEmpty(t *testing.T) {
	if _, _, ok := CachedCheck(filepath.Join(t.TempDir(), "absent.json")); ok {
		t.Error("CachedCheck on a missing file should report ok=false")
	}
}

func TestStatePath(t *testing.T) {
	got := StatePath("/home/u")
	want := filepath.Join("/home/u", ".cache", "corral", "update-check.json")
	if got != want {
		t.Errorf("StatePath = %q, want %q", got, want)
	}
}

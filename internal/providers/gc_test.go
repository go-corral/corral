package providers

import (
	"context"
	"errors"
	"testing"
)

// fakeReaper is a Provider that also implements Reaper, for GC tests.
type fakeReaper struct {
	fakeProvider
	orphans []Orphan
	gcErr   error
	reaped  []Orphan
	reapErr error
}

func (f *fakeReaper) GC(context.Context) ([]Orphan, error) {
	if f.gcErr != nil {
		return nil, f.gcErr
	}
	return f.orphans, nil
}
func (f *fakeReaper) Reap(_ context.Context, approved []Orphan) error {
	f.reaped = append(f.reaped, approved...)
	return f.reapErr
}

func TestReapersFiltersNonReapers(t *testing.T) {
	broker := &fakeProvider{name: "ssh"}
	reaper := &fakeReaper{fakeProvider: fakeProvider{name: "k8s"}}
	got := Reapers([]Provider{broker, reaper})
	if len(got) != 1 || got[0].Name() != "k8s" {
		t.Errorf("Reapers should keep only the reaper, got %v", got)
	}
}

func TestCollectOrphansAggregatesAndReportsErrors(t *testing.T) {
	r1 := &fakeReaper{fakeProvider: fakeProvider{name: "k8s"}, orphans: []Orphan{{Provider: "k8s", ID: "sa1", Describe: "SA sa1"}}}
	r2 := &fakeReaper{fakeProvider: fakeProvider{name: "vault"}, gcErr: errors.New("unreachable")}
	orphans, errs := CollectOrphans(context.Background(), []Reaper{r1, r2})
	if len(orphans) != 1 || orphans[0].ID != "sa1" {
		t.Errorf("orphans = %+v, want sa1", orphans)
	}
	if len(errs) != 1 {
		t.Errorf("expected 1 reaper error, got %v", errs)
	}
}

func TestReapRoutesToOwningReaper(t *testing.T) {
	r1 := &fakeReaper{fakeProvider: fakeProvider{name: "k8s"}}
	r2 := &fakeReaper{fakeProvider: fakeProvider{name: "vault"}}
	approved := []Orphan{
		{Provider: "k8s", ID: "sa1"},
		{Provider: "vault", ID: "lease1"},
		{Provider: "k8s", ID: "sa2"},
	}
	if errs := Reap(context.Background(), []Reaper{r1, r2}, approved); len(errs) != 0 {
		t.Fatalf("unexpected reap errors: %v", errs)
	}
	if len(r1.reaped) != 2 {
		t.Errorf("k8s reaper should get 2 orphans, got %d", len(r1.reaped))
	}
	if len(r2.reaped) != 1 {
		t.Errorf("vault reaper should get 1 orphan, got %d", len(r2.reaped))
	}
}

func TestReapUnknownProviderReported(t *testing.T) {
	r := &fakeReaper{fakeProvider: fakeProvider{name: "k8s"}}
	errs := Reap(context.Background(), []Reaper{r}, []Orphan{{Provider: "ghost", ID: "x"}})
	if len(errs) != 1 {
		t.Errorf("expected 1 error for unknown provider, got %v", errs)
	}
}

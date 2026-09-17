package providers

import (
	"context"
	"fmt"
)

// Reapers returns the subset of providers that implement Reaper.
func Reapers(ps []Provider) []Reaper {
	var out []Reaper
	for _, p := range ps {
		if r, ok := p.(Reaper); ok {
			out = append(out, r)
		}
	}
	return out
}

// CollectOrphans runs GC() on every reaper and aggregates the previews. It never
// deletes anything — that is Reap's job, after the caller obtains approval.
func CollectOrphans(ctx context.Context, reapers []Reaper) (orphans []Orphan, errs []error) {
	for _, r := range reapers {
		found, err := r.GC(ctx)
		if err != nil {
			errs = append(errs, fmt.Errorf("provider %q: %w", r.Name(), err))
			continue
		}
		orphans = append(orphans, found...)
	}
	return orphans, errs
}

// Reap deletes the approved orphans, routing each to its owning reaper.
func Reap(ctx context.Context, reapers []Reaper, approved []Orphan) []error {
	byName := make(map[string]Reaper, len(reapers))
	for _, r := range reapers {
		byName[r.Name()] = r
	}
	byProvider := map[string][]Orphan{}
	var errs []error
	for _, o := range approved {
		byProvider[o.Provider] = append(byProvider[o.Provider], o)
	}
	for name, group := range byProvider {
		r, ok := byName[name]
		if !ok {
			errs = append(errs, fmt.Errorf("no reaper for provider %q", name))
			continue
		}
		if err := r.Reap(ctx, group); err != nil {
			errs = append(errs, fmt.Errorf("provider %q: %w", name, err))
		}
	}
	return errs
}

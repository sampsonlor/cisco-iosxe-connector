package acmeflow

import (
	"context"
	"errors"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

type cancelSolver struct {
	f           *fixture
	cancel      context.CancelFunc
	denyCleanup bool
}

func (s *cancelSolver) Present(ctx context.Context, c Challenge) error {
	if err := s.f.Present(ctx, c); err != nil {
		return err
	}
	// Model a durable progress revision whose caller did not observe completion
	// before cancellation. Recovery must reload it rather than use stale memory.
	flow, err := s.f.store.ACMEStatus(ctx, s.f.ref)
	if err != nil {
		return err
	}
	if _, err = s.f.store.SaveACME(ctx, s.f.ref, flow.Revision, flow); err != nil {
		return err
	}
	s.cancel()
	return ctx.Err()
}
func (s *cancelSolver) Cleanup(ctx context.Context, c Challenge) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.denyCleanup {
		return errors.New("synthetic DNS permission denial")
	}
	return s.f.Cleanup(ctx, c)
}
func TestCallerCancellationPersistsCleanupBeforeAnyIssuanceResume(t *testing.T) {
	for _, denied := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup-completed", true: "cleanup-restart"}[denied], func(t *testing.T) {
			f := newFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			solver := &cancelSolver{f: f, cancel: cancel, denyCleanup: denied}
			e, err := New(f.config, f.store, f.gate, f.accountKey, solver, f.server.Client())
			must(t, err)
			if _, err = e.Run(ctx, f.ref); !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation lost", err)
			}
			flow, err := f.store.ACMEStatus(context.Background(), f.ref)
			must(t, err)
			if !flow.CancelRequested || len(flow.Challenges) != 1 || flow.Challenges[0].Cleaned == denied {
				t.Fatal("cancel intent or cleanup result not durable")
			}
			f.mu.Lock()
			before := f.requests
			f.mu.Unlock()
			must(t, f.store.Close())
			f.store, err = journal.Open(f.path, f.services)
			must(t, err)
			solver.denyCleanup = false
			e, err = New(f.config, f.store, f.gate, f.accountKey, solver, f.server.Client())
			must(t, err)
			if _, err = e.Run(context.Background(), f.ref); !errors.Is(err, ErrCanceled) {
				t.Fatal("cancelled workflow resumed issuing", err)
			}
			flow, err = f.store.ACMEStatus(context.Background(), f.ref)
			must(t, err)
			if !flow.CancelRequested || !flow.Challenges[0].Cleaned {
				t.Fatal("restart did not complete reference-only cleanup")
			}
			if _, err = e.Run(context.Background(), f.ref); !errors.Is(err, ErrCanceled) {
				t.Fatal(err)
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.requests != before || f.orders != 1 || f.finalizes != 0 || f.cleanups != 1 {
				t.Fatal("cancel replayed DNS/CA mutation")
			}
		})
	}
}

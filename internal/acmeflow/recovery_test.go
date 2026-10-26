package acmeflow

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

func TestProcessingOrderAndZeroDelayCannotRepeatFinalizeOrSpin(t *testing.T) {
	f := newFixture(t)
	f.finalizeProcessing = true
	f.zeroPollDelay = true
	f.config.RunTimeout = 250 * time.Millisecond
	var err error
	f.engine, err = New(f.config, f.store, f.gate, f.accountKey, f, f.server.Client())
	must(t, err)
	for range 3 {
		_, err := f.engine.Run(context.Background(), f.ref)
		if !errors.Is(err, ErrPending) {
			t.Fatal("processing not deferred", err)
		}
		f.advance()
	}
	status, err := f.store.ACMEStatus(context.Background(), f.ref)
	must(t, err)
	f.mu.Lock()
	if f.finalizes != 1 || f.orders != 1 || f.requests > 35 {
		t.Fatal("processing repeated finalize or polled tightly", f.requests)
	}
	f.orderStatus = "valid"
	f.mu.Unlock()
	if status.Stage != journal.ACMEFinalizing {
		t.Fatal("processing intent lost")
	}
	f.untilReady()
}
func TestHTTPDateRetryAfterAndAttemptExhaustionRetainOwnership(t *testing.T) {
	t.Run("HTTP-date", func(t *testing.T) {
		f := newFixture(t)
		at := f.Now().Add(2 * time.Minute)
		f.rateLimits = 1
		f.retryAfter = at.Format(http.TimeFormat)
		_, err := f.engine.Run(context.Background(), f.ref)
		if !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		status, err := f.store.ACMEStatus(context.Background(), f.ref)
		must(t, err)
		if status.NextAttemptAt.Before(at) {
			t.Fatal("date Retry-After shortened")
		}
		f.advance()
		f.untilReady()
	})
	t.Run("attempt-budget", func(t *testing.T) {
		f := newFixture(t)
		f.config.MaxAttempts = 1
		var err error
		f.engine, err = New(f.config, f.store, f.gate, f.accountKey, f, f.server.Client())
		must(t, err)
		if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrExhausted) {
			t.Fatal("attempt budget ignored", err)
		}
		f.mu.Lock()
		before := f.requests
		f.mu.Unlock()
		if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrExhausted) {
			t.Fatal("exhausted work retried", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.requests != before || f.orders != 1 || f.finalizes != 0 {
			t.Fatal("exhaustion dispatched more work")
		}
	})
	t.Run("nonce-budget", func(t *testing.T) {
		f := newFixture(t)
		f.badNonce = 20
		_, err := f.engine.Run(context.Background(), f.ref)
		if err == nil {
			t.Fatal("unbounded nonce failures accepted")
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.orders != 0 || f.requests > 10 || f.signatureErrors != 0 {
			t.Fatal("nonce retry budget or nonce provenance failed")
		}
	})
}

type blockingSolver struct {
	f               *fixture
	entered, finish chan struct{}
}

func (s *blockingSolver) Present(ctx context.Context, c Challenge) error {
	select {
	case s.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.finish:
		return s.f.Present(ctx, c)
	}
}
func (s *blockingSolver) Cleanup(ctx context.Context, c Challenge) error { return s.f.Cleanup(ctx, c) }
func TestConcurrentWorkersAndFailedIntentCannotDispatchSecondOrder(t *testing.T) {
	t.Run("overlap", func(t *testing.T) {
		f := newFixture(t)
		solver := &blockingSolver{f: f, entered: make(chan struct{}, 1), finish: make(chan struct{})}
		engine, err := New(f.config, f.store, f.gate, f.accountKey, solver, f.server.Client())
		must(t, err)
		done := make(chan error, 1)
		go func() { _, err := engine.Run(context.Background(), f.ref); done <- err }()
		select {
		case <-solver.entered:
		case <-time.After(3 * time.Second):
			t.Fatal("solver not entered")
		}
		if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, journal.ErrBusy) {
			t.Fatal("second worker entered", err)
		}
		close(solver.finish)
		if err := <-done; !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		f.advance()
		f.untilReady()
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.orders != 1 || f.finalizes != 1 {
			t.Fatal("overlap duplicated issuance")
		}
	})
	t.Run("intent-commit", func(t *testing.T) {
		f := newFixture(t)
		db, err := sql.Open("sqlite", f.path)
		must(t, err)
		defer db.Close()
		_, err = db.Exec("CREATE TRIGGER reject_order_intent BEFORE UPDATE ON acme_operations BEGIN SELECT RAISE(ABORT,'synthetic private diagnostic'); END")
		must(t, err)
		_, err = f.engine.Run(context.Background(), f.ref)
		if !errors.Is(err, journal.ErrStore) || strings.Contains(err.Error(), "synthetic private diagnostic") {
			t.Fatal("intent failure was bypassed or leaked", err)
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.orders != 0 || f.finalizes != 0 || f.presents != 0 {
			t.Fatal("network/DNS mutation preceded its order intent")
		}
	})
}

func TestHTTPSPolicyRedirectAndCancellationBoundaries(t *testing.T) {
	f := newFixture(t)
	for _, mutate := range []func(*Config){func(c *Config) { c.DirectoryURL = "http://acme.example.test/profiles/test/directory" }, func(c *Config) { c.PolicySHA256 = strings.Repeat("e", 64) }, func(c *Config) { c.AccountKeyRef = "secret-with\nnewline" }, func(c *Config) { c.RunTimeout = 2 * time.Minute }} {
		c := f.config
		mutate(&c)
		if _, err := New(c, f.store, f.gate, f.accountKey, f, f.server.Client()); !errors.Is(err, ErrPolicy) {
			t.Fatal("invalid host policy accepted", err)
		}
	}
	insecure := f.server.Client()
	transport := insecure.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.InsecureSkipVerify = true
	insecure.Transport = transport
	if _, err := New(f.config, f.store, f.gate, f.accountKey, f, insecure); !errors.Is(err, ErrPolicy) {
		t.Fatal("insecure TLS client accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.engine.Run(ctx, f.ref); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled work started", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests != 0 {
		t.Fatal("invalid/cancelled policy accessed network")
	}
}

func TestAccountResponseLossAndDownloadRateLimitDoNotReissue(t *testing.T) {
	for _, mode := range []string{"account-response-loss", "download-rate-limit"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			if mode == "account-response-loss" {
				f.loseAccount = true
			} else {
				f.certRateLimits = 1
			}
			f.untilReady()
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.registrations != 1 || f.orders != 1 || f.finalizes != 1 || f.signatureErrors != 0 {
				t.Fatal("account/download recovery duplicated a mutation")
			}
		})
	}
}

func TestRedirectNeverReachesAnotherProfile(t *testing.T) {
	f := newFixture(t)
	f.redirectDirectory = true
	if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.requests != 1 || f.registrations != 0 || f.orders != 0 {
		t.Fatal("redirect was followed")
	}
}

func TestExpiredOrderCleansOwnedChallengesWithoutNewIssuance(t *testing.T) {
	f := newFixture(t)
	if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	f.advance()
	f.mu.Lock()
	f.expiredOrder = true
	f.mu.Unlock()
	if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrProtocol) {
		t.Fatal("expired order accepted", err)
	}
	status, err := f.store.ACMEStatus(context.Background(), f.ref)
	must(t, err)
	if status.Stage != journal.ACMEInvalid {
		t.Fatal("expired order not retained as invalid")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.cleanups != 2 || f.finalizes != 0 || f.orders != 1 {
		t.Fatal("expired order cleanup or ownership failed")
	}
}

func TestRequestBudgetDefersAndResumesWithoutDuplicateIssuance(t *testing.T) {
	f := newFixture(t)
	f.config.MaxRequests = 8
	var err error
	f.engine, err = New(f.config, f.store, f.gate, f.accountKey, f, f.server.Client())
	must(t, err)
	finished := false
	for range 10 {
		f.mu.Lock()
		before := f.requests
		f.mu.Unlock()
		_, err = f.engine.Run(context.Background(), f.ref)
		f.mu.Lock()
		delta := f.requests - before
		f.mu.Unlock()
		if delta > f.config.MaxRequests {
			t.Fatal("request budget exceeded", delta)
		}
		if err == nil {
			finished = true
			break
		}
		if !errors.Is(err, ErrPending) {
			t.Fatal(err)
		}
		f.advance()
	}
	if !finished {
		t.Fatal("bounded attempts did not resume")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.orders != 1 || f.finalizes != 1 {
		t.Fatal("budget recovery duplicated issuance")
	}
}

package lifecycle_test

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

type importerFunc func(context.Context, journal.Record) error

func (f importerFunc) Import(ctx context.Context, r journal.Record) error { return f(ctx, r) }

func TestRepeatedPushUsesOneDurableImport(t *testing.T) {
	entity := "11111111-2222-4333-8444-555555555555"
	b := journal.Binding{EntityID: entity, LocationID: provider.HTTPSLocationID(entity), DeviceID: "router-a", Target: "192.0.2.10", HostKeySHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), PolicySHA256: strings.Repeat("a", 64), Owner: journal.ILMCore}
	c := journal.Correlation{Binding: b, ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: strings.Repeat("b", 64), StagingTrustpoint: "HTTPS-STAGE-A"}
	services := []journal.Service{{Binding: b, StagingTrustpoints: []string{"HTTPS-STAGE-A"}}}
	path := filepath.Join(t.TempDir(), "journal.sqlite")
	s, err := journal.Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	r, err := s.Begin(ctx, uuid.NewString(), c)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []journal.State{journal.KeyCreating, journal.CSRReady, journal.AwaitingIssuance} {
		r, err = s.Progress(ctx, r.Ref(), r.Revision, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err = s.CertificateReady(ctx, r.Ref(), r.Revision, strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	api, err := lifecycle.NewImportGate(s)
	if err != nil {
		t.Fatal(err)
	}
	worker, _ := lifecycle.NewImportGate(s)
	var calls atomic.Int32
	entered := make(chan struct{})
	finish := make(chan struct{})
	done := make(chan error, 1)
	importer := importerFunc(func(_ context.Context, observed journal.Record) error {
		calls.Add(1)
		if observed.State != journal.Importing || observed.Correlation != c || observed.CertificateSHA256 != r.CertificateSHA256 {
			return errors.New("wrong import intent")
		}
		close(entered)
		<-finish
		return nil
	})
	go func() { _, err := api.Stage(ctx, r.Ref(), r.CertificateSHA256, importer); done <- err }()
	<-entered
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := worker.Stage(ctx, r.Ref(), r.CertificateSHA256, importer); !errors.Is(err, journal.ErrReconcile) {
				t.Errorf("overlapping push did not await reconciliation: %v", err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("overlapping push repeated import", calls.Load())
	}
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for range 5 {
		got, err := api.Stage(ctx, r.Ref(), r.CertificateSHA256, importer)
		if err != nil || got.State != journal.Staged {
			t.Fatal("completed retry not idempotent", err)
		}
	}
	if _, err := api.Stage(ctx, r.Ref(), strings.Repeat("d", 64), importer); !errors.Is(err, journal.ErrCorrelation) {
		t.Fatal("different certificate replay accepted", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = journal.Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	api, _ = lifecycle.NewImportGate(s)
	if got, err := api.Stage(ctx, r.Ref(), r.CertificateSHA256, importer); err != nil || got.State != journal.Staged || calls.Load() != 1 {
		t.Fatal("restart reimported completed certificate", err)
	}
	if _, err := s.Begin(ctx, uuid.NewString(), c); !errors.Is(err, journal.ErrBusy) {
		t.Fatal("STAGED released service lock before activation/recovery", err)
	}
}

func TestCloseWaitsForDispatchedImport(t *testing.T) {
	entity := "11111111-2222-4333-8444-555555555555"
	b := journal.Binding{EntityID: entity, LocationID: provider.HTTPSLocationID(entity), DeviceID: "router-a", Target: "192.0.2.10", HostKeySHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), PolicySHA256: strings.Repeat("a", 64), Owner: journal.ILMCore}
	services := []journal.Service{{Binding: b, StagingTrustpoints: []string{"HTTPS-STAGE-A"}}}
	path := filepath.Join(t.TempDir(), "journal.sqlite")
	s, err := journal.Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	r, err := s.Begin(ctx, uuid.NewString(), journal.Correlation{Binding: b, ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: strings.Repeat("b", 64), StagingTrustpoint: "HTTPS-STAGE-A"})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []journal.State{journal.KeyCreating, journal.CSRReady, journal.AwaitingIssuance} {
		r, err = s.Progress(ctx, r.Ref(), r.Revision, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err = s.CertificateReady(ctx, r.Ref(), r.Revision, strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	gate, _ := lifecycle.NewImportGate(s)
	entered := make(chan struct{})
	finish := make(chan struct{})
	importDone := make(chan error, 1)
	go func() {
		_, err := gate.Stage(ctx, r.Ref(), r.CertificateSHA256, importerFunc(func(context.Context, journal.Record) error { close(entered); <-finish; return nil }))
		importDone <- err
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case <-closed:
		t.Fatal("instance unlocked with an import still running")
	case <-time.After(50 * time.Millisecond):
	}
	if other, err := journal.Open(path, services); !errors.Is(err, journal.ErrInstance) {
		if other != nil {
			_ = other.Close()
		}
		t.Fatal("another instance entered during shutdown", err)
	}
	close(finish)
	if err := <-importDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

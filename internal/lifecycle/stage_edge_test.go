package lifecycle_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lab"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
)

func TestStageFreshTLSBaselineAcrossSuccessAndLostReply(t *testing.T) {
	for _, mode := range []string{"success", "lost-reply", "unexpected-live-certificate"} {
		t.Run(mode, func(t *testing.T) {
			f := newStageFixture(t)
			var changed atomic.Bool
			var handshakes, applications atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { applications.Add(1) }))
			server.TLS = &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				handshakes.Add(1)
				if changed.Load() {
					return &f.candidateTLS, nil
				}
				return &f.baselineTLS, nil
			}}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			root, err := x509.ParseCertificate(f.root)
			stageMust(t, err)
			roots.AddCert(root)
			if mode == "lost-reply" {
				f.backend.lost = true
			}
			if mode == "unexpected-live-certificate" {
				f.backend.after = func() { changed.Store(true) }
			}
			f.gate, err = lifecycle.NewStageGate(f.s, f.v, map[string]string{"router-a": strings.Repeat("e", 64)}, f.backend, func(ctx context.Context, q staging.Request, active []byte) error {
				_, err := lab.ProbeTLS(ctx, server.Listener.Addr().String(), q.CSR.Spec.CommonName, active, roots)
				return err
			})
			stageMust(t, err)
			got, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
			if mode == "success" {
				stageMust(t, err)
				if !got.WithKey {
					t.Fatal("matching key not reported")
				}
			} else if !errors.Is(err, journal.ErrReconcile) || got.WithKey {
				t.Fatal("uncertain result promoted", err)
			}
			if handshakes.Load() < 3 || applications.Load() != 0 || f.backend.imports != 1 {
				t.Fatal("missing fresh before/after TLS or application payload sent", handshakes.Load())
			}
		})
	}
}

func TestStageJournalFailuresCannotDispatchOrLoseUncertainIntent(t *testing.T) {
	for _, mode := range []string{"artifact-write", "import-intent", "completion-write", "settings-rebind", "other-state-changed"} {
		t.Run(mode, func(t *testing.T) {
			f := newStageFixture(t)
			db, err := sql.Open("sqlite", f.path)
			stageMust(t, err)
			defer db.Close()
			statement := ""
			switch mode {
			case "artifact-write":
				statement = "CREATE TRIGGER deny_stage BEFORE INSERT ON staging_operations BEGIN SELECT RAISE(ABORT,'private storage diagnostic'); END"
			case "import-intent":
				statement = "CREATE TRIGGER deny_stage BEFORE UPDATE ON operations WHEN NEW.state='IMPORTING' BEGIN SELECT RAISE(ABORT,'private storage diagnostic'); END"
			case "completion-write":
				statement = "CREATE TRIGGER deny_stage BEFORE UPDATE ON operations WHEN NEW.state='STAGED' BEGIN SELECT RAISE(ABORT,'private storage diagnostic'); END"
			case "settings-rebind", "other-state-changed":
				f.backend.lost = true
			}
			if statement != "" {
				_, err = db.Exec(statement)
				stageMust(t, err)
			}
			got, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
			if err == nil || got.WithKey || strings.Contains(err.Error(), "private storage diagnostic") {
				t.Fatal("storage uncertainty suppressed/leaked", err)
			}
			if mode == "artifact-write" || mode == "import-intent" {
				if f.backend.imports != 0 {
					t.Fatal("effect before durable intent")
				}
				return
			}
			if statement != "" {
				_, err = db.Exec("DROP TRIGGER deny_stage")
				stageMust(t, err)
			}
			stageMust(t, f.s.Close())
			f.s, err = journal.Open(f.path, f.services)
			stageMust(t, err)
			f.rewire(t)
			if mode == "settings-rebind" {
				f.gate, err = lifecycle.NewStageGate(f.s, f.v, map[string]string{"router-a": strings.Repeat("a", 64)}, f.backend, func(context.Context, staging.Request, []byte) error { return nil })
				stageMust(t, err)
			}
			if mode == "other-state-changed" {
				f.backend.obs.OtherStateSHA256 = strings.Repeat("a", 64)
			}
			got, err = f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
			if mode == "completion-write" {
				stageMust(t, err)
				if got.Operation.State != journal.Staged || !got.WithKey {
					t.Fatal("read-only completion failed")
				}
			} else if err == nil || got.WithKey {
				t.Fatal("changed correlation accepted")
			}
			if f.backend.imports != 1 {
				t.Fatal("recovery repeated import")
			}
		})
	}
}

func TestStageRuntimeCannotUseDigestOnlyImportGate(t *testing.T) {
	f := newStageFixture(t)
	gate, err := lifecycle.NewImportGate(f.s)
	stageMust(t, err)
	calls := 0
	_, err = gate.Stage(context.Background(), f.r.Ref(), f.r.CertificateSHA256, importerFunc(func(context.Context, journal.Record) error { calls++; return nil }))
	if !errors.Is(err, journal.ErrState) || calls != 0 {
		t.Fatal("runtime CSR bypassed validated stage gate", err)
	}
}

func TestStageACMECancellationIsCheckedBeforeRealDispatch(t *testing.T) {
	for _, late := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-stage", true: "at-dispatch"}[late], func(t *testing.T) {
			f := newStageFixtureOwner(t, journal.ACMEWorker)
			if late {
				db, err := sql.Open("sqlite", f.path)
				stageMust(t, err)
				defer db.Close()
				f.backend.before = func() {
					_, err := db.Exec("UPDATE acme_operations SET record=json_set(record,'$.Revision',revision+1,'$.CancelRequested',json('true')),revision=revision+1 WHERE operation_id=?", f.r.ID)
					stageMust(t, err)
				}
			} else {
				flow, err := f.s.ACMEStatus(context.Background(), f.r.Ref())
				stageMust(t, err)
				flow.CancelRequested = true
				_, err = f.s.SaveACME(context.Background(), f.r.Ref(), flow.Revision, flow)
				stageMust(t, err)
			}
			got, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
			if err == nil || got.WithKey || f.backend.imports != 0 {
				t.Fatal("cancelled ACME operation dispatched staging", err)
			}
		})
	}
}

func TestStageV4MigrationAndMissingArtifactsFailClosed(t *testing.T) {
	f := newStageFixture(t)
	db, err := sql.Open("sqlite", f.path)
	stageMust(t, err)
	defer db.Close()
	_, err = db.Exec("DROP TABLE staging_operations")
	stageMust(t, err)
	_, err = db.Exec("PRAGMA user_version=4")
	stageMust(t, err)
	stageMust(t, f.s.Close())
	f.s, err = journal.Open(f.path, f.services)
	stageMust(t, err)
	f.rewire(t)
	got, err := f.s.Get(context.Background(), f.r.Ref())
	stageMust(t, err)
	if got != f.r {
		t.Fatal("migration replaced original certificate operation")
	}
	_, err = f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
	stageMust(t, err)
	_, err = db.Exec("DELETE FROM staging_operations")
	stageMust(t, err)
	stageMust(t, f.s.Close())
	if s, err := journal.Open(f.path, f.services); err == nil {
		s.Close()
		t.Fatal("staged CSR without import provenance admitted")
	}
}

func TestStageCloseWaitsThroughDispatchRecheckAndCompletion(t *testing.T) {
	f := newStageFixture(t)
	f.backend.entered = make(chan struct{})
	f.backend.finish = make(chan struct{})
	done := make(chan error, 1)
	go func() { _, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil); done <- err }()
	<-f.backend.entered
	closed := make(chan error, 1)
	go func() { closed <- f.s.Close() }()
	select {
	case err := <-closed:
		t.Fatal("close released dispatched import", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(f.backend.finish)
	select {
	case err := <-done:
		stageMust(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("close deadlocked the dispatch recheck")
	}
	stageMust(t, <-closed)
	var err error
	f.s, err = journal.Open(f.path, f.services)
	stageMust(t, err)
	f.rewire(t)
	got, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
	stageMust(t, err)
	if !got.WithKey || f.backend.imports != 1 {
		t.Fatal("close/restart repeated import")
	}
}

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

package journal

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

func acmeBinding() ACMEBinding {
	return ACMEBinding{DirectoryURL: "https://acme.example.test/profiles/test/directory", AccountKeyRef: "secret://acme/test", AccountKeySHA256: strings.Repeat("c", 64), TLSBundleRef: "bundle://acme/test", SettingsSHA256: strings.Repeat("d", 64)}
}
func acmeOperation(t *testing.T) (*Store, string, []Service, Record, csr.Result) {
	t.Helper()
	p := approved()
	p.Owner = ACMEWorker
	services := []Service{p}
	s, path := openTest(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	c := correlation()
	c.Binding = p.Binding
	r, err := s.Begin(context.Background(), uuid.NewString(), c)
	if err != nil {
		t.Fatal(err)
	}
	material := csrResult(t)
	r, _, err = s.GenerateCSR(context.Background(), r.Ref(), csrSpec(), func(context.Context, csr.Request) (csr.Result, error) { return material, nil })
	if err != nil {
		t.Fatal(err)
	}
	return s, path, services, r, material
}

func TestACMEJournalPreservesCSRAccountAndOrderAcrossRestart(t *testing.T) {
	s, path, services, r, material := acmeOperation(t)
	defer s.Close()
	ctx := context.Background()
	operation, spec, saved, flow, err := s.BeginACME(ctx, r.Ref(), acmeBinding())
	if err != nil || operation.State != AwaitingIssuance || spec.CommonName != csrSpec().CommonName || string(saved.DER) != string(material.DER) || flow.CSRSHA256 != certpolicy.SHA256(material.DER) || flow.Stage != ACMEPreparing {
		t.Fatal("ACME did not bind durable original CSR", err)
	}
	if err := s.BindACMEAccount(ctx, r.Ref(), "https://acme.example.test/profiles/test/acct/a"); err != nil {
		t.Fatal(err)
	}
	flow.Stage = ACMECreating
	flow, err = s.SaveACME(ctx, r.Ref(), flow.Revision, flow)
	if err != nil {
		t.Fatal(err)
	}
	flow.Stage = ACMEBound
	flow.OrderURL = "https://acme.example.test/profiles/test/order/one"
	flow.FinalizeURL = flow.OrderURL + "/finalize"
	flow.AuthorizationURLs = []string{"https://acme.example.test/profiles/test/authz/one"}
	flow, err = s.SaveACME(ctx, r.Ref(), flow.Revision, flow)
	if err != nil {
		t.Fatal(err)
	}
	before := flow
	if _, err := s.SaveACME(ctx, r.Ref(), flow.Revision-1, flow); !errors.Is(err, ErrConflict) {
		t.Fatal("stale ACME revision accepted", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, _, saved, flow, err = s.BeginACME(ctx, r.Ref(), acmeBinding())
	if err != nil || flow.Revision != before.Revision || flow.OrderURL != before.OrderURL || string(saved.DER) != string(material.DER) {
		t.Fatal("restart lost original order or CSR", err)
	}
	account, err := s.ACMEAccount(ctx, r.Ref())
	if err != nil || account != "https://acme.example.test/profiles/test/acct/a" {
		t.Fatal("account association lost", err)
	}
	mutated := acmeBinding()
	mutated.AccountKeyRef = "secret://other/key"
	if _, _, _, _, err := s.BeginACME(ctx, r.Ref(), mutated); !errors.Is(err, ErrCorrelation) {
		t.Fatal("account/CSR operation rebound", err)
	}
	flow.OrderURL = "https://acme.example.test/profiles/test/order/two"
	if _, err := s.SaveACME(ctx, r.Ref(), flow.Revision, flow); err == nil {
		t.Fatal("existing order replaced")
	}
	got, err := s.ACMEStatus(ctx, r.Ref())
	if err != nil || got.OrderURL != before.OrderURL {
		t.Fatal("rejected mutation persisted", err)
	}
}

func TestACMEJournalRejectsUnownedMissingCSRAndUnsafeResources(t *testing.T) {
	s, _ := openTest(t)
	defer s.Close()
	r := begin(t, s)
	if _, _, _, _, err := s.BeginACME(context.Background(), r.Ref(), acmeBinding()); err == nil {
		t.Fatal("native Core owner accepted by ACME")
	}
	p := approved()
	p.Owner = ACMEWorker
	bare, err := Open(filepath.Join(t.TempDir(), "bare.sqlite"), []Service{p})
	if err != nil {
		t.Fatal(err)
	}
	defer bare.Close()
	c := correlation()
	c.Binding = p.Binding
	missing, err := bare.Begin(context.Background(), uuid.NewString(), c)
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range []State{KeyCreating, CSRReady} {
		missing, err = bare.Progress(context.Background(), missing.Ref(), missing.Revision, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, _, err := bare.BeginACME(context.Background(), missing.Ref(), acmeBinding()); !errors.Is(err, ErrState) {
		t.Fatal("missing recorded CSR accepted", err)
	}
	s2, _, _, r2, _ := acmeOperation(t)
	defer s2.Close()
	ctx := context.Background()
	_, _, _, flow, err := s2.BeginACME(ctx, r2.Ref(), acmeBinding())
	if err != nil {
		t.Fatal(err)
	}
	for _, uri := range []string{"http://acme.example.test/profiles/test/acct/a", "https://other.example.test/profiles/test/acct/a", "https://acme.example.test/profiles/other/acct/a", "https://acme.example.test/profiles/test/../other/acct/a", "https://user:password@acme.example.test/profiles/test/acct/a", "https://acme.example.test/profiles/test/acct/a?secret=value"} {
		if err := s2.BindACMEAccount(ctx, r2.Ref(), uri); err == nil {
			t.Fatal("unsafe account resource accepted")
		}
	}
	if _, err := s2.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	flow.Stage = ACMECreating
	if _, err := s2.SaveACME(ctx, r2.Ref(), flow.Revision, flow); !errors.Is(err, ErrStore) {
		t.Fatal("failed intent commit accepted", err)
	}
	if _, err := s2.db.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	got, err := s2.ACMEStatus(ctx, r2.Ref())
	if err != nil || got.Stage != ACMEPreparing {
		t.Fatal("failed intent changed durable stage", err)
	}
	release, err := s2.LockACME(ctx, r2.Ref())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s2.LockACME(ctx, r2.Ref()); !errors.Is(err, ErrBusy) {
		t.Fatal("overlapping ACME worker admitted", err)
	}
	release()
	release()
	release, err = s2.LockACME(ctx, r2.Ref())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestACMESchemaMigrationAndMissingArtifacts(t *testing.T) {
	s, path, services, r, material := acmeOperation(t)
	if _, err := s.db.Exec("DROP TABLE acme_operations"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP TABLE acme_accounts"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA user_version=2"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, _, saved, flow, err := s.BeginACME(context.Background(), r.Ref(), acmeBinding())
	if err != nil || string(saved.DER) != string(material.DER) || flow.Revision != 1 {
		t.Fatal("v2 migration damaged CSR or operation", err)
	}
	flow.NextAttemptAt = time.Now().UTC().Add(time.Hour)
	flow.Attempts = 1
	if _, err := s.SaveACME(context.Background(), r.Ref(), flow.Revision, flow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("DROP TABLE acme_operations"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path, services); err == nil {
		other.Close()
		t.Fatal("v3 missing ACME storage accepted")
	}
}

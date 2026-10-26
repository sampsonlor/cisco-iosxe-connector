package journal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

func csrSpec() csr.Spec {
	return csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test"}, RSABits: 2048}
}
func csrResult(t *testing.T) csr.Result {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "router.example.test"}, DNSNames: []string{"router.example.test"}, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	return csr.Result{DER: der, PublicKeyDER: pub, NonExportable: true}
}

func TestCSRIntentAndRestartNeverRegenerate(t *testing.T) {
	s, path := openTest(t)
	r := begin(t, s)
	result := csrResult(t)
	var calls atomic.Int32
	entered := make(chan struct{})
	finish := make(chan struct{})
	done := make(chan error, 1)
	generate := func(_ context.Context, q csr.Request) (csr.Result, error) {
		calls.Add(1)
		if q.KeyLabel() != csr.KeyLabel(r.ID) || q.Trustpoint != r.Correlation.StagingTrustpoint || q.Target != r.Correlation.Target {
			return csr.Result{}, errors.New("wrong durable request")
		}
		close(entered)
		<-finish
		return result, nil
	}
	go func() { _, _, err := s.GenerateCSR(context.Background(), r.Ref(), csrSpec(), generate); done <- err }()
	<-entered
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := s.GenerateCSR(context.Background(), r.Ref(), csrSpec(), generate); !errors.Is(err, ErrReconcile) {
				t.Errorf("overlap not blocked: %v", err)
			}
		}()
	}
	wg.Wait()
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err := Open(path, []Service{approved()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, der, err := s.GenerateCSR(context.Background(), r.Ref(), csrSpec(), generate)
	if err != nil || got.State != CSRReady || string(der) != string(result.DER) || calls.Load() != 1 {
		t.Fatal("restart lost CSR or regenerated key", err)
	}
	der[0] ^= 1
	_, again, err := s.GenerateCSR(context.Background(), r.Ref(), csrSpec(), generate)
	if err != nil || string(again) != string(result.DER) {
		t.Fatal("caller changed cached CSR", err)
	}
	changed := csrSpec()
	changed.DNSNames = append(changed.DNSNames, "other.example.test")
	if _, _, err := s.GenerateCSR(context.Background(), r.Ref(), changed, generate); !errors.Is(err, ErrCorrelation) {
		t.Fatal("CSR policy replay accepted", err)
	}
	q, err := s.CSRRequest(context.Background(), r.Ref())
	if err != nil || q.OperationID != r.ID {
		t.Fatal("read-only reconciliation request unavailable", err)
	}
}

func TestCSRStorageAndUnknownOutcomeBlockRegeneration(t *testing.T) {
	for _, mode := range []string{"intent-fails", "device-timeout", "bad-csr", "completion-fails"} {
		t.Run(mode, func(t *testing.T) {
			s, path := openTest(t)
			r := begin(t, s)
			result := csrResult(t)
			calls := 0
			if mode == "intent-fails" {
				if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
					t.Fatal(err)
				}
			}
			generate := func(context.Context, csr.Request) (csr.Result, error) {
				calls++
				if mode == "device-timeout" {
					return csr.Result{}, context.DeadlineExceeded
				}
				if mode == "bad-csr" {
					result.DER = []byte("invalid")
				}
				if mode == "completion-fails" {
					_, _ = s.db.Exec("PRAGMA query_only=ON")
				}
				return result, nil
			}
			if _, _, err := s.GenerateCSR(context.Background(), r.Ref(), csrSpec(), generate); err == nil {
				t.Fatal("failure reported CSR_READY")
			}
			if mode == "intent-fails" {
				if calls != 0 {
					t.Fatal("generator ran without intent")
				}
				return
			}
			_ = s.Close()
			reopened, err := Open(path, []Service{approved()})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if _, _, err := reopened.GenerateCSR(context.Background(), r.Ref(), csrSpec(), generate); !errors.Is(err, ErrReconcile) || calls != 1 {
				t.Fatal("unknown key generation was repeated", err)
			}
			pending, err := reopened.Pending(context.Background())
			if err != nil || len(pending) != 1 || pending[0].State != KeyCreating {
				t.Fatal("key intent/lock lost", err)
			}
		})
	}
}

func TestCSRSchemaMigrationPreservesLegacyOperations(t *testing.T) {
	s, path := openTest(t)
	r := begin(t, s)
	for _, table := range []string{"staging_operations", "dns_claims", "acme_operations", "acme_accounts"} {
		if _, err := s.db.Exec("DROP TABLE " + table); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("DROP TABLE csr_operations"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	s, err := Open(path, []Service{approved()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.Get(context.Background(), r.Ref())
	if err != nil || got != r {
		t.Fatal("migration changed legacy operation", err)
	}
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 5 {
		t.Fatal("schema not upgraded", err)
	}
	bad := csrSpec()
	bad.CommonName = strings.Repeat("x", 300)
	calls := 0
	if _, _, err := s.GenerateCSR(context.Background(), r.Ref(), bad, func(context.Context, csr.Request) (csr.Result, error) { calls++; return csr.Result{}, nil }); err == nil || calls != 0 {
		t.Fatal("invalid policy reached generator")
	}
}

func TestCSRSchemaMissingArtifactsFailsStartup(t *testing.T) {
	s, path := openTest(t)
	if _, err := s.db.Exec("DROP TABLE csr_operations"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if reopened, err := Open(path, []Service{approved()}); err == nil {
		_ = reopened.Close()
		t.Fatal("schema v2 with missing CSR table accepted")
	}
}

func TestCSRCallbackCannotChangePersistedSpecification(t *testing.T) {
	s, _ := openTest(t)
	r := begin(t, s)
	result := csrResult(t)
	if _, _, err := s.GenerateCSR(context.Background(), r.Ref(), csrSpec(), func(_ context.Context, q csr.Request) (csr.Result, error) {
		q.Spec.DNSNames[0] = "injected.example.test"
		return result, nil
	}); err != nil {
		t.Fatal("callback mutated trusted canonical specification", err)
	}
	q, err := s.CSRRequest(context.Background(), r.Ref())
	if err != nil || q.Spec.DNSNames[0] != "router.example.test" {
		t.Fatal("stored specification changed", err)
	}
}

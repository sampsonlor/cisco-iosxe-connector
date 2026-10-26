package journal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

type certClockFunc func(context.Context) (certpolicy.TimeReading, error)

func (f certClockFunc) Read(ctx context.Context) (certpolicy.TimeReading, error) { return f(ctx) }

type certEvidenceFunc func(context.Context, string) (certpolicy.EnrollmentEvidence, error)

func (f certEvidenceFunc) Read(ctx context.Context, r string) (certpolicy.EnrollmentEvidence, error) {
	return f(ctx, r)
}

func TestValidatedCertificateUsesRecordedCSRAndDurableCAS(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	material := csrResult(t)
	request, err := x509.ParseCertificateRequest(material.DER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic root issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	p := certpolicy.Policy{ID: "https-policy", Spec: csrSpec(), RAProfileID: "ra-a", RAProfileName: "Friendly RA", AuthorityID: "authority-a", PrincipalRef: "principal://adcs/service", EvidenceRef: "evidence://private/snapshot", BundleRef: "bundle://approved/ca", Roots: [][]byte{rootDER}, IssuerSHA256: []string{certpolicy.SHA256(rootDER)}, Template: certpolicy.Template{Kind: certpolicy.V1, Name: "TechnicalWeb"}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, MinRemaining: time.Hour, MaxLifetime: 3 * 365 * 24 * time.Hour, MaxBackdate: 24 * time.Hour, MaxClockAge: time.Minute, MaxClockError: time.Second, MaxEvidenceAge: 24 * time.Hour}
	var validator *certpolicy.Validator
	denied := false
	validator, err = certpolicy.New(p, certClockFunc(func(context.Context) (certpolicy.TimeReading, error) {
		return certpolicy.TimeReading{Now: now, ObservedAt: now, Synchronized: true}, nil
	}), certEvidenceFunc(func(_ context.Context, ref string) (certpolicy.EnrollmentEvidence, error) {
		return certpolicy.EnrollmentEvidence{Reference: ref, SnapshotSHA256: strings.Repeat("d", 64), PolicySHA256: validator.Digest(), RAProfileID: p.RAProfileID, AuthorityID: p.AuthorityID, PrincipalRef: p.PrincipalRef, IssuerSHA256: p.IssuerSHA256[0], Template: p.Template, ObservedAt: now, ValidUntil: now.Add(time.Hour), RABindingVerified: true, Published: true, CAReadTemplate: true, CARequestCertificates: true, TemplateRead: true, TemplateEnroll: !denied, SubjectSupplyAllowed: true, SANSupplyAllowed: true}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	service := approved()
	service.PolicySHA256 = validator.Digest()
	s, err := Open(filepath.Join(t.TempDir(), "journal.sqlite"), []Service{service})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c := correlation()
	c.Binding = service.Binding
	r, err := s.Begin(ctx, uuid.NewString(), c)
	if err != nil {
		t.Fatal(err)
	}
	r, _, err = s.GenerateCSR(ctx, r.Ref(), csrSpec(), func(context.Context, csr.Request) (csr.Result, error) { return material, nil })
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Progress(ctx, r.Ref(), r.Revision, AwaitingIssuance)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(serial int64, cn string) []byte {
		bmp := []byte{}
		for _, r := range p.Template.Name {
			bmp = append(bmp, byte(r>>8), byte(r))
		}
		ext, _ := asn1.Marshal(asn1.RawValue{Tag: 30, Bytes: bmp})
		c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{"router.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(2, 0, 0), KeyUsage: p.KeyUsage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}, Value: ext}}}
		der, err := x509.CreateCertificate(rand.Reader, c, root, request.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	if _, err := s.CertificateReady(ctx, r.Ref(), r.Revision, strings.Repeat("c", 64)); !errors.Is(err, ErrState) {
		t.Fatal("raw digest bypassed certificate validation", err)
	}
	if _, err := s.CertificateValidated(ctx, r.Ref(), r.Revision, certpolicy.Result{}); err == nil {
		t.Fatal("zero/forged receipt accepted")
	}
	valid := leaf(2, "router.example.test")
	proof, err := validator.Validate(ctx, material, csrSpec(), valid, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertificateValidated(ctx, r.Ref(), r.Revision+1, proof); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision accepted", err)
	}
	unrelated := csrResult(t)
	originalRequest := request
	request, err = x509.ParseCertificateRequest(unrelated.DER)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedLeaf := leaf(20, "router.example.test")
	request = originalRequest
	unrelatedProof, err := validator.Validate(ctx, unrelated, csrSpec(), unrelatedLeaf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertificateValidated(ctx, r.Ref(), r.Revision, unrelatedProof); !errors.Is(err, ErrCorrelation) {
		t.Fatal("receipt for another recorded CSR accepted", err)
	}
	if _, err := s.db.Exec("CREATE TRIGGER reject_certificate BEFORE UPDATE OF state ON operations WHEN NEW.state='CERT_READY' BEGIN SELECT RAISE(ABORT,'synthetic diagnostic'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertificateValidated(ctx, r.Ref(), r.Revision, proof); !errors.Is(err, ErrStore) || strings.Contains(err.Error(), "synthetic diagnostic") {
		t.Fatal("failed commit accepted or exposed SQL diagnostics", err)
	}
	unchanged, err := s.Get(ctx, r.Ref())
	if err != nil || unchanged != r {
		t.Fatal("failed receipt commit changed record", err)
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_certificate"); err != nil {
		t.Fatal(err)
	}
	ready, err := s.CertificateValidated(ctx, r.Ref(), r.Revision, proof)
	if err != nil || ready.State != CertReady || ready.CertificateSHA256 != certpolicy.SHA256(valid) {
		t.Fatal("validated state did not commit", err)
	}
	_, spec, stored, err := s.CertificateMaterial(ctx, r.Ref())
	if err != nil || string(stored.DER) != string(material.DER) || spec.CommonName != "router.example.test" {
		t.Fatal("recorded CSR unavailable", err)
	}
	other := leaf(3, "router.example.test")
	otherProof, err := validator.Validate(ctx, material, csrSpec(), other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CertificateValidated(ctx, ready.Ref(), ready.Revision, otherProof); err == nil {
		t.Fatal("already-bound certificate was replaced")
	}
	denied = true
	if _, err := validator.Validate(ctx, material, csrSpec(), valid, nil); !errors.Is(err, certpolicy.ErrEvidence) {
		t.Fatal("cached certificate bypassed changed permissions", err)
	}
}

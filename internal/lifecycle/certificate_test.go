package lifecycle_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

type validationClock func(context.Context) (certpolicy.TimeReading, error)

func (f validationClock) Read(ctx context.Context) (certpolicy.TimeReading, error) { return f(ctx) }

type validationEvidence func(context.Context, string) (certpolicy.EnrollmentEvidence, error)

func (f validationEvidence) Read(ctx context.Context, r string) (certpolicy.EnrollmentEvidence, error) {
	return f(ctx, r)
}

func TestCertificateGateRejectsBeforeCommitAndRevalidatesRetries(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spec := csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test"}, RSABits: 2048}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: spec.CommonName}, DNSNames: spec.DNSNames, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(4, 0, 0), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	p := certpolicy.Policy{ID: "policy-a", Spec: spec, RAProfileID: "ra-a", AuthorityID: "ca-a", PrincipalRef: "principal://service/a", EvidenceRef: "evidence://private/a", BundleRef: "bundle://approved/a", Roots: [][]byte{caDER}, IssuerSHA256: []string{certpolicy.SHA256(caDER)}, Template: certpolicy.Template{Kind: certpolicy.V1, Name: "TechnicalWeb"}, KeyUsage: x509.KeyUsageDigitalSignature, MinRemaining: time.Hour, MaxLifetime: 3 * 365 * 24 * time.Hour, MaxBackdate: time.Hour, MaxClockAge: time.Minute, MaxClockError: time.Second, MaxEvidenceAge: time.Hour}
	denied := false
	var validator *certpolicy.Validator
	validator, err = certpolicy.New(p, validationClock(func(context.Context) (certpolicy.TimeReading, error) {
		return certpolicy.TimeReading{Now: now, ObservedAt: now, Synchronized: true}, nil
	}), validationEvidence(func(_ context.Context, r string) (certpolicy.EnrollmentEvidence, error) {
		return certpolicy.EnrollmentEvidence{Reference: r, SnapshotSHA256: strings.Repeat("d", 64), PolicySHA256: validator.Digest(), RAProfileID: p.RAProfileID, AuthorityID: p.AuthorityID, PrincipalRef: p.PrincipalRef, IssuerSHA256: p.IssuerSHA256[0], Template: p.Template, ObservedAt: now, ValidUntil: now.Add(time.Hour), RABindingVerified: true, Published: true, CAReadTemplate: true, CARequestCertificates: true, TemplateRead: true, TemplateEnroll: !denied, SubjectSupplyAllowed: true, SANSupplyAllowed: true}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	entity := uuid.NewString()
	b := journal.Binding{EntityID: entity, LocationID: provider.HTTPSLocationID(entity), DeviceID: "router-a", Target: "192.0.2.10", HostKeySHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), PolicySHA256: validator.Digest(), Owner: journal.ACMEWorker}
	services := []journal.Service{{Binding: b, StagingTrustpoints: []string{"HTTPS-STAGE-A"}}}
	path := filepath.Join(t.TempDir(), "journal.sqlite")
	s, err := journal.Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.Begin(ctx, uuid.NewString(), journal.Correlation{Binding: b, ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: strings.Repeat("b", 64), StagingTrustpoint: "HTTPS-STAGE-A"})
	if err != nil {
		t.Fatal(err)
	}
	r, _, err = s.GenerateCSR(ctx, r.Ref(), spec, func(context.Context, csr.Request) (csr.Result, error) {
		return csr.Result{DER: request, PublicKeyDER: pub, NonExportable: true}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Progress(ctx, r.Ref(), r.Revision, journal.AwaitingIssuance)
	if err != nil {
		t.Fatal(err)
	}
	bmp := []byte{}
	for _, c := range p.Template.Name {
		bmp = append(bmp, byte(c>>8), byte(c))
	}
	ext, err := asn1.Marshal(asn1.RawValue{Tag: 30, Bytes: bmp})
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: spec.CommonName}, DNSNames: spec.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(2, 0, 0), KeyUsage: p.KeyUsage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}, Value: ext}}}
	valid, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate.DNSNames = []string{"other.example.test"}
	wrong, err := x509.CreateCertificate(rand.Reader, leafTemplate, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := lifecycle.NewCertificateGate(s, validator)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := gate.Accept(ctx, r.Ref(), wrong, nil); !errors.Is(err, certpolicy.ErrLeaf) {
		t.Fatal("wrong leaf reached ready", err)
	}
	unchanged, err := s.Get(ctx, r.Ref())
	if err != nil || unchanged.State != journal.AwaitingIssuance || unchanged.Revision != r.Revision {
		t.Fatal("failed validation changed intent", err)
	}
	ready, proof, err := gate.Accept(ctx, r.Ref(), valid, nil)
	if err != nil || ready.State != journal.CertReady || proof.CertificateSHA256() != certpolicy.SHA256(valid) {
		t.Fatal("approved leaf rejected", err)
	}
	repeated, _, err := gate.Accept(ctx, r.Ref(), valid, nil)
	if err != nil || repeated.Revision != ready.Revision {
		t.Fatal("same certificate duplicated state", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = journal.Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	gate, err = lifecycle.NewCertificateGate(s, validator)
	if err != nil {
		t.Fatal(err)
	}
	denied = true
	if _, _, err := gate.Accept(ctx, r.Ref(), valid, nil); !errors.Is(err, certpolicy.ErrEvidence) {
		t.Fatal("restart reused outdated permission decision", err)
	}
	unchanged, err = s.Get(ctx, r.Ref())
	if err != nil || unchanged != ready {
		t.Fatal("denied retry changed durable state", err)
	}
}

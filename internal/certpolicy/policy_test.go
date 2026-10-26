package certpolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

type clockFunc func(context.Context) (TimeReading, error)

func (f clockFunc) Read(ctx context.Context) (TimeReading, error) { return f(ctx) }

type evidenceFunc func(context.Context, string) (EnrollmentEvidence, error)

func (f evidenceFunc) Read(ctx context.Context, ref string) (EnrollmentEvidence, error) {
	return f(ctx, ref)
}

type fixture struct {
	p                  Policy
	now                time.Time
	material           csr.Result
	spec               csr.Spec
	root, issuer       *x509.Certificate
	rootKey, issuerKey *ecdsa.PrivateKey
	leafPub            any
	serial             int64
}

func u32(n uint32) *uint32 { return &n }
func templateDER(t *testing.T, identity Template) []byte {
	t.Helper()
	if identity.Kind == V1 {
		b := []byte{}
		for _, r := range identity.Name {
			b = append(b, byte(r>>8), byte(r))
		}
		raw, err := asn1.Marshal(asn1.RawValue{Tag: 30, Bytes: b})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	oid, err := parseOID(identity.OID)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := asn1.Marshal(oid)
	for _, v := range []*uint32{identity.Major, identity.Minor} {
		if v != nil {
			encoded, _ := asn1.Marshal(int64(*v))
			body = append(body, encoded...)
		}
	}
	raw, err := asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func makeCA(t *testing.T, cn string, now time.Time, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(4, 0, 0), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	if parent == nil {
		parent = c
		parentKey = key
	}
	der, err := x509.CreateCertificate(rand.Reader, c, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, key
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Now().UTC().Truncate(time.Second), serial: 1000}
	f.root, f.rootKey = makeCA(t, "Synthetic root", f.now, nil, nil)
	f.issuer, f.issuerKey = makeCA(t, "Synthetic issuer", f.now, f.root, f.rootKey)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.spec = csr.Spec{CommonName: "router.example.test", Organization: "Example", DNSNames: []string{"router.example.test", "router"}, RSABits: 2048}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: f.spec.CommonName, Organization: []string{"Example"}}, DNSNames: f.spec.DNSNames, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	f.material = csr.Result{DER: der, PublicKeyDER: pub, NonExportable: true}
	f.leafPub = &key.PublicKey
	f.p = Policy{ID: "https-policy-a", Spec: f.spec, RAProfileID: "ra-profile-a", RAProfileName: "A friendly RA label", AuthorityID: "authority-a", PrincipalRef: "principal://adcs/connector", EvidenceRef: "evidence://private/template-a", BundleRef: "bundle://approved/ca-a", Roots: [][]byte{f.root.Raw}, Intermediates: [][]byte{f.issuer.Raw}, IssuerSHA256: []string{SHA256(f.issuer.Raw)}, Template: Template{Kind: V2, Name: "InternalWebTemplate", OID: "1.3.6.1.4.1.32473.10.2", Major: u32(3), Minor: u32(5)}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, MinRemaining: 24 * time.Hour, MaxLifetime: 3 * 365 * 24 * time.Hour, MaxBackdate: 24 * time.Hour, MaxClockAge: 5 * time.Minute, MaxClockError: 2 * time.Second, MaxEvidenceAge: 24 * time.Hour}
	return f
}
func (f *fixture) leaf(t *testing.T, change func(*x509.Certificate)) []byte {
	t.Helper()
	f.serial++
	identity := f.p.Template
	oid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 7}
	if identity.Kind == V1 {
		oid = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(f.serial), Subject: pkix.Name{CommonName: f.spec.CommonName, Organization: []string{"Example"}}, DNSNames: append([]string(nil), f.spec.DNSNames...), NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.AddDate(2, 0, 0), KeyUsage: f.p.KeyUsage, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: oid, Value: templateDER(t, identity)}}}
	if change != nil {
		change(c)
	}
	der, err := x509.CreateCertificate(rand.Reader, c, f.issuer, f.leafPub, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
func (f *fixture) validator(t *testing.T, p Policy, clockChange func(*TimeReading), proofChange func(*EnrollmentEvidence)) *Validator {
	t.Helper()
	// The trusted evidence fixture owns its snapshot independently of the
	// constructor input, including version pointers mutated by boundary tests.
	p.Template = cloneTemplate(p.Template)
	p.IssuerSHA256 = append([]string(nil), p.IssuerSHA256...)
	var v *Validator
	clock := clockFunc(func(context.Context) (TimeReading, error) {
		r := TimeReading{Now: f.now, Synchronized: true, ObservedAt: f.now, Uncertainty: time.Second}
		if clockChange != nil {
			clockChange(&r)
		}
		return r, nil
	})
	proof := evidenceFunc(func(_ context.Context, ref string) (EnrollmentEvidence, error) {
		e := EnrollmentEvidence{Reference: ref, SnapshotSHA256: strings.Repeat("d", 64), PolicySHA256: v.Digest(), RAProfileID: p.RAProfileID, AuthorityID: p.AuthorityID, PrincipalRef: p.PrincipalRef, IssuerSHA256: p.IssuerSHA256[0], Template: cloneTemplate(p.Template), ObservedAt: f.now.Add(-time.Minute), ValidUntil: f.now.Add(time.Hour), RABindingVerified: true, Published: true, CAReadTemplate: true, CARequestCertificates: true, TemplateRead: true, TemplateEnroll: true, SubjectSupplyAllowed: true, SANSupplyAllowed: true}
		if proofChange != nil {
			proofChange(&e)
		}
		return e, nil
	})
	var err error
	v, err = New(p, clock, proof)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCertificateMatchesCSRIdentityPurposeAndTime(t *testing.T) {
	f := newFixture(t)
	v := f.validator(t, f.p, nil, nil)
	leaf := f.leaf(t, nil)
	result, err := v.Validate(context.Background(), f.material, f.spec, leaf, nil)
	if err != nil || !result.ValidAt(f.now) || result.CertificateSHA256() != SHA256(leaf) || result.CSRSHA256() != SHA256(f.material.DER) || result.PolicySHA256() != v.Digest() {
		t.Fatal("valid certificate rejected", err)
	}
	for name, change := range map[string]func(*x509.Certificate){"extra-SAN": func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "other.example.test") }, "missing-SAN": func(c *x509.Certificate) { c.DNSNames = nil }, "IP-SAN": func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")} }, "subject": func(c *x509.Certificate) { c.Subject.CommonName = "other.example.test" }, "extra-subject": func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"Unapproved"} }, "client-EKU": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }, "any-EKU": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }, "no-EKU": func(c *x509.Certificate) { c.ExtKeyUsage = nil }, "CA": func(c *x509.Certificate) {
		c.IsCA = true
		c.BasicConstraintsValid = true
		c.KeyUsage |= x509.KeyUsageCertSign
	}, "wrong-KU": func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageKeyEncipherment }, "expired": func(c *x509.Certificate) { c.NotAfter = f.now.Add(-time.Minute) }, "not-yet": func(c *x509.Certificate) { c.NotBefore = f.now.Add(time.Minute) }, "too-short": func(c *x509.Certificate) { c.NotAfter = f.now.Add(time.Hour) }, "too-long": func(c *x509.Certificate) { c.NotAfter = f.now.AddDate(5, 0, 0) }, "backdated": func(c *x509.Certificate) { c.NotBefore = f.now.Add(-48 * time.Hour) }, "critical-extension": func(c *x509.Certificate) {
		c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 32473, 99}, Critical: true, Value: []byte{5, 0}})
	}} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Validate(context.Background(), f.material, f.spec, f.leaf(t, change), nil); err == nil {
				t.Fatal("unapproved certificate accepted")
			}
		})
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.leafPub = &otherKey.PublicKey
	if _, err := v.Validate(context.Background(), f.material, f.spec, f.leaf(t, nil), nil); err == nil {
		t.Fatal("wrong CSR public key accepted")
	}
	copyDER := result.LeafDER()
	copyDER[0] ^= 1
	if bytes.Equal(copyDER, result.LeafDER()) {
		t.Fatal("mutable validation result")
	}
}

func TestApprovedChainAndLeafOnlyBundle(t *testing.T) {
	f := newFixture(t)
	leaf := f.leaf(t, nil)
	p := f.p
	p.Intermediates = nil
	v := f.validator(t, p, nil, nil)
	if _, err := v.Validate(context.Background(), f.material, f.spec, leaf, nil); err == nil {
		t.Fatal("incomplete chain accepted")
	}
	if _, err := v.Validate(context.Background(), f.material, f.spec, leaf, [][]byte{f.issuer.Raw}); err != nil {
		t.Fatal("provided intermediate rejected", err)
	}
	trusted := f.validator(t, f.p, nil, nil)
	if _, err := trusted.Validate(context.Background(), f.material, f.spec, leaf, nil); err != nil {
		t.Fatal("approved cached bundle did not support leaf-only input", err)
	}
	unknown, _ := makeCA(t, "Unknown root", f.now, nil, nil)
	unrelated, _ := makeCA(t, "Unrelated intermediate", f.now, f.root, f.rootKey)
	for name, chain := range map[string][][]byte{"unknown-root": {f.issuer.Raw, unknown.Raw}, "unrelated-CA": {f.issuer.Raw, unrelated.Raw}, "leaf-as-CA": {leaf}, "duplicate": {f.issuer.Raw, f.issuer.Raw}, "malformed": {[]byte("invalid")}} {
		t.Run(name, func(t *testing.T) {
			if _, err := trusted.Validate(context.Background(), f.material, f.spec, leaf, chain); err == nil {
				t.Fatal("unapproved chain accepted")
			}
		})
	}
	p = f.p
	p.Roots = [][]byte{unknown.Raw}
	if _, err := f.validator(t, p, nil, nil).Validate(context.Background(), f.material, f.spec, leaf, nil); err == nil {
		t.Fatal("wrong trust root accepted")
	}
	p = f.p
	p.IssuerSHA256 = []string{SHA256(f.root.Raw)}
	if _, err := f.validator(t, p, nil, nil).Validate(context.Background(), f.material, f.spec, leaf, nil); err == nil {
		t.Fatal("unapproved immediate issuer accepted")
	}
	p = f.p
	p.Roots = nil
	if _, err := New(p, clockFunc(func(context.Context) (TimeReading, error) { return TimeReading{}, nil }), evidenceFunc(func(context.Context, string) (EnrollmentEvidence, error) { return EnrollmentEvidence{}, nil })); err == nil {
		t.Fatal("system trust fallback allowed")
	}
}

func TestADCSNameOIDVersionsAndPermissionEvidence(t *testing.T) {
	f := newFixture(t)
	v := f.validator(t, f.p, nil, nil)
	leaf := f.leaf(t, nil)
	for name, change := range map[string]func(*EnrollmentEvidence){"no-enroll": func(e *EnrollmentEvidence) { e.TemplateEnroll = false }, "no-read": func(e *EnrollmentEvidence) { e.TemplateRead = false }, "CA-read": func(e *EnrollmentEvidence) { e.CAReadTemplate = false }, "CA-request": func(e *EnrollmentEvidence) { e.CARequestCertificates = false }, "unpublished": func(e *EnrollmentEvidence) { e.Published = false }, "RA-binding": func(e *EnrollmentEvidence) { e.RABindingVerified = false }, "wrong-profile": func(e *EnrollmentEvidence) { e.RAProfileID = "other-profile" }, "wrong-principal": func(e *EnrollmentEvidence) { e.PrincipalRef = "principal://other/user" }, "wrong-template": func(e *EnrollmentEvidence) { e.Template.Name = "DisplayNameIsNotTemplateIdentity" }, "wrong-policy": func(e *EnrollmentEvidence) { e.PolicySHA256 = strings.Repeat("a", 64) }, "expired": func(e *EnrollmentEvidence) { e.ValidUntil = f.now.Add(-time.Second) }, "stale": func(e *EnrollmentEvidence) { e.ObservedAt = f.now.Add(-48 * time.Hour) }, "missing-source": func(e *EnrollmentEvidence) { e.SnapshotSHA256 = "" }, "SAN-permission": func(e *EnrollmentEvidence) { e.SANSupplyAllowed = false }} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.validator(t, f.p, nil, change).Validate(context.Background(), f.material, f.spec, leaf, nil); !errors.Is(err, ErrEvidence) {
				t.Fatal("invalid permission evidence accepted", err)
			}
		})
	}
	for _, identity := range []Template{{Kind: V2, Name: f.p.Template.Name, OID: "1.3.6.1.4.1.32473.10.9", Major: u32(3), Minor: u32(5)}, {Kind: V2, Name: f.p.Template.Name, OID: f.p.Template.OID, Major: u32(4), Minor: u32(5)}, {Kind: V2, Name: f.p.Template.Name, OID: f.p.Template.OID, Major: u32(3), Minor: nil}} {
		raw := templateDER(t, identity)
		bad := f.leaf(t, func(c *x509.Certificate) { c.ExtraExtensions[0].Value = raw })
		if _, err := v.Validate(context.Background(), f.material, f.spec, bad, nil); !errors.Is(err, ErrTemplate) {
			t.Fatal("wrong template OID/version accepted", err)
		}
	}
	f.p.Template = Template{Kind: V1, Name: "InternalWebTemplate"}
	legacy := f.validator(t, f.p, nil, nil)
	if _, err := legacy.Validate(context.Background(), f.material, f.spec, f.leaf(t, nil), nil); err != nil {
		t.Fatal("V1 BMP template name rejected", err)
	}
	bad := f.leaf(t, func(c *x509.Certificate) { c.ExtraExtensions[0].Value = []byte{0x1e, 1, 0} })
	if _, err := legacy.Validate(context.Background(), f.material, f.spec, bad, nil); !errors.Is(err, ErrTemplate) {
		t.Fatal("malformed BMP template accepted", err)
	}
	p := f.p
	p.RAProfileName = p.Template.Name
	if legacy.Digest() != f.validator(t, p, nil, nil).Digest() {
		t.Fatal("RA display rename changed authorization identity")
	}
}

func TestValidationClockAndMutableInputBoundaries(t *testing.T) {
	f := newFixture(t)
	leaf := f.leaf(t, nil)
	for name, change := range map[string]func(*TimeReading){"unsynchronized": func(r *TimeReading) { r.Synchronized = false }, "stale": func(r *TimeReading) { r.ObservedAt = f.now.Add(-time.Hour) }, "uncertain": func(r *TimeReading) { r.Uncertainty = time.Hour }, "missing": func(r *TimeReading) { r.Now = time.Time{} }, "future-observation": func(r *TimeReading) { r.ObservedAt = f.now.Add(time.Hour) }} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.validator(t, f.p, change, nil).Validate(context.Background(), f.material, f.spec, leaf, nil); !errors.Is(err, ErrClock) {
				t.Fatal("unsafe clock accepted", err)
			}
		})
	}
	v := f.validator(t, f.p, nil, nil)
	f.p.Roots[0][0] ^= 1
	*f.p.Template.Major = 99
	f.p.Spec.DNSNames[0] = "injected.example.test"
	if _, err := v.Validate(context.Background(), f.material, csr.Spec{CommonName: "router.example.test", Organization: "Example", DNSNames: []string{"router.example.test", "router"}, RSABits: 2048}, leaf, nil); err != nil {
		t.Fatal("constructor retained mutable policy buffers", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Validate(ctx, f.material, f.spec, leaf, nil); err == nil {
		t.Fatal("cancelled validation accepted")
	}
}

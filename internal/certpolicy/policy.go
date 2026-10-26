// Package certpolicy validates public certificates against a recorded device CSR,
// a pinned CA bundle and trusted host-supplied AD CS enrollment evidence. It has
// no network, enrollment, private-key, or device mutation capabilities.
package certpolicy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

var (
	ErrPolicy   = errors.New("certificate policy rejected")
	ErrCSR      = errors.New("recorded CSR rejected")
	ErrLeaf     = errors.New("certificate identity, purpose or validity rejected")
	ErrChain    = errors.New("approved certificate chain required")
	ErrTemplate = errors.New("certificate template identity rejected")
	ErrClock    = errors.New("trusted current time required")
	ErrEvidence = errors.New("current approved enrollment evidence required")
)

type TemplateKind string

const (
	V1 TemplateKind = "v1"
	V2 TemplateKind = "v2"
)

// Name is the technical template name, never an ILM RA Profile display name.
// Nil version pointers require absence; a pointer to zero requires explicit zero.
type Template struct {
	Kind         TemplateKind
	Name, OID    string
	Major, Minor *uint32
}

type Policy struct {
	ID                                         string
	Spec                                       csr.Spec
	RAProfileID, RAProfileName, AuthorityID    string
	PrincipalRef, EvidenceRef, BundleRef       string
	Roots, Intermediates                       [][]byte
	IssuerSHA256                               []string
	Template                                   Template
	KeyUsage                                   x509.KeyUsage
	MinRemaining, MaxLifetime, MaxBackdate     time.Duration
	MaxClockAge, MaxClockError, MaxEvidenceAge time.Duration
}

// Clock is supplied by the host after checking its synchronization source. A
// bare time.Now call cannot assert synchronization or uncertainty by itself.
type TimeReading struct {
	Now, ObservedAt time.Time
	Synchronized    bool
	Uncertainty     time.Duration
}
type Clock interface {
	Read(context.Context) (TimeReading, error)
}

// EnrollmentEvidence is a trusted private snapshot, not caller-provided Core
// attributes or a proof derived from a certificate. The host authenticates its
// source and verifies the effective enrolling principal's current rights.
type EnrollmentEvidence struct {
	Reference, SnapshotSHA256, PolicySHA256              string
	RAProfileID, AuthorityID, PrincipalRef, IssuerSHA256 string
	Template                                             Template
	ObservedAt, ValidUntil                               time.Time
	RABindingVerified, Published, CAReadTemplate         bool
	CARequestCertificates, TemplateRead, TemplateEnroll  bool
	SubjectSupplyAllowed, SANSupplyAllowed               bool
}
type EvidenceSource interface {
	Read(context.Context, string) (EnrollmentEvidence, error)
}

type Validator struct {
	p        Policy
	digest   string
	roots    []*x509.Certificate
	issuers  []*x509.Certificate
	clock    Clock
	evidence EvidenceSource
}

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var templateName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var reference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:/.@_-]{0,255}$`)

func SHA256(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func cloneTemplate(t Template) Template {
	if t.Major != nil {
		n := *t.Major
		t.Major = &n
	}
	if t.Minor != nil {
		n := *t.Minor
		t.Minor = &n
	}
	return t
}
func sameVersion(a, b *uint32) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
func sameTemplate(a, b Template) bool {
	return a.Kind == b.Kind && a.Name == b.Name && a.OID == b.OID && sameVersion(a.Major, b.Major) && sameVersion(a.Minor, b.Minor)
}
func validTemplate(t Template) bool {
	if !templateName.MatchString(t.Name) {
		return false
	}
	if t.Kind == V1 {
		return t.OID == "" && t.Major == nil && t.Minor == nil
	}
	_, err := parseOID(t.OID)
	return t.Kind == V2 && err == nil && (t.Minor == nil || t.Major != nil)
}
func cloneBundle(input [][]byte) [][]byte {
	out := make([][]byte, len(input))
	for i := range input {
		out[i] = bytes.Clone(input[i])
	}
	slices.SortFunc(out, bytes.Compare)
	return slices.CompactFunc(out, bytes.Equal)
}
func modernSignature(s x509.SignatureAlgorithm) bool {
	switch s {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
		return true
	}
	return false
}
func strongKey(key any) bool {
	switch k := key.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048 && k.E == 65537
	case *ecdsa.PublicKey:
		return k.Curve.Params().BitSize >= 256
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	}
	return false
}
func parseCA(der []byte) (*x509.Certificate, error) {
	if len(der) == 0 || len(der) > 64<<10 {
		return nil, ErrChain
	}
	c, err := x509.ParseCertificate(der)
	if err != nil || !c.IsCA || !c.BasicConstraintsValid || c.KeyUsage&x509.KeyUsageCertSign == 0 || len(c.UnhandledCriticalExtensions) != 0 || !modernSignature(c.SignatureAlgorithm) || !strongKey(c.PublicKey) || !c.NotAfter.After(c.NotBefore) {
		return nil, ErrChain
	}
	return c, nil
}

// New freezes all policy buffers. Trust roots are explicit and self-signed;
// operating-system trust and network chain discovery are never fallbacks.
func New(p Policy, clock Clock, source EvidenceSource) (*Validator, error) {
	if clock == nil || source == nil || len(p.Roots) == 0 || len(p.Roots) > 16 || len(p.Intermediates) > 16 || len(p.IssuerSHA256) == 0 || len(p.IssuerSHA256) > 16 {
		return nil, ErrPolicy
	}
	for _, s := range []string{p.ID, p.RAProfileID, p.AuthorityID, p.PrincipalRef, p.EvidenceRef, p.BundleRef} {
		if !reference.MatchString(s) {
			return nil, ErrPolicy
		}
	}
	var err error
	p.Spec, err = csr.Normalize(p.Spec)
	if err != nil || !validTemplate(p.Template) || (p.KeyUsage != x509.KeyUsageDigitalSignature && p.KeyUsage != x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment) || p.MinRemaining <= 0 || p.MaxLifetime <= p.MinRemaining || p.MaxBackdate < 0 || p.MaxBackdate >= p.MaxLifetime || p.MaxClockAge <= 0 || p.MaxClockError < 0 || p.MaxClockError >= p.MinRemaining || p.MaxEvidenceAge <= 0 {
		return nil, ErrPolicy
	}
	p.Template = cloneTemplate(p.Template)
	p.Roots = cloneBundle(p.Roots)
	p.Intermediates = cloneBundle(p.Intermediates)
	p.IssuerSHA256 = slices.Clone(p.IssuerSHA256)
	for _, h := range p.IssuerSHA256 {
		if !hashPattern.MatchString(h) {
			return nil, ErrPolicy
		}
	}
	slices.Sort(p.IssuerSHA256)
	p.IssuerSHA256 = slices.Compact(p.IssuerSHA256)
	v := &Validator{p: p, clock: clock, evidence: source}
	for _, der := range p.Roots {
		c, err := parseCA(der)
		if err != nil || !bytes.Equal(c.RawSubject, c.RawIssuer) || c.CheckSignatureFrom(c) != nil {
			return nil, ErrPolicy
		}
		v.roots = append(v.roots, c)
	}
	for _, der := range p.Intermediates {
		c, err := parseCA(der)
		if err != nil || bytes.Equal(c.RawSubject, c.RawIssuer) {
			return nil, ErrPolicy
		}
		v.issuers = append(v.issuers, c)
	}
	// Display labels do not grant enrollment authority. Every effective security
	// field, including the local bundle and evidence selector, is hashed.
	digestPolicy := p
	digestPolicy.RAProfileName = ""
	raw, err := json.Marshal(digestPolicy)
	if err != nil {
		return nil, ErrPolicy
	}
	v.digest = SHA256(raw)
	return v, nil
}

func (v *Validator) Digest() string {
	if v == nil {
		return ""
	}
	return v.digest
}

// Result is an in-process, short-lived receipt, with no exported writable fields.
// It is not a durable authorization to import after permissions or time change.
type Result struct {
	leaf, csr, policy, source, snapshot string
	der                                 []byte
	chain                               [][]byte
	at, until                           time.Time
}

func (r Result) ValidAt(t time.Time) bool {
	return !t.IsZero() && !r.at.IsZero() && !t.Before(r.at) && t.Before(r.until) && hashPattern.MatchString(r.leaf) && hashPattern.MatchString(r.csr) && hashPattern.MatchString(r.policy)
}
func (r Result) CertificateSHA256() string { return r.leaf }
func (r Result) CSRSHA256() string         { return r.csr }
func (r Result) PolicySHA256() string      { return r.policy }
func (r Result) LeafDER() []byte           { return bytes.Clone(r.der) }
func (r Result) ChainDER() [][]byte {
	out := make([][]byte, len(r.chain))
	for i := range r.chain {
		out[i] = bytes.Clone(r.chain[i])
	}
	return out
}
func (r Result) EvidenceRef() string    { return r.source }
func (r Result) EvidenceSHA256() string { return r.snapshot }
func (r Result) ValidatedAt() time.Time { return r.at }
func (r Result) ValidUntil() time.Time  { return r.until }

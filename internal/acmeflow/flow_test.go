package acmeflow

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
	"golang.org/x/crypto/acme"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type testClock func(context.Context) (certpolicy.TimeReading, error)

func (f testClock) Read(c context.Context) (certpolicy.TimeReading, error) { return f(c) }

type testEvidence func(context.Context, string) (certpolicy.EnrollmentEvidence, error)

func (f testEvidence) Read(c context.Context, r string) (certpolicy.EnrollmentEvidence, error) {
	return f(c, r)
}

type fixture struct {
	t                                                                                           *testing.T
	mu                                                                                          sync.Mutex
	now                                                                                         time.Time
	server                                                                                      *httptest.Server
	store                                                                                       *journal.Store
	path                                                                                        string
	services                                                                                    []journal.Service
	ref                                                                                         journal.Ref
	gate                                                                                        *lifecycle.CertificateGate
	engine                                                                                      *Engine
	config                                                                                      Config
	accountKey                                                                                  *ecdsa.PrivateKey
	caKey                                                                                       *ecdsa.PrivateKey
	ca                                                                                          *x509.Certificate
	material                                                                                    csr.Result
	spec                                                                                        csr.Spec
	account                                                                                     bool
	nonce                                                                                       int
	nonces                                                                                      map[string]bool
	mustUseNonce                                                                                string
	orders, finalizes, registrations, requests, signatureErrors                                 int
	authValid                                                                                   map[string]bool
	prepared                                                                                    map[string]bool
	presents, cleanups                                                                          int
	badNonce, rateLimits                                                                        int
	retryAfter                                                                                  string
	orderStatus                                                                                 string
	leaf                                                                                        []byte
	loseFinalize, loseOrder, externalRequired, httpOnly, wrongAuth, foreignDirectory, wrongLeaf bool
}

const profilePath = "/v1/protocols/acme/test"

func (f *fixture) url(s string) string { return f.server.URL + profilePath + s }
func (f *fixture) Now() time.Time      { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *fixture) Present(_ context.Context, c Challenge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	thumb, err := acme.JWKThumbprint(&f.accountKey.PublicKey)
	if err != nil {
		return err
	}
	h := sha256.Sum256([]byte(c.Token + "." + thumb))
	if c.OperationID != f.ref.ID || !slices.Contains(f.spec.DNSNames, c.Identifier) || c.TXTValue != base64.RawURLEncoding.EncodeToString(h[:]) {
		return errors.New("synthetic solver scope rejected")
	}
	f.prepared[c.AuthorizationURL] = true
	f.presents++
	return nil
}
func (f *fixture) Cleanup(_ context.Context, c Challenge) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.prepared[c.AuthorizationURL] {
		return errors.New("unowned synthetic cleanup")
	}
	f.cleanups++
	return nil
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{t: t, now: time.Now().UTC().Truncate(time.Second), nonces: map[string]bool{}, authValid: map[string]bool{}, prepared: map[string]bool{}, orderStatus: "pending"}
	var err error
	f.accountKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	f.caKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic ACME root"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.AddDate(4, 0, 0), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &f.caKey.PublicKey, f.caKey)
	must(t, err)
	f.ca, err = x509.ParseCertificate(der)
	must(t, err)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	f.spec = csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test", "router-alt.example.test"}, RSABits: 2048}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: f.spec.CommonName}, DNSNames: f.spec.DNSNames, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	must(t, err)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(t, err)
	f.material = csr.Result{DER: request, PublicKeyDER: pub, NonExportable: true}
	p := certpolicy.Policy{ID: "https-policy", Spec: f.spec, RAProfileID: "ra-a", AuthorityID: "authority-a", PrincipalRef: "principal://test/issuer", EvidenceRef: "evidence://test/template", BundleRef: "bundle://test/ca", Roots: [][]byte{der}, IssuerSHA256: []string{certpolicy.SHA256(der)}, Template: certpolicy.Template{Kind: certpolicy.V1, Name: "TechnicalWeb"}, KeyUsage: x509.KeyUsageDigitalSignature, MinRemaining: time.Hour, MaxLifetime: 3 * 365 * 24 * time.Hour, MaxBackdate: 24 * time.Hour, MaxClockAge: time.Minute, MaxClockError: time.Second, MaxEvidenceAge: time.Hour}
	var validator *certpolicy.Validator
	validator, err = certpolicy.New(p, testClock(func(context.Context) (certpolicy.TimeReading, error) {
		n := time.Now().UTC()
		return certpolicy.TimeReading{Now: n, ObservedAt: n, Synchronized: true}, nil
	}), testEvidence(func(_ context.Context, r string) (certpolicy.EnrollmentEvidence, error) {
		n := time.Now().UTC()
		return certpolicy.EnrollmentEvidence{Reference: r, SnapshotSHA256: strings.Repeat("d", 64), PolicySHA256: validator.Digest(), RAProfileID: p.RAProfileID, AuthorityID: p.AuthorityID, PrincipalRef: p.PrincipalRef, IssuerSHA256: p.IssuerSHA256[0], Template: p.Template, ObservedAt: n, ValidUntil: n.Add(time.Hour), RABindingVerified: true, Published: true, CAReadTemplate: true, CARequestCertificates: true, TemplateRead: true, TemplateEnroll: true, SubjectSupplyAllowed: true, SANSupplyAllowed: true}, nil
	}))
	must(t, err)
	entity := uuid.NewString()
	b := journal.Binding{EntityID: entity, LocationID: provider.HTTPSLocationID(entity), DeviceID: "router-a", Target: "192.0.2.10", HostKeySHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), PolicySHA256: validator.Digest(), Owner: journal.ACMEWorker}
	f.services = []journal.Service{{Binding: b, StagingTrustpoints: []string{"HTTPS-STAGE-A"}}}
	f.path = filepath.Join(t.TempDir(), "journal.sqlite")
	f.store, err = journal.Open(f.path, f.services)
	must(t, err)
	r, err := f.store.Begin(context.Background(), uuid.NewString(), journal.Correlation{Binding: b, ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: strings.Repeat("b", 64), StagingTrustpoint: "HTTPS-STAGE-A"})
	must(t, err)
	r, _, err = f.store.GenerateCSR(context.Background(), r.Ref(), f.spec, func(context.Context, csr.Request) (csr.Result, error) { return f.material, nil })
	must(t, err)
	f.ref = r.Ref()
	f.gate, err = lifecycle.NewCertificateGate(f.store, validator)
	must(t, err)
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	f.config = Config{DirectoryURL: f.url("/directory"), AccountKeyRef: "secret://acme/test", TLSBundleRef: "bundle://acme/test", PolicySHA256: validator.Digest(), MinBackoff: time.Second, MaxBackoff: 8 * time.Second, RunTimeout: time.Second, MaxAttempts: 16, MaxRequests: 64, NonceRetries: 2, Now: f.Now}
	f.engine, err = New(f.config, f.store, f.gate, f.accountKey, f, f.server.Client())
	must(t, err)
	t.Cleanup(func() { f.store.Close(); f.server.Close() })
	return f
}
func (f *fixture) order() map[string]any {
	ids := []map[string]string{}
	auth := []string{}
	for i, name := range f.spec.DNSNames {
		ids = append(ids, map[string]string{"type": "dns", "value": name})
		auth = append(auth, f.url(fmt.Sprintf("/authz/%d", i)))
	}
	o := map[string]any{"status": f.orderStatus, "expires": f.now.Add(time.Hour), "identifiers": ids, "authorizations": auth, "finalize": f.url("/order/one/finalize")}
	if f.orderStatus == "valid" {
		o["certificate"] = f.url("/cert/one")
	}
	return o
}
func (f *fixture) challenge(i int) map[string]any {
	typ := "dns-01"
	if f.httpOnly {
		typ = "http-01"
	}
	status := "pending"
	if f.authValid[fmt.Sprint(i)] {
		status = "valid"
	}
	return map[string]any{"type": typ, "status": status, "url": f.url(fmt.Sprintf("/chall/%d", i)), "token": base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("synthetic-challenge-%d", i)))}
}
func (f *fixture) jws(r *http.Request) ([]byte, error) {
	var v struct{ Protected, Payload, Signature string }
	if json.NewDecoder(http.MaxBytesReader(nil, r.Body, 64<<10)).Decode(&v) != nil {
		return nil, errors.New("bad synthetic JWS")
	}
	protected, err := base64.RawURLEncoding.DecodeString(v.Protected)
	if err != nil {
		return nil, err
	}
	var h struct {
		Alg, Nonce, URL, KID string
		JWK                  json.RawMessage
	}
	if json.Unmarshal(protected, &h) != nil || h.Alg != "ES256" || h.URL != f.server.URL+r.URL.Path || !f.nonces[h.Nonce] {
		return nil, errors.New("bad synthetic JWS header/nonce")
	}
	delete(f.nonces, h.Nonce)
	if r.URL.Path == profilePath+"/new-account" {
		if len(h.JWK) == 0 || h.KID != "" {
			return nil, errors.New("missing account JWK")
		}
	} else if h.KID != f.url("/acct/a") {
		return nil, errors.New("wrong account KID")
	}
	if f.mustUseNonce != "" && r.URL.Path == profilePath+"/new-order" {
		if h.Nonce != f.mustUseNonce {
			return nil, errors.New("did not reuse badNonce response nonce")
		}
		f.mustUseNonce = ""
	}
	sig, err := base64.RawURLEncoding.DecodeString(v.Signature)
	if err != nil || len(sig) != 64 {
		return nil, errors.New("bad signature shape")
	}
	hash := sha256.Sum256([]byte(v.Protected + "." + v.Payload))
	if !ecdsa.Verify(&f.accountKey.PublicKey, hash[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("bad signature")
	}
	return base64.RawURLEncoding.DecodeString(v.Payload)
}
func (f *fixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	f.nonce++
	nonce := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("synthetic-nonce-%016d", f.nonce)))
	f.nonces[nonce] = true
	w.Header().Set("Replay-Nonce", nonce)
	w.Header().Set("Content-Type", "application/json")
	respond := func(code int, v any) {
		w.WriteHeader(code)
		if v != nil {
			_ = json.NewEncoder(w).Encode(v)
		}
	}
	problem := func(code int, typ string) {
		respond(code, map[string]string{"type": "urn:ietf:params:acme:error:" + typ, "detail": "synthetic private diagnostic"})
	}
	if r.Method == http.MethodGet && r.URL.Path == profilePath+"/directory" {
		order := f.url("/new-order")
		if f.foreignDirectory {
			order = f.server.URL + "/other-profile/new-order"
		}
		respond(200, map[string]any{"newNonce": f.url("/new-nonce"), "newAccount": f.url("/new-account"), "newOrder": order, "meta": map[string]any{"externalAccountRequired": f.externalRequired}})
		return
	}
	if r.Method == http.MethodHead && r.URL.Path == profilePath+"/new-nonce" {
		w.WriteHeader(200)
		return
	}
	if r.Method != http.MethodPost {
		problem(405, "malformed")
		return
	}
	payload, err := f.jws(r)
	if err != nil {
		f.signatureErrors++
		problem(400, "malformed")
		return
	}
	switch {
	case r.URL.Path == profilePath+"/new-account":
		var a struct{ OnlyReturnExisting bool }
		if json.Unmarshal(payload, &a) != nil {
			problem(400, "malformed")
			return
		}
		if !f.account && a.OnlyReturnExisting {
			problem(400, "accountDoesNotExist")
			return
		}
		code := 200
		if !f.account {
			f.account = true
			f.registrations++
			code = 201
		}
		w.Header().Set("Location", f.url("/acct/a"))
		respond(code, map[string]any{"status": "valid", "orders": f.url("/acct/a/orders")})
	case r.URL.Path == profilePath+"/new-order":
		if f.badNonce > 0 {
			f.badNonce--
			f.mustUseNonce = nonce
			problem(400, "badNonce")
			return
		}
		if f.rateLimits > 0 {
			f.rateLimits--
			w.Header().Set("Retry-After", f.retryAfter)
			problem(429, "rateLimited")
			return
		}
		var o struct{ Identifiers []acme.AuthzID }
		if json.Unmarshal(payload, &o) != nil || len(o.Identifiers) != len(f.spec.DNSNames) {
			problem(400, "malformed")
			return
		}
		f.orders++
		if f.loseOrder {
			f.loseOrder = false
			c, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				c.Close()
			}
			return
		}
		w.Header().Set("Location", f.url("/order/one"))
		respond(201, f.order())
	case strings.HasPrefix(r.URL.Path, profilePath+"/authz/"):
		if len(payload) != 0 {
			problem(400, "malformed")
			return
		}
		var i int
		if _, err := fmt.Sscanf(r.URL.Path, profilePath+"/authz/%d", &i); err != nil || i < 0 || i >= len(f.spec.DNSNames) {
			problem(400, "malformed")
			return
		}
		status := "pending"
		if f.authValid[fmt.Sprint(i)] {
			status = "valid"
		}
		name := f.spec.DNSNames[i]
		if f.wrongAuth {
			name = "unapproved.example.test"
		}
		respond(200, map[string]any{"status": status, "identifier": map[string]string{"type": "dns", "value": name}, "expires": f.now.Add(time.Hour), "challenges": []any{f.challenge(i)}})
	case strings.HasPrefix(r.URL.Path, profilePath+"/chall/"):
		var i int
		if _, err := fmt.Sscanf(r.URL.Path, profilePath+"/chall/%d", &i); err != nil || !f.prepared[f.url(fmt.Sprintf("/authz/%d", i))] {
			problem(400, "unauthorized")
			return
		}
		f.authValid[fmt.Sprint(i)] = true
		if len(f.authValid) == len(f.spec.DNSNames) {
			f.orderStatus = "ready"
		}
		respond(200, f.challenge(i))
	case r.URL.Path == profilePath+"/order/one/finalize":
		f.finalizes++
		var v struct{ CSR string }
		if json.Unmarshal(payload, &v) != nil {
			problem(400, "badCSR")
			return
		}
		der, err := base64.RawURLEncoding.DecodeString(v.CSR)
		if err != nil || !bytes.Equal(der, f.material.DER) {
			problem(400, "badCSR")
			return
		}
		q, err := x509.ParseCertificateRequest(der)
		if err != nil {
			problem(400, "badCSR")
			return
		}
		bmp := []byte{}
		for _, c := range "TechnicalWeb" {
			bmp = append(bmp, byte(c>>8), byte(c))
		}
		ext, _ := asn1.Marshal(asn1.RawValue{Tag: 30, Bytes: bmp})
		leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(100 + f.finalizes)), Subject: q.Subject, DNSNames: q.DNSNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}, Value: ext}}}
		if f.wrongLeaf {
			leaf.DNSNames = []string{"unapproved.example.test"}
		}
		f.leaf, err = x509.CreateCertificate(rand.Reader, leaf, f.ca, q.PublicKey, f.caKey)
		if err != nil {
			problem(500, "serverInternal")
			return
		}
		f.orderStatus = "valid"
		if f.loseFinalize {
			f.loseFinalize = false
			c, _, e := w.(http.Hijacker).Hijack()
			if e == nil {
				c.Close()
			}
			return
		}
		w.Header().Set("Location", f.url("/order/one"))
		respond(200, f.order())
	case r.URL.Path == profilePath+"/order/one":
		if len(payload) != 0 {
			problem(400, "malformed")
			return
		}
		w.Header().Set("Location", f.url("/order/one"))
		respond(200, f.order())
	case r.URL.Path == profilePath+"/cert/one":
		if len(payload) != 0 || len(f.leaf) == 0 {
			problem(400, "malformed")
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.leaf}))
		w.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.ca.Raw}))
	default:
		problem(404, "malformed")
	}
}
func (f *fixture) advance() {
	r, err := f.store.ACMEStatus(context.Background(), f.ref)
	must(f.t, err)
	f.mu.Lock()
	f.now = r.NextAttemptAt.Add(time.Millisecond)
	f.mu.Unlock()
}
func (f *fixture) untilReady() journal.Record {
	f.t.Helper()
	for range 12 {
		r, err := f.engine.Run(context.Background(), f.ref)
		if err == nil {
			return r
		}
		if !errors.Is(err, ErrPending) {
			f.t.Fatal("ACME flow failed", err)
		}
		f.advance()
	}
	f.t.Fatal("flow did not complete")
	return journal.Record{}
}

func TestExternalCSRAndOfferedDNSChallengeThroughSignedHTTPS(t *testing.T) {
	f := newFixture(t)
	r := f.untilReady()
	if r.State != journal.CertReady {
		t.Fatal("certificate not validated into journal")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.orders != 1 || f.finalizes != 1 || f.registrations != 1 || f.presents != 2 || f.cleanups != 2 || f.signatureErrors != 0 {
		t.Fatal("incorrect side effects", f.orders, f.finalizes, f.presents, f.cleanups, f.signatureErrors)
	}
}
func TestFinalizeResponseLossRecoversOriginalOrderAfterRestart(t *testing.T) {
	f := newFixture(t)
	f.loseFinalize = true
	for range 4 {
		_, err := f.engine.Run(context.Background(), f.ref)
		if !errors.Is(err, ErrPending) {
			t.Fatal("lost response was not retained", err)
		}
		f.mu.Lock()
		issued := f.finalizes == 1
		f.mu.Unlock()
		f.advance()
		if issued {
			break
		}
	}
	must(t, f.store.Close())
	var err error
	f.store, err = journal.Open(f.path, f.services)
	must(t, err)
	// The gate is rebound to the reopened Store while retaining the same policy.
	f.gate, err = f.gate.WithJournal(f.store)
	must(t, err)
	f.engine, err = New(f.config, f.store, f.gate, f.accountKey, f, f.server.Client())
	must(t, err)
	r := f.untilReady()
	if r.State != journal.CertReady {
		t.Fatal("recovered certificate not accepted")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.orders != 1 || f.finalizes != 1 || f.registrations != 1 || f.signatureErrors != 0 {
		t.Fatal("restart duplicated issuance or changed identity")
	}
}
func TestBadNonceRetryAndPersistentRateLimitCooldown(t *testing.T) {
	f := newFixture(t)
	f.badNonce = 1
	f.rateLimits = 1
	f.retryAfter = "3"
	if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrPending) {
		t.Fatal("429 did not defer", err)
	}
	status, err := f.store.ACMEStatus(context.Background(), f.ref)
	must(t, err)
	if status.NextAttemptAt.Before(f.Now().Add(3 * time.Second)) {
		t.Fatal("Retry-After shortened")
	}
	f.mu.Lock()
	requests := f.requests
	f.mu.Unlock()
	if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrPending) {
		t.Fatal("cooldown did not persist", err)
	}
	f.mu.Lock()
	if f.requests != requests {
		t.Fatal("cooldown performed network requests")
	}
	f.mu.Unlock()
	f.advance()
	f.untilReady()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.orders != 1 || f.finalizes != 1 || f.signatureErrors != 0 || f.mustUseNonce != "" {
		t.Fatal("nonce/rate-limit handling duplicated or changed request")
	}
}
func TestDirectoryAuthorizationAndEndpointBoundaries(t *testing.T) {
	for _, mode := range []string{"EAB-required", "HTTP-only", "wrong-identifier", "cross-profile", "bad-leaf"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			switch mode {
			case "EAB-required":
				f.externalRequired = true
			case "HTTP-only":
				f.httpOnly = true
			case "wrong-identifier":
				f.wrongAuth = true
			case "cross-profile":
				f.foreignDirectory = true
			case "bad-leaf":
				f.wrongLeaf = true
			}
			for range 5 {
				_, err := f.engine.Run(context.Background(), f.ref)
				if !errors.Is(err, ErrPending) {
					if err == nil {
						t.Fatal("unapproved result accepted")
					}
					break
				}
				f.advance()
			}
			r, err := f.store.Get(context.Background(), f.ref)
			must(t, err)
			if r.State == journal.CertReady {
				t.Fatal("unapproved flow reached ready")
			}
			f.mu.Lock()
			defer f.mu.Unlock()
			if mode != "bad-leaf" && (f.finalizes != 0 || f.presents != 0) {
				t.Fatal("unapproved authorization mutated challenge or issued")
			}
		})
	}
}
func TestLostNewOrderResponseNeverCreatesReplacement(t *testing.T) {
	f := newFixture(t)
	f.loseOrder = true
	if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrReconcile) {
		t.Fatal("unknown creation not retained", err)
	}
	for range 2 {
		if _, err := f.engine.Run(context.Background(), f.ref); !errors.Is(err, ErrReconcile) {
			t.Fatal("unknown creation retried", err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.orders != 1 || f.finalizes != 0 {
		t.Fatal("ambiguous order creation repeated")
	}
}

// Package acmeflow runs a bounded, resumable external-CSR ACME workflow. It does
// not generate certificate keys, implement DNS credentials or import to devices.
package acmeflow

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"golang.org/x/crypto/acme"
)

var (
	ErrPolicy    = errors.New("ACME host policy rejected")
	ErrProtocol  = errors.New("ACME response or authorization rejected")
	ErrPending   = errors.New("ACME operation deferred until its recorded retry time")
	ErrReconcile = errors.New("ACME outcome requires original-order reconciliation")
	ErrExhausted = errors.New("ACME attempt or request budget exhausted")
)

type Config struct {
	DirectoryURL, AccountKeyRef, TLSBundleRef, TermsURL, PolicySHA256 string
	MinBackoff, MaxBackoff, RunTimeout                                time.Duration
	MaxAttempts, MaxRequests, NonceRetries                            int
	Now                                                               func() time.Time
}
type Challenge struct {
	OperationID, Identifier, AuthorizationURL, URL, Token, TXTValue string
	TokenSHA256, TXTValueSHA256                                     string
}

// The backend must durably own/idempotently ensure and clean exactly this
// operation's value. A failed Present can be ambiguous; Cleanup must also work
// from the operation/authorization/hash references without raw token material.
// The real restricted DNS backend is backlog #11, not an implicit system tool.
type Solver interface {
	Present(context.Context, Challenge) error
	Cleanup(context.Context, Challenge) error
}
type Engine struct {
	config    Config
	store     *journal.Store
	gate      *lifecycle.CertificateGate
	key       crypto.Signer
	publicDER []byte
	binding   journal.ACMEBinding
	solver    Solver
	http      *http.Client
}

var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{22,256}$`)
var referencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:/.@_-]{0,255}$`)

func New(c Config, s *journal.Store, g *lifecycle.CertificateGate, key crypto.Signer, solver Solver, client *http.Client) (*Engine, error) {
	if s == nil || g == nil || key == nil || solver == nil || !journal.ValidACMEResource(c.DirectoryURL, c.DirectoryURL) || !referencePattern.MatchString(c.AccountKeyRef) || !referencePattern.MatchString(c.TLSBundleRef) || c.PolicySHA256 != g.PolicySHA256() || c.MinBackoff < time.Second || c.MaxBackoff < c.MinBackoff || c.MaxBackoff > 24*time.Hour || c.RunTimeout <= 0 || c.RunTimeout > time.Minute || c.MaxAttempts < 1 || c.MaxAttempts > 1000 || c.MaxRequests < 8 || c.MaxRequests > 256 || c.NonceRetries < 0 || c.NonceRetries > 5 || len(c.PolicySHA256) != 64 {
		return nil, ErrPolicy
	}
	switch p := key.Public().(type) {
	case *ecdsa.PublicKey:
		if p.Curve.Params().BitSize < 256 {
			return nil, ErrPolicy
		}
	case *rsa.PublicKey:
		if p.N.BitLen() < 2048 || p.E != 65537 {
			return nil, ErrPolicy
		}
	default:
		return nil, ErrPolicy
	}
	pub, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, ErrPolicy
	}
	if c.Now == nil {
		c.Now = func() time.Time { return time.Now().UTC() }
	}
	if c.Now().IsZero() {
		return nil, ErrPolicy
	}
	copyClient := http.Client{}
	if client != nil {
		copyClient = *client
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if copyClient.Transport != nil {
		original, ok := copyClient.Transport.(*http.Transport)
		if !ok {
			return nil, ErrPolicy
		}
		transport = original.Clone()
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.InsecureSkipVerify || transport.TLSClientConfig.MaxVersion != 0 && transport.TLSClientConfig.MaxVersion < tls.VersionTLS12 {
			return nil, ErrPolicy
		}
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
		if transport.TLSClientConfig.RootCAs != nil {
			transport.TLSClientConfig.RootCAs = transport.TLSClientConfig.RootCAs.Clone()
		}
	}
	copyClient.Transport = transport
	copyClient.Jar = nil
	copyClient.Timeout = c.RunTimeout
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrPolicy }
	settings, _ := json.Marshal(struct {
		Directory, KeyRef, TLSRef, Terms, Policy string
		Min, Max, Run                            time.Duration
		Attempts, Requests, Nonce                int
	}{c.DirectoryURL, c.AccountKeyRef, c.TLSBundleRef, c.TermsURL, c.PolicySHA256, c.MinBackoff, c.MaxBackoff, c.RunTimeout, c.MaxAttempts, c.MaxRequests, c.NonceRetries})
	b := journal.ACMEBinding{DirectoryURL: c.DirectoryURL, AccountKeyRef: c.AccountKeyRef, AccountKeySHA256: certpolicy.SHA256(pub), TLSBundleRef: c.TLSBundleRef, SettingsSHA256: certpolicy.SHA256(settings)}
	// The journal applies its stricter reference and digest validation before any
	// protocol I/O. No account key or MAC secret is serialized in this binding.
	return &Engine{config: c, store: s, gate: g, key: key, publicDER: pub, binding: b, solver: solver, http: &copyClient}, nil
}

type guard struct {
	e                    *Engine
	base                 http.RoundTripper
	requests             int
	retryAt              time.Time
	problem, mutationURL string
	mutationAccepted     bool
	badNonce             string
}

func (g *guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if !journal.ValidACMEResource(g.e.config.DirectoryURL, req.URL.String()) || req.Method != http.MethodGet && req.Method != http.MethodHead && req.Method != http.MethodPost {
		return nil, ErrPolicy
	}
	// x/crypto clears its nonce pool on badNonce, including the new response
	// nonce. Retain that one-use server nonce and serve the next nonce HEAD
	// locally so the retry uses the nonce mandated by RFC 8555 section 6.5.
	if req.Method == http.MethodHead && g.badNonce != "" {
		nonce := g.badNonce
		g.badNonce = ""
		return &http.Response{StatusCode: 200, Header: http.Header{"Replay-Nonce": {nonce}}, Body: http.NoBody, Request: req}, nil
	}
	if g.requests >= g.e.config.MaxRequests {
		return nil, ErrExhausted
	}
	g.requests++
	res, err := g.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if req.URL.String() == g.mutationURL && res.StatusCode >= 200 && res.StatusCode < 300 {
		g.mutationAccepted = true
	}
	if after := parseRetryAfter(res.Header.Get("Retry-After"), g.e.config.Now()); after.After(g.retryAt) {
		g.retryAt = after
	}
	limit := int64(512 << 10)
	if res.Header.Get("Content-Type") == "application/pem-certificate-chain" {
		limit = 2 << 20
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	res.Body.Close()
	if err != nil || int64(len(body)) > limit {
		return nil, ErrProtocol
	}
	res.Body = io.NopCloser(bytes.NewReader(body))
	g.problem = ""
	if res.StatusCode >= 400 {
		var p struct{ Type string }
		if json.Unmarshal(body, &p) == nil {
			g.problem = p.Type
		}
		if g.problem == "urn:ietf:params:acme:error:badNonce" {
			n := res.Header.Get("Replay-Nonce")
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(n)
			if err == nil && len(decoded) > 0 && len(n) <= 1024 {
				g.badNonce = n
			}
		}
	}
	// The library's combined finalize method polls internally. A past/zero
	// server delay must not turn it into a tight loop; positive delays stay intact.
	if req.Method == http.MethodPost && res.StatusCode == 200 && res.Header.Get("Retry-After") != "" && !parseRetryAfter(res.Header.Get("Retry-After"), g.e.config.Now()).After(g.e.config.Now()) {
		res.Header = res.Header.Clone()
		res.Header.Set("Retry-After", "1")
	}
	return res, nil
}
func parseRetryAfter(raw string, now time.Time) time.Time {
	if n, err := strconv.ParseUint(raw, 10, 32); err == nil {
		return now.Add(time.Duration(n) * time.Second)
	}
	if at, err := http.ParseTime(raw); err == nil {
		return at.UTC()
	}
	return time.Time{}
}
func (e *Engine) client() (*acme.Client, *guard) {
	g := &guard{e: e, base: e.http.Transport}
	h := *e.http
	h.Transport = g
	c := &acme.Client{Key: e.key, DirectoryURL: e.config.DirectoryURL, HTTPClient: &h, UserAgent: "cisco-iosxe-connector/external-csr"}
	c.RetryBackoff = func(n int, _ *http.Request, res *http.Response) time.Duration {
		// Only a protocol-explicit rejection is replayed in-process. 429 is
		// persisted by the worker; generic 5xx and transport loss are ambiguous.
		if n > e.config.NonceRetries || res.StatusCode != 400 || g.problem != "urn:ietf:params:acme:error:badNonce" || g.badNonce == "" {
			return 0
		}
		d := time.Duration(1<<uint(n-1)) * 10 * time.Millisecond
		if after := parseRetryAfter(res.Header.Get("Retry-After"), e.config.Now()); after.After(e.config.Now().Add(d)) {
			d = after.Sub(e.config.Now())
		}
		return d
	}
	return c, g
}
func explicitRejection(err error, g *guard) bool {
	var p *acme.Error
	return !g.mutationAccepted && errors.As(err, &p) && (p.StatusCode == 429 || p.ProblemType == "urn:ietf:params:acme:error:badNonce")
}

package dns01

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/acmeflow"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func txt(name, value string) dns.RR {
	return &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120}, Txt: []string{value}}
}
func values(rr []dns.RR) []string {
	out := []string{}
	for _, r := range rr {
		if t, ok := r.(*dns.TXT); ok {
			out = append(out, strings.Join(t.Txt, ""))
		}
	}
	return out
}
func has(rr []dns.RR, value string) bool {
	for _, v := range values(rr) {
		if v == value {
			return true
		}
	}
	return false
}

type memoryWire struct {
	mu                                 sync.Mutex
	records                            map[string][]dns.RR
	adds, deletes, opens, conflicts    int
	visibleValue                       bool
	deny, loseAdd, loseDelete, skipAdd bool
	cancel                             context.CancelFunc
}
type memorySession struct{ w *memoryWire }

func (w *memoryWire) open(ctx context.Context) (session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	w.mu.Lock()
	w.opens++
	w.mu.Unlock()
	return &memorySession{w}, nil
}
func (w *memoryWire) visible(_ context.Context, owner, value string, _ ValidationMode) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.visibleValue && has(w.records[owner], value), nil
}
func (s *memorySession) close() error { return nil }
func (s *memorySession) read(ctx context.Context, name string) ([]dns.RR, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.w.mu.Lock()
	defer s.w.mu.Unlock()
	out := []dns.RR{}
	for _, r := range s.w.records[name] {
		out = append(out, dns.Copy(r))
	}
	return out, nil
}
func (s *memorySession) update(ctx context.Context, c change) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	w := s.w
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.deny {
		return ErrDenied
	}
	if w.conflicts > 0 {
		w.conflicts--
		w.records[c.Claim.OwnerName] = append(w.records[c.Claim.OwnerName], txt(c.Claim.OwnerName, fmt.Sprintf("concurrent-%d", w.conflicts)))
		return ErrConflict
	}
	if !sameSet(w.records[c.Claim.OwnerName], c.Before.Data) || !sameSet(w.records[c.Claim.MarkerName], c.Before.Markers) {
		return ErrConflict
	}
	if !c.Remove {
		w.adds++
		if !w.skipAdd {
			w.records[c.Claim.OwnerName] = append(w.records[c.Claim.OwnerName], txt(c.Claim.OwnerName, c.Claim.Request.Value))
			w.records[c.Claim.MarkerName] = append(w.records[c.Claim.MarkerName], txt(c.Claim.MarkerName, c.Claim.Marker))
		}
		if w.cancel != nil {
			w.cancel()
			w.cancel = nil
			return context.Canceled
		}
		if w.loseAdd {
			w.loseAdd = false
			return ErrUnavailable
		}
	} else {
		w.deletes++
		for name, value := range map[string]string{c.Claim.OwnerName: c.Claim.Request.Value, c.Claim.MarkerName: c.Claim.Marker} {
			next := []dns.RR{}
			for _, r := range w.records[name] {
				if t, ok := r.(*dns.TXT); !ok || len(t.Txt) != 1 || t.Txt[0] != value {
					next = append(next, r)
				}
			}
			w.records[name] = next
		}
		if w.loseDelete {
			w.loseDelete = false
			return ErrUnavailable
		}
	}
	return nil
}

type fixture struct {
	s        *journal.Store
	path     string
	services []journal.Service
	cfg      Config
	wire     *memoryWire
	p        *Provider
	material csr.Result
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{wire: &memoryWire{records: map[string][]dns.RR{}, visibleValue: true}}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	spec := csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test"}, RSABits: 2048}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: spec.CommonName}, DNSNames: spec.DNSNames, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	must(t, err)
	pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(t, err)
	f.material = csr.Result{DER: der, PublicKeyDER: pub, NonExportable: true}
	for i := range 2 {
		id := uuid.NewString()
		b := journal.Binding{EntityID: id, LocationID: provider.HTTPSLocationID(id), DeviceID: fmt.Sprintf("router-%d", i), Target: fmt.Sprintf("192.0.2.%d", 10+i), HostKeySHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), PolicySHA256: strings.Repeat("a", 64), Owner: journal.ACMEWorker}
		f.services = append(f.services, journal.Service{Binding: b, StagingTrustpoints: []string{"HTTPS-STAGE-A"}})
	}
	f.path = filepath.Join(t.TempDir(), "journal.sqlite")
	f.s, err = journal.Open(f.path, f.services)
	must(t, err)
	f.cfg = Config{Zone: "example.test.", ServerName: "dns.example.test.", ServerAddress: "192.0.2.53:53", CredentialRef: "secret://dns/test", ViewRef: "view://test/internal", Resolvers: []string{"192.0.2.54:53"}, Mode: VerifiedMultiTXT, Timeout: time.Second, TTL: 120, MaxConflicts: 3}
	for _, svc := range f.services {
		f.cfg.Targets = append(f.cfg.Targets, Target{LocationID: svc.LocationID, PolicySHA256: svc.PolicySHA256, Identifier: spec.CommonName})
	}
	f.p, err = newWithWire(f.cfg, f.s, f.wire)
	must(t, err)
	t.Cleanup(func() { f.s.Close() })
	return f
}
func (f *fixture) challenge(t *testing.T, index int, seed string) acmeflow.Challenge {
	t.Helper()
	ctx := context.Background()
	b := f.services[index].Binding
	r, err := f.s.Begin(ctx, uuid.NewString(), journal.Correlation{Binding: b, ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: strings.Repeat("b", 64), StagingTrustpoint: "HTTPS-STAGE-A"})
	must(t, err)
	r, _, err = f.s.GenerateCSR(ctx, r.Ref(), csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test"}, RSABits: 2048}, func(context.Context, csr.Request) (csr.Result, error) { return f.material, nil })
	must(t, err)
	ab := journal.ACMEBinding{DirectoryURL: "https://acme.example.test/profiles/test/directory", AccountKeyRef: "secret://acme/test", AccountKeySHA256: strings.Repeat("c", 64), TLSBundleRef: "bundle://test/ca", SettingsSHA256: strings.Repeat("d", 64)}
	_, _, _, flow, err := f.s.BeginACME(ctx, r.Ref(), ab)
	must(t, err)
	flow.Stage = journal.ACMECreating
	flow, err = f.s.SaveACME(ctx, r.Ref(), flow.Revision, flow)
	must(t, err)
	base := "https://acme.example.test/profiles/test/" + r.ID
	flow.Stage = journal.ACMEBound
	flow.OrderURL = base + "/order"
	flow.FinalizeURL = base + "/finalize"
	flow.AuthorizationURLs = []string{base + "/authz"}
	val := sha256.Sum256([]byte(seed))
	value := base64.RawURLEncoding.EncodeToString(val[:])
	token := "synthetic-challenge-token-" + seed
	c := acmeflow.Challenge{OperationID: r.ID, Identifier: "router.example.test", AuthorizationURL: base + "/authz", URL: base + "/chall", Token: token, TXTValue: value, TokenSHA256: certpolicy.SHA256([]byte(token)), TXTValueSHA256: certpolicy.SHA256([]byte(value))}
	flow.Challenges = []journal.ACMEChallenge{{AuthorizationURL: c.AuthorizationURL, Identifier: c.Identifier, ChallengeURL: c.URL, TokenSHA256: c.TokenSHA256, TXTValueSHA256: c.TXTValueSHA256}}
	_, err = f.s.SaveACME(ctx, r.Ref(), flow.Revision, flow)
	must(t, err)
	return c
}
func TestDNSPreservesForeignTXTAndCleansOnlyOwnedPair(t *testing.T) {
	f := newFixture(t)
	c := f.challenge(t, 0, "one")
	owner, marker := journal.DNSNames(c.Identifier)
	f.wire.records[owner] = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 120}, Txt: []string{"foreign-", "chunks"}}}
	f.wire.records[marker] = []dns.RR{txt(marker, "foreign-owner-marker")}
	must(t, f.p.Present(context.Background(), c))
	must(t, f.p.Present(context.Background(), c))
	if !has(f.wire.records[owner], c.TXTValue) || f.wire.adds != 1 {
		t.Fatal("presentation not idempotent")
	}
	c.Token = ""
	c.TXTValue = ""
	must(t, f.p.Cleanup(context.Background(), c))
	must(t, f.p.Cleanup(context.Background(), c))
	if !has(f.wire.records[owner], "foreign-chunks") || len(f.wire.records[owner]) != 1 || !has(f.wire.records[marker], "foreign-owner-marker") || len(f.wire.records[marker]) != 1 || f.wire.deletes != 1 {
		t.Fatal("foreign TXT or ownership marker was removed")
	}
}
func TestDNSConcurrentChallengesUseCASAndIndependentOwnership(t *testing.T) {
	f := newFixture(t)
	a := f.challenge(t, 0, "one")
	b := f.challenge(t, 1, "two")
	var wg sync.WaitGroup
	for _, c := range []acmeflow.Challenge{a, b} {
		wg.Add(1)
		go func(c acmeflow.Challenge) {
			defer wg.Done()
			if err := f.p.Present(context.Background(), c); err != nil {
				t.Error(err)
			}
		}(c)
	}
	wg.Wait()
	owner, _ := journal.DNSNames(a.Identifier)
	if !has(f.wire.records[owner], a.TXTValue) || !has(f.wire.records[owner], b.TXTValue) {
		t.Fatal("concurrent challenge lost")
	}
	must(t, f.p.Cleanup(context.Background(), a))
	if has(f.wire.records[owner], a.TXTValue) || !has(f.wire.records[owner], b.TXTValue) {
		t.Fatal("cleanup removed another challenge")
	}
	must(t, f.p.Cleanup(context.Background(), b))
}
func TestDNSLostRepliesRecoverOwnershipAcrossRestart(t *testing.T) {
	f := newFixture(t)
	c := f.challenge(t, 0, "one")
	f.wire.loseAdd = true
	if err := f.p.Present(context.Background(), c); !errors.Is(err, ErrReconcile) {
		t.Fatal("uncertain update not retained", err)
	}
	must(t, f.s.Close())
	var err error
	f.s, err = journal.Open(f.path, f.services)
	must(t, err)
	f.p, err = newWithWire(f.cfg, f.s, f.wire)
	must(t, err)
	f.wire.loseDelete = true
	c.Token = ""
	c.TXTValue = ""
	if err := f.p.Cleanup(context.Background(), c); !errors.Is(err, ErrReconcile) {
		t.Fatal("uncertain cleanup not retained", err)
	}
	must(t, f.p.Cleanup(context.Background(), c))
	owner, marker := journal.DNSNames(c.Identifier)
	if len(f.wire.records[owner]) != 0 || len(f.wire.records[marker]) != 0 || f.wire.adds != 1 || f.wire.deletes != 1 {
		t.Fatal("restart repeated add or broad delete")
	}
}
func TestDNSNeverAdoptsExistingValueOrGuessesUnknownAdd(t *testing.T) {
	t.Run("preexisting-value", func(t *testing.T) {
		f := newFixture(t)
		c := f.challenge(t, 0, "one")
		owner, _ := journal.DNSNames(c.Identifier)
		f.wire.records[owner] = []dns.RR{txt(owner, c.TXTValue)}
		if err := f.p.Present(context.Background(), c); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
		must(t, f.p.Cleanup(context.Background(), c))
		if !has(f.wire.records[owner], c.TXTValue) || f.wire.deletes != 0 {
			t.Fatal("preexisting value was adopted/deleted")
		}
	})
	t.Run("unknown-absent", func(t *testing.T) {
		f := newFixture(t)
		c := f.challenge(t, 0, "one")
		f.wire.loseAdd = true
		f.wire.skipAdd = true
		if err := f.p.Present(context.Background(), c); !errors.Is(err, ErrReconcile) {
			t.Fatal(err)
		}
		if err := f.p.Cleanup(context.Background(), c); !errors.Is(err, ErrReconcile) {
			t.Fatal("absence treated as proof of no pending add", err)
		}
		if f.wire.adds != 1 || f.wire.deletes != 0 {
			t.Fatal("unknown add was replayed or guessed clean")
		}
	})
}
func TestDNSViewPermissionsScopeAndCancellation(t *testing.T) {
	t.Run("single-TXT-compatibility", func(t *testing.T) {
		f := newFixture(t)
		c := f.challenge(t, 0, "one")
		owner, _ := journal.DNSNames(c.Identifier)
		f.wire.records[owner] = []dns.RR{txt(owner, "another-value")}
		f.cfg.Mode = SingleTXT
		var err error
		f.p, err = newWithWire(f.cfg, f.s, f.wire)
		must(t, err)
		if err := f.p.Present(context.Background(), c); !errors.Is(err, ErrView) {
			t.Fatal(err)
		}
		if f.wire.adds != 0 {
			t.Fatal("incompatible view mutated")
		}
	})
	t.Run("propagation", func(t *testing.T) {
		f := newFixture(t)
		c := f.challenge(t, 0, "one")
		f.wire.visibleValue = false
		if err := f.p.Present(context.Background(), c); !errors.Is(err, ErrPropagation) {
			t.Fatal(err)
		}
		f.wire.visibleValue = true
		must(t, f.p.Present(context.Background(), c))
		if f.wire.adds != 1 {
			t.Fatal("propagation wait repeated add")
		}
		must(t, f.p.Cleanup(context.Background(), c))
	})
	t.Run("denied", func(t *testing.T) {
		f := newFixture(t)
		c := f.challenge(t, 0, "one")
		f.wire.deny = true
		if err := f.p.Present(context.Background(), c); !errors.Is(err, ErrDenied) {
			t.Fatal(err)
		}
		must(t, f.p.Cleanup(context.Background(), c))
		if f.wire.adds != 0 || f.wire.deletes != 0 {
			t.Fatal("denied update changed records")
		}
	})
	t.Run("scope", func(t *testing.T) {
		f := newFixture(t)
		c := f.challenge(t, 0, "one")
		c.Identifier = "unapproved.example.test"
		if err := f.p.Present(context.Background(), c); err == nil {
			t.Fatal("forged DNS target accepted")
		}
		if f.wire.opens != 0 {
			t.Fatal("forged target reached DNS")
		}
	})
	t.Run("cancel-after-add", func(t *testing.T) {
		f := newFixture(t)
		c := f.challenge(t, 0, "one")
		ctx, cancel := context.WithCancel(context.Background())
		f.wire.cancel = cancel
		if err := f.p.Present(ctx, c); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		// A canceled wire call preserves its intent. The workflow uses a fresh
		// bounded context to clean it, including when Present never returned.
		must(t, f.p.Cleanup(context.Background(), c))
		owner, marker := journal.DNSNames(c.Identifier)
		if len(f.wire.records[owner]) != 0 || len(f.wire.records[marker]) != 0 {
			t.Fatal("cancellation left owned records")
		}
	})
}

package dns01

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

// This synthetic MIC tests DNS framing/signature enforcement, not Kerberos.
// Production contexts are established by bodgit/gssapi; no test key is used there.
type testMIC struct{}

func (*testMIC) MakeSignature(b []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte("synthetic-loopback-MIC"))
	h.Write(b)
	return h.Sum(nil), nil
}
func (m *testMIC) VerifySignature(b, sig []byte) error {
	want, _ := m.MakeSignature(b)
	if !hmac.Equal(want, sig) {
		return ErrAuthentication
	}
	return nil
}
func (*testMIC) Expiry() time.Time { return time.Now().Add(time.Hour) }
func (*testMIC) Close() error      { return nil }

func startDNS(t *testing.T, handler dns.Handler, auth dns.TsigProvider) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	must(t, err)
	ready := make(chan struct{})
	done := make(chan error, 1)
	server := &dns.Server{Listener: listener, Handler: handler, TsigProvider: auth, ReadTimeout: time.Second, WriteTimeout: time.Second, NotifyStartedFunc: func() { close(ready) }}
	go func() { done <- server.ActivateAndServe() }()
	select {
	case <-ready:
	case err := <-done:
		t.Fatal("loopback DNS did not start", err)
	}
	t.Cleanup(func() {
		must(t, server.Shutdown())
		must(t, <-done)
	})
	return listener.Addr().String()
}

type testSecrets struct{ fail bool }

func (s testSecrets) LoadDNS(context.Context, string) (Credentials, error) {
	if s.fail {
		return Credentials{}, fmt.Errorf("private diagnostic must not escape")
	}
	return Credentials{}, nil
}

type dnsPeer struct {
	t                     *testing.T
	mu                    sync.Mutex
	records               map[string][]dns.RR
	requests              []*dns.Msg
	unsigned, deny, alias bool
	key                   string
}

func (p *dnsPeer) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.requests = append(p.requests, req.Copy())
	res := new(dns.Msg)
	res.SetReply(req)
	res.Authoritative = true
	if len(req.Question) != 1 || req.Opcode != dns.OpcodeQuery && req.Opcode != dns.OpcodeUpdate {
		p.t.Error("unexpected DNS operation")
		res.Rcode = dns.RcodeRefused
	} else if req.IsTsig() != nil && w.TsigStatus() != nil {
		p.t.Error("request signature invalid", w.TsigStatus())
		res.Rcode = dns.RcodeNotAuth
	} else if req.Opcode == dns.OpcodeQuery {
		q := req.Question[0]
		if q.Qtype != dns.TypeTXT || q.Qclass != dns.ClassINET {
			p.t.Error("unexpected query type")
			res.Rcode = dns.RcodeRefused
		} else if p.alias {
			res.Answer = []dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "outside.example.test."}}
		} else {
			res.Answer = cloned(p.records[q.Name])
		}
	} else if req.IsTsig() == nil || p.deny {
		res.Rcode = dns.RcodeRefused
	} else {
		// Independent minimal RFC 2136 authoritative peer: all prerequisites
		// are checked before either name is changed in this same TCP request.
		if req.Question[0] != (dns.Question{Name: "example.test.", Qtype: dns.TypeSOA, Qclass: dns.ClassINET}) {
			p.t.Error("wrong update zone")
			res.Rcode = dns.RcodeNotZone
		}
		sets := map[string][]string{}
		empty := map[string]bool{}
		for _, rr := range req.Answer {
			h := rr.Header()
			if h.Ttl != 0 {
				p.t.Error("nonzero prerequisite TTL")
			}
			if h.Rrtype == dns.TypeCNAME {
				if h.Class != dns.ClassNONE || h.Rdlength != 0 {
					p.t.Error("missing no-alias prerequisite")
				}
				continue
			}
			txt, ok := rr.(*dns.TXT)
			if !ok || h.Class != dns.ClassINET && h.Class != dns.ClassNONE {
				p.t.Error("unsafe prerequisite")
				continue
			}
			if h.Class == dns.ClassNONE {
				empty[h.Name] = true
			} else {
				b, _ := json.Marshal(txt.Txt)
				sets[h.Name] = append(sets[h.Name], string(b))
			}
		}
		for name := range empty {
			if len(p.records[name]) != 0 {
				res.Rcode = dns.RcodeYXRrset
			}
		}
		for name, expected := range sets {
			actual := []string{}
			for _, rr := range p.records[name] {
				b, _ := json.Marshal(rr.(*dns.TXT).Txt)
				actual = append(actual, string(b))
			}
			if !reflect.DeepEqual(stringSet(expected), stringSet(actual)) {
				res.Rcode = dns.RcodeNXRrset
			}
		}
		if res.Rcode == dns.RcodeSuccess {
			if len(req.Ns) != 2 {
				p.t.Error("data and marker not updated atomically")
			}
			for _, rr := range req.Ns {
				txt, ok := rr.(*dns.TXT)
				if !ok || len(txt.Txt) != 1 || txt.Hdr.Class == dns.ClassANY {
					p.t.Error("broad or non-TXT update")
					continue
				}
				name := txt.Hdr.Name
				switch txt.Hdr.Class {
				case dns.ClassINET:
					p.records[name] = append(p.records[name], dns.Copy(txt))
				case dns.ClassNONE:
					if txt.Hdr.Ttl != 0 {
						p.t.Error("delete TTL must be zero")
					}
					kept := []dns.RR{}
					for _, old := range p.records[name] {
						if !reflect.DeepEqual(old.(*dns.TXT).Txt, txt.Txt) {
							kept = append(kept, old)
						}
					}
					p.records[name] = kept
				default:
					p.t.Error("unsafe update class")
				}
			}
		}
	}
	if req.IsTsig() != nil && !p.unsigned {
		res.SetTsig(p.key, gssAlgorithm, 300, time.Now().Unix())
	}
	if err := w.WriteMsg(res); err != nil {
		p.t.Error("loopback write failed", err)
	}
}
func stringSet(s []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range s {
		m[v] = true
	}
	return m
}
func wireFixture(t *testing.T) (*fixture, *adWire, *dnsPeer) {
	t.Helper()
	f := newFixture(t)
	auth := &gssProvider{context: &testMIC{}, name: "loopback.dns.example.test."}
	peer := &dnsPeer{t: t, records: map[string][]dns.RR{}, key: auth.name}
	f.cfg.ServerAddress = startDNS(t, peer, auth)
	f.cfg.Resolvers = []string{f.cfg.ServerAddress}
	w, err := newAD(f.cfg, testSecrets{})
	must(t, err)
	w.negotiate = func(context.Context, Config, Credentials) (authContext, error) { return auth, nil }
	f.p, err = newWithWire(f.cfg, f.s, w)
	must(t, err)
	return f, w, peer
}

func TestADWireSignedAtomicUpdatesPreserveOtherTXT(t *testing.T) {
	f, _, peer := wireFixture(t)
	c := f.challenge(t, 0, "wire")
	owner, marker := journal.DNSNames(c.Identifier)
	foreign := txt(owner, "foreign")
	foreign.(*dns.TXT).Txt = []string{"foreign", "-chunks"}
	peer.records[owner] = []dns.RR{foreign}
	peer.records[marker] = []dns.RR{txt(marker, "foreign-marker")}
	must(t, f.p.Present(context.Background(), c))
	must(t, f.p.Cleanup(context.Background(), c))
	peer.mu.Lock()
	defer peer.mu.Unlock()
	if len(peer.records[owner]) != 1 || len(peer.records[marker]) != 1 || !reflect.DeepEqual(peer.records[owner][0].(*dns.TXT).Txt, []string{"foreign", "-chunks"}) || !has(peer.records[marker], "foreign-marker") {
		t.Fatal("foreign values or TXT chunking changed")
	}
	updates := 0
	for _, req := range peer.requests {
		if req.Opcode != dns.OpcodeUpdate {
			continue
		}
		updates++
		if req.IsTsig() == nil || len(req.Answer) != 4 || len(req.Ns) != 2 {
			t.Fatal("missing signed atomic two-name prerequisites")
		}
	}
	if updates != 2 {
		t.Fatal("update was replayed", updates)
	}
}

func TestADWireRejectsUnsignedAliasAndDeniedReplies(t *testing.T) {
	for _, mode := range []string{"unsigned", "alias", "denied", "credential-error", "wrong-name"} {
		t.Run(mode, func(t *testing.T) {
			f, w, peer := wireFixture(t)
			c := f.challenge(t, 0, mode)
			owner, _ := journal.DNSNames(c.Identifier)
			var want error
			switch mode {
			case "unsigned":
				peer.unsigned = true
				want = ErrAuthentication
			case "alias":
				peer.alias = true
				want = ErrView
			case "denied":
				peer.deny = true
				want = ErrDenied
			case "credential-error":
				w.source = testSecrets{fail: true}
				want = ErrAuthentication
			case "wrong-name":
				s, err := w.open(context.Background())
				must(t, err)
				defer s.close()
				_, err = s.read(context.Background(), "_acme-challenge.foreign.example.test.")
				if !errors.Is(err, ErrPolicy) {
					t.Fatal("foreign read allowed", err)
				}
				peer.mu.Lock()
				defer peer.mu.Unlock()
				if len(peer.requests) != 0 {
					t.Fatal("foreign read sent on wire")
				}
				return
			}
			if err := f.p.Present(context.Background(), c); !errors.Is(err, want) || strings.Contains(err.Error(), "private diagnostic") {
				t.Fatal("unsafe response accepted or diagnostic leaked", err)
			}
			peer.mu.Lock()
			defer peer.mu.Unlock()
			if len(peer.records[owner]) != 0 {
				t.Fatal("rejected request changed records")
			}
		})
	}
}

func TestADResolverViewsCannotUseAliasOrSingleTXTWithMultipleValues(t *testing.T) {
	f, w, peer := wireFixture(t)
	owner, _ := journal.DNSNames("router.example.test")
	peer.records[owner] = []dns.RR{txt(owner, "value"), txt(owner, "other")}
	if _, err := w.visible(context.Background(), owner, "value", SingleTXT); !errors.Is(err, ErrView) {
		t.Fatal(err)
	}
	ok, err := w.visible(context.Background(), owner, "value", VerifiedMultiTXT)
	must(t, err)
	if !ok {
		t.Fatal("approved multi-value view not observed")
	}
	peer.mu.Lock()
	peer.alias = true
	peer.mu.Unlock()
	if _, err := w.visible(context.Background(), owner, "value", VerifiedMultiTXT); !errors.Is(err, ErrView) {
		t.Fatal(err)
	}
	_ = f
}

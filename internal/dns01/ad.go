package dns01

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

const gssAlgorithm = "gss-tsig."

type Credentials struct{ Realm, Username, Password, KerberosConfig string }

func (Credentials) String() string               { return "DNS credentials [redacted]" }
func (Credentials) GoString() string             { return "DNS credentials [redacted]" }
func (Credentials) MarshalJSON() ([]byte, error) { return []byte(`"[redacted]"`), nil }

type CredentialSource interface {
	LoadDNS(context.Context, string) (Credentials, error)
}
type authContext interface {
	dns.TsigProvider
	keyName() string
	expiry() time.Time
	close() error
}
type adWire struct {
	cfg       Config
	source    CredentialSource
	negotiate func(context.Context, Config, Credentials) (authContext, error)
}
type adSession struct {
	wire   *adWire
	client *dns.Client
	auth   authContext
}

func newAD(c Config, source CredentialSource) (*adWire, error) {
	if source == nil {
		return nil, ErrPolicy
	}
	return &adWire{cfg: c, source: source, negotiate: negotiateGSS}, nil
}
func (w *adWire) open(ctx context.Context) (session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	credentials, err := w.source.LoadDNS(ctx, w.cfg.CredentialRef)
	if err != nil {
		return nil, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, err := w.negotiate(ctx, w.cfg, credentials)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		a.close()
		return nil, err
	}
	if a.keyName() == "" || !dns.IsFqdn(a.keyName()) || !a.expiry().After(time.Now().Add(w.cfg.Timeout)) {
		a.close()
		return nil, ErrAuthentication
	}
	return &adSession{wire: w, client: &dns.Client{Net: "tcp", Timeout: w.cfg.Timeout, TsigProvider: a}, auth: a}, nil
}
func (s *adSession) close() error { return s.auth.close() }
func (s *adSession) allowed(name string) bool {
	for _, t := range s.wire.cfg.Targets {
		owner, marker := journal.DNSNames(t.Identifier)
		if name == owner || name == marker {
			return true
		}
	}
	return false
}
func signedResponse(req, res *dns.Msg, key string) bool {
	if res == nil || !res.Response || res.Id != req.Id || res.Opcode != req.Opcode || res.Truncated {
		return false
	}
	// RFC 2136 section 3.8 permits UPDATE responses with no copied sections.
	// ID, opcode and verified GSS TSIG still bind that response to this update.
	if len(res.Question) != len(req.Question) && !(req.Opcode == dns.OpcodeUpdate && len(res.Question) == 0) {
		return false
	}
	for i, q := range res.Question {
		if req.Question[i] != q {
			return false
		}
	}
	t := res.IsTsig()
	return t != nil && dns.CanonicalName(t.Hdr.Name) == dns.CanonicalName(key) && dns.CanonicalName(t.Algorithm) == gssAlgorithm && t.Error == 0
}

// The library honors context deadlines but does not close a socket when a
// context without a deadline is canceled during a read. Own the TCP lifetime.
func exchangeTCP(ctx context.Context, client *dns.Client, msg *dns.Msg, address string) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	res, _, err := client.ExchangeWithConnContext(ctx, msg, conn)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return res, err
}

func (s *adSession) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !s.auth.expiry().After(time.Now()) {
		return nil, ErrAuthentication
	}
	msg.SetTsig(s.auth.keyName(), gssAlgorithm, 300, time.Now().Unix())
	res, err := exchangeTCP(ctx, s.client, msg, s.wire.cfg.ServerAddress)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrUnavailable
	}
	// miekg/dns verifies a present TSIG but does not require one in a reply.
	// Require it explicitly before treating a read or update result as evidence.
	if !signedResponse(msg, res, s.auth.keyName()) {
		return nil, ErrAuthentication
	}
	if res.Rcode == dns.RcodeRefused || res.Rcode == dns.RcodeNotAuth {
		return nil, ErrDenied
	}
	return res, nil
}
func parseTXT(res *dns.Msg, name string, authoritative bool) ([]dns.RR, error) {
	if res == nil || res.Truncated || authoritative && !res.Authoritative || (res.Rcode != dns.RcodeSuccess && res.Rcode != dns.RcodeNameError) || len(res.Answer) > 32 {
		return nil, ErrUnavailable
	}
	out := []dns.RR{}
	seen := map[string]bool{}
	for _, r := range res.Answer {
		t, ok := r.(*dns.TXT)
		if !ok || dns.CanonicalName(t.Hdr.Name) != name || t.Hdr.Class != dns.ClassINET || len(t.Txt) == 0 || len(t.Txt) > 16 {
			return nil, ErrView
		}
		length := 0
		for _, chunk := range t.Txt {
			if len(chunk) > 255 {
				return nil, ErrView
			}
			length += len(chunk)
		}
		if length > 2048 {
			return nil, ErrView
		}
		c := dns.Copy(t)
		c.Header().Name = name
		c.Header().Ttl = 0
		id := c.String()
		if seen[id] {
			return nil, ErrView
		}
		seen[id] = true
		out = append(out, dns.Copy(t))
	}
	if res.Rcode == dns.RcodeNameError && len(out) != 0 {
		return nil, ErrView
	}
	return out, nil
}
func (s *adSession) read(ctx context.Context, name string) ([]dns.RR, error) {
	if !s.allowed(name) {
		return nil, ErrPolicy
	}
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeTXT)
	msg.RecursionDesired = false
	res, err := s.exchange(ctx, msg)
	if err != nil {
		return nil, err
	}
	return parseTXT(res, name, true)
}
func cloned(rr []dns.RR) []dns.RR {
	out := make([]dns.RR, len(rr))
	for i, r := range rr {
		out[i] = dns.Copy(r)
	}
	return out
}
func prerequisites(msg *dns.Msg, name string, before []dns.RR) {
	if len(before) == 0 {
		msg.RRsetNotUsed([]dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT}}})
	} else {
		msg.Used(cloned(before))
	}
	msg.RRsetNotUsed([]dns.RR{&dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME}}})
}
func (s *adSession) update(ctx context.Context, c change) error {
	owner, marker := journal.DNSNames(c.Claim.Request.Identifier)
	if c.Claim.Binding.Zone != s.wire.cfg.Zone || c.Claim.Binding.ServerName != s.wire.cfg.ServerName || c.Claim.Binding.ServerAddress != s.wire.cfg.ServerAddress || c.Claim.OwnerName != owner || c.Claim.MarkerName != marker || !s.allowed(owner) || !s.allowed(marker) || len(c.Claim.Request.Value) != 43 || !strings.HasPrefix(c.Claim.Marker, "ilm-acme-v1:") {
		return ErrPolicy
	}
	msg := new(dns.Msg)
	msg.SetUpdate(s.wire.cfg.Zone)
	prerequisites(msg, owner, c.Before.Data)
	prerequisites(msg, marker, c.Before.Markers)
	rr := []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: s.wire.cfg.TTL}, Txt: []string{c.Claim.Request.Value}}, &dns.TXT{Hdr: dns.RR_Header{Name: marker, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: s.wire.cfg.TTL}, Txt: []string{c.Claim.Marker}}}
	if c.Remove {
		msg.Remove(rr)
	} else {
		if equivalent(c.Before.Data, c.Claim.Request.Value) || exact(c.Before.Markers, c.Claim.Marker) {
			return ErrConflict
		}
		// RRset TTL is shared. Preserve an existing set's TTL when adding our RR.
		if len(c.Before.Data) > 0 {
			rr[0].Header().Ttl = c.Before.Data[0].Header().Ttl
		}
		if len(c.Before.Markers) > 0 {
			rr[1].Header().Ttl = c.Before.Markers[0].Header().Ttl
		}
		msg.Insert(rr)
	}
	res, err := s.exchange(ctx, msg)
	if err != nil {
		return err
	}
	switch res.Rcode {
	case dns.RcodeSuccess:
		return nil
	case dns.RcodeNXRrset, dns.RcodeYXRrset, dns.RcodeNameError, dns.RcodeYXDomain:
		return ErrConflict
	default:
		return ErrUnavailable
	}
}
func (w *adWire) visible(ctx context.Context, owner, value string, mode ValidationMode) (bool, error) {
	for _, address := range w.cfg.Resolvers {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		msg := new(dns.Msg)
		msg.SetQuestion(owner, dns.TypeTXT)
		res, err := exchangeTCP(ctx, &dns.Client{Net: "tcp", Timeout: w.cfg.Timeout}, msg, address)
		if err != nil {
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, ErrUnavailable
		}
		if res == nil || res.Id != msg.Id || !res.Response || res.Opcode != dns.OpcodeQuery || len(res.Question) != 1 || res.Question[0] != msg.Question[0] {
			return false, ErrView
		}
		rr, err := parseTXT(res, owner, false)
		if err != nil {
			return false, err
		}
		if mode == SingleTXT && len(rr) > 1 {
			return false, ErrView
		}
		if !equivalent(rr, value) {
			return false, nil
		}
	}
	return true, nil
}

// gssProvider delegates all cryptography to the established Kerberos context.
type gssProvider struct {
	context gssContext
	name    string
}
type gssContext interface {
	MakeSignature([]byte) ([]byte, error)
	VerifySignature([]byte, []byte) error
	Expiry() time.Time
	Close() error
}

func (p *gssProvider) keyName() string   { return p.name }
func (p *gssProvider) expiry() time.Time { return p.context.Expiry() }
func (p *gssProvider) close() error      { return p.context.Close() }
func (p *gssProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	if dns.CanonicalName(t.Algorithm) != gssAlgorithm || dns.CanonicalName(t.Hdr.Name) != p.name {
		return nil, ErrAuthentication
	}
	return p.context.MakeSignature(msg)
}
func (p *gssProvider) Verify(msg []byte, t *dns.TSIG) error {
	if dns.CanonicalName(t.Algorithm) != gssAlgorithm || dns.CanonicalName(t.Hdr.Name) != p.name {
		return ErrAuthentication
	}
	mac, err := hex.DecodeString(t.MAC)
	if err != nil {
		return ErrAuthentication
	}
	return p.context.VerifySignature(msg, mac)
}

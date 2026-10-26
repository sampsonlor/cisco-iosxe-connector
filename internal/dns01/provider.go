// Package dns01 implements scoped AD DNS challenge ownership and exact cleanup.
// Ownership markers use a separate TXT name, never the ACME challenge RRset.
package dns01

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/acmeflow"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

var (
	ErrPolicy         = errors.New("DNS challenge policy rejected")
	ErrDenied         = errors.New("DNS update permission denied")
	ErrAuthentication = errors.New("DNS GSS-TSIG authentication required")
	ErrUnavailable    = errors.New("DNS service unavailable")
	ErrConflict       = errors.New("DNS ownership or update prerequisite conflict")
	ErrView           = errors.New("DNS validation view does not support this TXT set")
	ErrPropagation    = errors.New("DNS challenge not yet visible in approved resolver view")
	ErrReconcile      = errors.New("DNS update outcome requires ownership reconciliation")
)

type ValidationMode string

const (
	SingleTXT        ValidationMode = "single-txt"
	VerifiedMultiTXT ValidationMode = "verified-multi-txt"
)

type Target struct{ LocationID, PolicySHA256, Identifier string }
type Config struct {
	Zone, ServerName, ServerAddress, CredentialRef, ViewRef string
	Targets                                                 []Target
	Resolvers                                               []string
	Mode                                                    ValidationMode
	Timeout                                                 time.Duration
	TTL                                                     uint32
	MaxConflicts                                            int
}
type snapshot struct{ Data, Markers []dns.RR }
type change struct {
	Claim  journal.DNSOwnership
	Before snapshot
	Remove bool
}
type session interface {
	read(context.Context, string) ([]dns.RR, error)
	update(context.Context, change) error
	close() error
}
type wire interface {
	open(context.Context) (session, error)
	visible(context.Context, string, string, ValidationMode) (bool, error)
}
type Provider struct {
	cfg    Config
	digest string
	store  *journal.Store
	wire   wire
}

var _ acmeflow.Solver = (*Provider)(nil)

var configReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:/.@_-]{0,255}$`)
var configDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)

func canonicalConfig(c Config) (Config, string, error) {
	if c.Mode == "" {
		c.Mode = SingleTXT
	}
	if !journal.DNSIdentifier(strings.TrimSuffix(c.Zone, ".")) || !strings.HasSuffix(c.Zone, ".") || !journal.DNSIdentifier(strings.TrimSuffix(c.ServerName, ".")) || !strings.HasSuffix(c.ServerName, ".") || c.Timeout <= 0 || c.Timeout > 30*time.Second || c.TTL < 30 || c.TTL > 3600 || c.MaxConflicts < 1 || c.MaxConflicts > 8 || c.Mode != SingleTXT && c.Mode != VerifiedMultiTXT || !configReference.MatchString(c.CredentialRef) || !configReference.MatchString(c.ViewRef) || len(c.Targets) == 0 || len(c.Targets) > 64 || len(c.Resolvers) == 0 || len(c.Resolvers) > 4 {
		return Config{}, "", ErrPolicy
	}
	for _, raw := range append([]string{c.ServerAddress}, c.Resolvers...) {
		a, err := netip.ParseAddrPort(raw)
		if err != nil || a.Port() == 0 || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Addr().Is4In6() || a.String() != raw {
			return Config{}, "", ErrPolicy
		}
	}
	c.Targets = slices.Clone(c.Targets)
	c.Resolvers = slices.Clone(c.Resolvers)
	slices.Sort(c.Resolvers)
	c.Resolvers = slices.Compact(c.Resolvers)
	slices.SortFunc(c.Targets, func(a, b Target) int {
		return strings.Compare(a.LocationID+":"+a.Identifier, b.LocationID+":"+b.Identifier)
	})
	for i, t := range c.Targets {
		owner, marker := journal.DNSNames(t.Identifier)
		id, err := uuid.Parse(t.LocationID)
		if !journal.DNSIdentifier(t.Identifier) || !strings.HasSuffix(owner, "."+c.Zone) || len(marker) > 253 || err != nil || id == uuid.Nil || id.String() != t.LocationID || !configDigest.MatchString(t.PolicySHA256) || i > 0 && c.Targets[i-1].LocationID == t.LocationID && c.Targets[i-1].Identifier == t.Identifier {
			return Config{}, "", ErrPolicy
		}
	}
	raw, _ := json.Marshal(c)
	return c, certpolicy.SHA256(raw), nil
}
func New(c Config, s *journal.Store, credentials CredentialSource) (*Provider, error) {
	c, digest, err := canonicalConfig(c)
	if err != nil || s == nil || credentials == nil {
		return nil, ErrPolicy
	}
	w, err := newAD(c, credentials)
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: c, digest: digest, store: s, wire: w}, nil
}
func newWithWire(c Config, s *journal.Store, w wire) (*Provider, error) {
	c, h, err := canonicalConfig(c)
	if err != nil || s == nil || w == nil {
		return nil, ErrPolicy
	}
	return &Provider{cfg: c, digest: h, store: s, wire: w}, nil
}
func request(c acmeflow.Challenge) journal.DNSRequest {
	return journal.DNSRequest{OperationID: c.OperationID, AuthorizationURL: c.AuthorizationURL, Identifier: c.Identifier, ChallengeURL: c.URL, TokenSHA256: c.TokenSHA256, ValueSHA256: c.TXTValueSHA256, Value: c.TXTValue}
}
func (p *Provider) binding(ctx context.Context, c acmeflow.Challenge) (journal.DNSRequest, journal.DNSBinding, error) {
	if p == nil || p.store == nil || p.wire == nil {
		return journal.DNSRequest{}, journal.DNSBinding{}, ErrPolicy
	}
	q := request(c)
	if c.Token != "" && certpolicy.SHA256([]byte(c.Token)) != q.TokenSHA256 {
		return q, journal.DNSBinding{}, ErrPolicy
	}
	r, err := p.store.DNSOperation(ctx, q)
	if err != nil {
		return q, journal.DNSBinding{}, err
	}
	for _, t := range p.cfg.Targets {
		if r.Correlation.LocationID == t.LocationID && r.Correlation.PolicySHA256 == t.PolicySHA256 && c.Identifier == t.Identifier {
			return q, journal.DNSBinding{ConfigSHA256: p.digest, PolicySHA256: t.PolicySHA256, CredentialRef: p.cfg.CredentialRef, ViewRef: p.cfg.ViewRef, Zone: p.cfg.Zone, ServerName: p.cfg.ServerName, ServerAddress: p.cfg.ServerAddress}, nil
		}
	}
	return q, journal.DNSBinding{}, ErrPolicy
}
func exact(rr []dns.RR, value string) bool {
	for _, r := range rr {
		if t, ok := r.(*dns.TXT); ok && len(t.Txt) == 1 && t.Txt[0] == value {
			return true
		}
	}
	return false
}
func equivalent(rr []dns.RR, value string) bool {
	for _, r := range rr {
		if t, ok := r.(*dns.TXT); ok && strings.Join(t.Txt, "") == value {
			return true
		}
	}
	return false
}
func sameSet(a, b []dns.RR) bool {
	key := func(rr []dns.RR) []string {
		out := []string{}
		for _, r := range rr {
			c := dns.Copy(r)
			c.Header().Ttl = 0
			c.Header().Name = dns.CanonicalName(c.Header().Name)
			out = append(out, c.String())
		}
		slices.Sort(out)
		return out
	}
	return slices.Equal(key(a), key(b))
}
func readSnapshot(ctx context.Context, s session, c journal.DNSOwnership) (snapshot, error) {
	a, err := s.read(ctx, c.OwnerName)
	if err != nil {
		return snapshot{}, err
	}
	b, err := s.read(ctx, c.MarkerName)
	if err != nil {
		return snapshot{}, err
	}
	return snapshot{a, b}, nil
}
func (p *Provider) progress(ctx context.Context, c *journal.DNSOwnership, to journal.DNSStage, confirmed bool) error {
	next, err := p.store.ProgressDNS(ctx, c.Request, c.Revision, to, confirmed)
	if err == nil {
		*c = next
	}
	return err
}
func (p *Provider) visible(ctx context.Context, c journal.DNSOwnership) error {
	ok, err := p.wire.visible(ctx, c.OwnerName, c.Request.Value, p.cfg.Mode)
	if err != nil {
		return err
	}
	if !ok {
		return ErrPropagation
	}
	return nil
}

func (p *Provider) Present(ctx context.Context, challenge acmeflow.Challenge) error {
	q, b, err := p.binding(ctx, challenge)
	if err != nil {
		return err
	}
	if q.Value == "" {
		return ErrPolicy
	}
	release, err := p.store.LockDNS(ctx, q)
	if err != nil {
		return err
	}
	defer release()
	c, err := p.store.PrepareDNS(ctx, q, b)
	if err != nil {
		return err
	}
	s, err := p.wire.open(ctx)
	if err != nil {
		return err
	}
	defer s.close()
	for attempt := 0; attempt < p.cfg.MaxConflicts; attempt++ {
		before, err := readSnapshot(ctx, s, c)
		if err != nil {
			return err
		}
		owned := exact(before.Markers, c.Marker)
		present := exact(before.Data, c.Request.Value)
		if c.Stage == journal.DNSAdding || c.Stage == journal.DNSActive {
			if !owned || !present {
				return ErrReconcile
			}
			if c.Stage != journal.DNSActive {
				if err := p.progress(ctx, &c, journal.DNSActive, true); err != nil {
					return err
				}
			}
			return p.visible(ctx, c)
		}
		if owned {
			return ErrReconcile
		}
		if equivalent(before.Data, c.Request.Value) {
			if err := p.progress(ctx, &c, journal.DNSRejected, false); err != nil {
				return err
			}
			return ErrConflict
		}
		if p.cfg.Mode == SingleTXT && len(before.Data) > 0 {
			if err := p.progress(ctx, &c, journal.DNSRejected, false); err != nil {
				return err
			}
			return ErrView
		}
		if err := p.progress(ctx, &c, journal.DNSAdding, false); err != nil {
			return err
		}
		err = s.update(ctx, change{Claim: c, Before: before})
		if errors.Is(err, ErrConflict) {
			if err := p.progress(ctx, &c, journal.DNSInspecting, false); err != nil {
				return err
			}
			continue
		}
		if errors.Is(err, ErrDenied) {
			if err := p.progress(ctx, &c, journal.DNSRejected, false); err != nil {
				return err
			}
			return ErrDenied
		}
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrReconcile
		}
		if err := p.progress(ctx, &c, journal.DNSActive, true); err != nil {
			return err
		}
		after, err := readSnapshot(ctx, s, c)
		if err != nil {
			return err
		}
		if !exact(after.Data, c.Request.Value) || !exact(after.Markers, c.Marker) {
			return ErrReconcile
		}
		return p.visible(ctx, c)
	}
	return ErrConflict
}

func (p *Provider) Cleanup(ctx context.Context, challenge acmeflow.Challenge) error {
	q, b, err := p.binding(ctx, challenge)
	if err != nil {
		return err
	}
	release, err := p.store.LockDNS(ctx, q)
	if err != nil {
		return err
	}
	defer release()
	c, err := p.store.DNSClaim(ctx, q)
	if errors.Is(err, journal.ErrState) {
		return nil
	}
	if err != nil {
		return err
	}
	if c.Binding != b {
		return ErrPolicy
	}
	if c.Stage == journal.DNSCleaned {
		return nil
	}
	if !c.Attempted {
		return p.progress(ctx, &c, journal.DNSCleaned, false)
	}
	if c.Stage != journal.DNSDeleting {
		if err := p.progress(ctx, &c, journal.DNSDeleting, c.Confirmed); err != nil {
			return err
		}
	}
	s, err := p.wire.open(ctx)
	if err != nil {
		return err
	}
	defer s.close()
	for attempt := 0; attempt < p.cfg.MaxConflicts; attempt++ {
		before, err := readSnapshot(ctx, s, c)
		if err != nil {
			return err
		}
		owned := exact(before.Markers, c.Marker)
		if !owned {
			if !c.Confirmed || equivalent(before.Data, c.Request.Value) {
				return ErrReconcile
			}
			return p.progress(ctx, &c, journal.DNSCleaned, true)
		}
		if equivalent(before.Data, c.Request.Value) && !exact(before.Data, c.Request.Value) {
			return ErrReconcile
		}
		if !c.Confirmed {
			if err := p.progress(ctx, &c, journal.DNSDeleting, true); err != nil {
				return err
			}
		}
		err = s.update(ctx, change{Claim: c, Before: before, Remove: true})
		if errors.Is(err, ErrConflict) {
			continue
		}
		if errors.Is(err, ErrDenied) {
			return ErrDenied
		}
		if err != nil {
			return ErrReconcile
		}
		after, err := readSnapshot(ctx, s, c)
		if err != nil {
			return err
		}
		if equivalent(after.Data, c.Request.Value) || exact(after.Markers, c.Marker) {
			return ErrReconcile
		}
		return p.progress(ctx, &c, journal.DNSCleaned, true)
	}
	return ErrConflict
}

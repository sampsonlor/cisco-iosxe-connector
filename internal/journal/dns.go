package journal

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
)

type DNSRequest struct {
	OperationID, AuthorizationURL, Identifier, ChallengeURL, TokenSHA256, ValueSHA256, Value string
}
type DNSBinding struct {
	ConfigSHA256, PolicySHA256, CredentialRef, ViewRef, Zone, ServerName, ServerAddress string
}
type DNSStage string

const (
	DNSInspecting DNSStage = "INSPECTING"
	DNSAdding     DNSStage = "ADDING"
	DNSActive     DNSStage = "ACTIVE"
	DNSDeleting   DNSStage = "DELETING"
	DNSRejected   DNSStage = "REJECTED"
	DNSCleaned    DNSStage = "CLEANED"
)

type DNSOwnership struct {
	Request                       DNSRequest
	Binding                       DNSBinding
	OwnerName, MarkerName, Marker string
	Stage                         DNSStage
	Revision                      int64
	Attempted, Confirmed          bool
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func DNSIdentifier(s string) bool {
	if len(s) == 0 || len(s) > 220 || s != strings.ToLower(s) || !strings.Contains(s, ".") {
		return false
	}
	if ip, err := netip.ParseAddr(s); err == nil && ip.IsValid() {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func DNSNames(identifier string) (string, string) {
	owner := "_acme-challenge." + identifier + "."
	return owner, "_ilm-acme-owner." + owner
}
func validDNSBinding(b DNSBinding) bool {
	addr, err := netip.ParseAddrPort(b.ServerAddress)
	return digest.MatchString(b.ConfigSHA256) && digest.MatchString(b.PolicySHA256) && acmeReference.MatchString(b.CredentialRef) && acmeReference.MatchString(b.ViewRef) && DNSIdentifier(strings.TrimSuffix(b.Zone, ".")) && strings.HasSuffix(b.Zone, ".") && DNSIdentifier(strings.TrimSuffix(b.ServerName, ".")) && strings.HasSuffix(b.ServerName, ".") && err == nil && addr.Port() != 0 && !addr.Addr().IsUnspecified() && !addr.Addr().IsMulticast() && !addr.Addr().Is4In6() && addr.String() == b.ServerAddress
}
func validDNSValue(v string) bool {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(v)
	return err == nil && len(raw) == 32 && len(v) == 43
}
func validDNSRequest(q DNSRequest, requireValue bool) bool {
	return canonicalID(q.OperationID) && DNSIdentifier(q.Identifier) && len(q.AuthorizationURL) <= 2048 && len(q.ChallengeURL) <= 2048 && digest.MatchString(q.TokenSHA256) && digest.MatchString(q.ValueSHA256) && (!requireValue && q.Value == "" || validDNSValue(q.Value) && certpolicy.SHA256([]byte(q.Value)) == q.ValueSHA256)
}
func dnsID(q DNSRequest) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("iosxe:dns:"+q.OperationID+":"+q.AuthorizationURL)).String()
}
func validDNSOwnership(c DNSOwnership) bool {
	owner, marker := DNSNames(c.Request.Identifier)
	if !validDNSRequest(c.Request, true) || !validDNSBinding(c.Binding) || c.OwnerName != owner || c.MarkerName != marker || !strings.HasSuffix(owner, "."+c.Binding.Zone) || len(marker) > 253 || c.Revision < 1 || !strings.HasPrefix(c.Marker, "ilm-acme-v1:") || !validDNSValue(strings.TrimPrefix(c.Marker, "ilm-acme-v1:")) || c.Confirmed && !c.Attempted {
		return false
	}
	switch c.Stage {
	case DNSInspecting, DNSRejected:
		return !c.Attempted && !c.Confirmed
	case DNSAdding:
		return c.Attempted && !c.Confirmed
	case DNSActive:
		return c.Attempted && c.Confirmed
	case DNSDeleting, DNSCleaned:
		return true
	}
	return false
}
func sameDNSRequest(a, b DNSRequest) bool {
	return a.OperationID == b.OperationID && a.AuthorizationURL == b.AuthorizationURL && a.Identifier == b.Identifier && a.ChallengeURL == b.ChallengeURL && a.TokenSHA256 == b.TokenSHA256 && a.ValueSHA256 == b.ValueSHA256 && (a.Value == "" || a.Value == b.Value)
}

func (s *Store) dnsAuthorized(ctx context.Context, q querier, want DNSRequest) (Record, error) {
	if !validDNSRequest(want, false) {
		return Record{}, ErrCorrelation
	}
	r, err := readRecord(q.QueryRowContext(ctx, "SELECT "+recordColumns+" FROM operations WHERE id=?", want.OperationID))
	if err != nil {
		return Record{}, err
	}
	if !s.approved(r.Correlation) || r.Correlation.Owner != ACMEWorker || (r.State != AwaitingIssuance && r.State != CertReady && r.State != Importing && r.State != Staged) {
		return Record{}, ErrCorrelation
	}
	flow, err := readACME(ctx, q, want.OperationID)
	if err != nil {
		return Record{}, err
	}
	for _, c := range flow.Challenges {
		if c.AuthorizationURL == want.AuthorizationURL && c.Identifier == want.Identifier && c.ChallengeURL == want.ChallengeURL && c.TokenSHA256 == want.TokenSHA256 && c.TXTValueSHA256 == want.ValueSHA256 {
			return r, nil
		}
	}
	return Record{}, ErrCorrelation
}
func (s *Store) DNSOperation(ctx context.Context, q DNSRequest) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, ErrStore
	}
	return s.dnsAuthorized(ctx, s.db, q)
}
func (s *Store) LockDNS(ctx context.Context, q DNSRequest) (func(), error) {
	if _, err := s.DNSOperation(ctx, q); err != nil {
		return nil, err
	}
	id := dnsID(q)
	s.dnsMu.Lock()
	defer s.dnsMu.Unlock()
	if s.dnsJobs == nil {
		s.dnsJobs = map[string]bool{}
	}
	if s.dnsJobs[id] {
		return nil, ErrBusy
	}
	s.dnsJobs[id] = true
	var once sync.Once
	return func() { once.Do(func() { s.dnsMu.Lock(); delete(s.dnsJobs, id); s.dnsMu.Unlock() }) }, nil
}
func readDNS(ctx context.Context, q querier, want DNSRequest) (DNSOwnership, error) {
	var raw string
	if err := q.QueryRowContext(ctx, "SELECT record FROM dns_claims WHERE claim_id=?", dnsID(want)).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DNSOwnership{}, ErrState
		}
		return DNSOwnership{}, ErrStore
	}
	var c DNSOwnership
	if len(raw) > 16<<10 || json.Unmarshal([]byte(raw), &c) != nil || !validDNSOwnership(c) || !sameDNSRequest(want, c.Request) {
		return DNSOwnership{}, ErrStore
	}
	encoded, _ := json.Marshal(c)
	if string(encoded) != raw {
		return DNSOwnership{}, ErrStore
	}
	return c, nil
}
func (s *Store) PrepareDNS(ctx context.Context, q DNSRequest, b DNSBinding) (DNSOwnership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return DNSOwnership{}, ErrStore
	}
	if !validDNSRequest(q, true) || !validDNSBinding(b) {
		return DNSOwnership{}, ErrCorrelation
	}
	var result DNSOwnership
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, err := s.dnsAuthorized(ctx, tx, q)
		if err != nil {
			return err
		}
		flow, err := readACME(ctx, tx, q.OperationID)
		if err != nil {
			return err
		}
		if flow.Stage != ACMEBound || flow.CancelRequested {
			return ErrState
		}
		for _, challenge := range flow.Challenges {
			if challenge.AuthorizationURL == q.AuthorizationURL && challenge.Cleaned {
				return ErrState
			}
		}
		if r.Correlation.PolicySHA256 != b.PolicySHA256 {
			return ErrCorrelation
		}
		old, err := readDNS(ctx, tx, q)
		if err == nil {
			if old.Binding != b {
				return ErrCorrelation
			}
			if old.Stage == DNSCleaned || old.Stage == DNSRejected || old.Stage == DNSDeleting {
				return ErrState
			}
			result = old
			return nil
		}
		if !errors.Is(err, ErrState) {
			return err
		}
		owner, marker := DNSNames(q.Identifier)
		if !strings.HasSuffix(owner, "."+b.Zone) {
			return ErrCorrelation
		}
		nonce := make([]byte, 32)
		if _, err := rand.Read(nonce); err != nil {
			return ErrStore
		}
		result = DNSOwnership{Request: q, Binding: b, OwnerName: owner, MarkerName: marker, Marker: "ilm-acme-v1:" + base64.RawURLEncoding.EncodeToString(nonce), Stage: DNSInspecting, Revision: 1}
		if !validDNSOwnership(result) {
			return ErrCorrelation
		}
		raw, _ := json.Marshal(result)
		if _, err = tx.ExecContext(ctx, "INSERT INTO dns_claims(claim_id,operation_id,revision,state,record) VALUES(?,?,?,?,?)", dnsID(q), q.OperationID, 1, DNSInspecting, string(raw)); err != nil {
			return ErrStore
		}
		return nil
	})
	if err != nil {
		return DNSOwnership{}, err
	}
	return result, nil
}
func (s *Store) DNSClaim(ctx context.Context, q DNSRequest) (DNSOwnership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return DNSOwnership{}, ErrStore
	}
	if _, err := s.dnsAuthorized(ctx, s.db, q); err != nil {
		return DNSOwnership{}, err
	}
	return readDNS(ctx, s.db, q)
}

// ProgressDNS accepts only lifecycle state; value, marker and target correlation
// cannot be replaced. confirmed is supplied only after verified ownership proof.
func (s *Store) ProgressDNS(ctx context.Context, q DNSRequest, revision int64, to DNSStage, confirmed bool) (DNSOwnership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return DNSOwnership{}, ErrStore
	}
	var result DNSOwnership
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := s.dnsAuthorized(ctx, tx, q); err != nil {
			return err
		}
		c, err := readDNS(ctx, tx, q)
		if err != nil {
			return err
		}
		if c.Revision != revision {
			return ErrConflict
		}
		allowed := c.Stage == to || c.Stage == DNSInspecting && (to == DNSAdding || to == DNSRejected || to == DNSCleaned) || c.Stage == DNSAdding && (to == DNSInspecting || to == DNSActive || to == DNSDeleting || to == DNSRejected) || c.Stage == DNSActive && to == DNSDeleting || c.Stage == DNSDeleting && to == DNSCleaned || c.Stage == DNSRejected && to == DNSCleaned
		if !allowed || c.Confirmed && !confirmed {
			return ErrState
		}
		c.Stage = to
		c.Revision++
		c.Confirmed = confirmed
		switch to {
		case DNSAdding:
			c.Attempted = true
		case DNSInspecting, DNSRejected:
			c.Attempted = false
		}
		if !validDNSOwnership(c) {
			return ErrState
		}
		raw, _ := json.Marshal(c)
		res, err := tx.ExecContext(ctx, "UPDATE dns_claims SET revision=?,state=?,record=? WHERE claim_id=? AND revision=?", c.Revision, to, string(raw), dnsID(q), revision)
		if err != nil {
			return ErrStore
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return ErrConflict
		}
		result = c
		return nil
	})
	if err != nil {
		return DNSOwnership{}, err
	}
	return result, nil
}
func (s *Store) PendingDNS(ctx context.Context) ([]DNSOwnership, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStore
	}
	rows, err := s.db.QueryContext(ctx, "SELECT record FROM dns_claims WHERE state<>?", DNSCleaned)
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()
	out := []DNSOwnership{}
	for rows.Next() {
		var raw string
		var c DNSOwnership
		if rows.Scan(&raw) != nil || json.Unmarshal([]byte(raw), &c) != nil || !validDNSOwnership(c) {
			return nil, ErrStore
		}
		out = append(out, c)
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return out, nil
}
func (s *Store) checkDNSStorage(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT d.claim_id,d.operation_id,d.revision,d.state,d.record,o.correlation FROM dns_claims d LEFT JOIN operations o ON d.operation_id=o.id")
	if err != nil {
		return ErrStore
	}
	defer rows.Close()
	for rows.Next() {
		var id, op, state, raw, corr string
		var rev int64
		var c DNSOwnership
		var correlation Correlation
		if rows.Scan(&id, &op, &rev, &state, &raw, &corr) != nil || len(raw) > 16<<10 || json.Unmarshal([]byte(raw), &c) != nil || json.Unmarshal([]byte(corr), &correlation) != nil || correlation.Owner != ACMEWorker || correlation.PolicySHA256 != c.Binding.PolicySHA256 || !validDNSOwnership(c) || id != dnsID(c.Request) || op != c.Request.OperationID || rev != c.Revision || state != string(c.Stage) {
			return ErrStore
		}
		encoded, _ := json.Marshal(c)
		if string(encoded) != raw {
			return ErrStore
		}
	}
	if rows.Err() != nil {
		return ErrStore
	}
	return nil
}

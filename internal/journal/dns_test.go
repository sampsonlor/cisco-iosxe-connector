package journal

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
)

func dnsOperation(t *testing.T) (*Store, string, []Service, DNSRequest, DNSBinding) {
	t.Helper()
	s, path, services, r, _ := acmeOperation(t)
	ctx := context.Background()
	_, _, _, flow, err := s.BeginACME(ctx, r.Ref(), acmeBinding())
	if err != nil {
		t.Fatal(err)
	}
	flow.Stage = ACMECreating
	flow, err = s.SaveACME(ctx, r.Ref(), flow.Revision, flow)
	if err != nil {
		t.Fatal(err)
	}
	flow.Stage = ACMEBound
	flow.OrderURL = "https://acme.example.test/profiles/test/order/one"
	flow.FinalizeURL = flow.OrderURL + "/finalize"
	flow.AuthorizationURLs = []string{"https://acme.example.test/profiles/test/authz/one"}
	value := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	q := DNSRequest{OperationID: r.ID, AuthorizationURL: flow.AuthorizationURLs[0], Identifier: csrSpec().CommonName, ChallengeURL: "https://acme.example.test/profiles/test/chall/one", TokenSHA256: strings.Repeat("e", 64), ValueSHA256: certpolicy.SHA256([]byte(value)), Value: value}
	flow.Challenges = []ACMEChallenge{{AuthorizationURL: q.AuthorizationURL, Identifier: q.Identifier, ChallengeURL: q.ChallengeURL, TokenSHA256: q.TokenSHA256, TXTValueSHA256: q.ValueSHA256}}
	if _, err = s.SaveACME(ctx, r.Ref(), flow.Revision, flow); err != nil {
		t.Fatal(err)
	}
	b := DNSBinding{ConfigSHA256: strings.Repeat("a", 64), PolicySHA256: r.Correlation.PolicySHA256, CredentialRef: "secret://dns/service", ViewRef: "view://approved/internal", Zone: "example.test.", ServerName: "dns.example.test.", ServerAddress: "192.0.2.53:53"}
	return s, path, services, q, b
}
func TestDNSClaimsBindIntentAndRecoverOnlyRecordedValue(t *testing.T) {
	s, path, services, q, b := dnsOperation(t)
	defer s.Close()
	ctx := context.Background()
	claim, err := s.PrepareDNS(ctx, q, b)
	if err != nil {
		t.Fatal(err)
	}
	if claim.Stage != DNSInspecting || claim.Request.Value != q.Value || claim.OwnerName != "_acme-challenge.router.example.test." || claim.MarkerName != "_ilm-acme-owner._acme-challenge.router.example.test." || claim.Marker == "" {
		t.Fatal("invalid ownership intent")
	}
	again, err := s.PrepareDNS(ctx, q, b)
	if err != nil || again.Marker != claim.Marker || again.Revision != claim.Revision {
		t.Fatal("retry replaced ownership marker", err)
	}
	claim, err = s.ProgressDNS(ctx, q, claim.Revision, DNSAdding, false)
	if err != nil {
		t.Fatal(err)
	}
	if !claim.Attempted || claim.Confirmed {
		t.Fatal("add intent not committed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	stored, err := s.DNSClaim(ctx, q)
	if err != nil || stored.Marker != claim.Marker || stored.Request.Value != claim.Request.Value || stored.Stage != DNSAdding {
		t.Fatal("restart lost exact value/intent", err)
	}
	if _, err := s.ProgressDNS(ctx, q, claim.Revision-1, DNSActive, true); !errors.Is(err, ErrConflict) {
		t.Fatal("stale ownership revision accepted", err)
	}
	claim, err = s.ProgressDNS(ctx, q, claim.Revision, DNSActive, true)
	if err != nil {
		t.Fatal(err)
	}
	claim, err = s.ProgressDNS(ctx, q, claim.Revision, DNSDeleting, true)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := q
	cleanup.Value = ""
	claim, err = s.ProgressDNS(ctx, cleanup, claim.Revision, DNSCleaned, true)
	if err != nil || claim.Stage != DNSCleaned {
		t.Fatal("reference-only cleanup failed", err)
	}
	if _, err := s.PrepareDNS(ctx, q, b); err == nil {
		t.Fatal("cleaned challenge presented again")
	}
}
func TestDNSClaimsRejectForgeryAndFailedIntent(t *testing.T) {
	s, _, _, q, b := dnsOperation(t)
	defer s.Close()
	ctx := context.Background()
	for _, mutate := range []func(*DNSRequest){func(q *DNSRequest) { q.Identifier = "other.example.test" }, func(q *DNSRequest) { q.AuthorizationURL += "-other" }, func(q *DNSRequest) { q.ValueSHA256 = strings.Repeat("f", 64) }, func(q *DNSRequest) { q.Value = "unvalidated-value" }} {
		bad := q
		mutate(&bad)
		if _, err := s.PrepareDNS(ctx, bad, b); err == nil {
			t.Fatal("forged challenge claimed")
		}
	}
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareDNS(ctx, q, b); !errors.Is(err, ErrStore) {
		t.Fatal("claim without durable intent accepted", err)
	}
	if _, err := s.db.Exec("PRAGMA query_only=OFF"); err != nil {
		t.Fatal(err)
	}
	claim, err := s.PrepareDNS(ctx, q, b)
	if err != nil {
		t.Fatal(err)
	}
	changed := b
	changed.ServerAddress = "192.0.2.54:53"
	if _, err := s.PrepareDNS(ctx, q, changed); !errors.Is(err, ErrCorrelation) {
		t.Fatal("unfinished claim rebound", err)
	}
	if _, err := s.ProgressDNS(ctx, q, claim.Revision, DNSActive, true); err == nil {
		t.Fatal("add intent bypassed")
	}
	claim, err = s.ProgressDNS(ctx, q, claim.Revision, DNSRejected, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ProgressDNS(ctx, q, claim.Revision, DNSCleaned, false); err != nil {
		t.Fatal(err)
	}
}
func TestDNSV3MigrationAndMissingClaimsFailClosed(t *testing.T) {
	s, path, services, q, b := dnsOperation(t)
	if _, err := s.db.Exec("DROP TABLE dns_claims"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA user_version=3"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, services)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.PrepareDNS(context.Background(), q, b); err != nil {
		t.Fatal("v3 migration damaged source correlation", err)
	}
	if _, err := s.db.Exec("DROP TABLE dns_claims"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(path, services); err == nil {
		other.Close()
		t.Fatal("v4 missing ownership data accepted")
	}
}

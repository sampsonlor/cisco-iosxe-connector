package journal

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
)

type ACMEBinding struct {
	DirectoryURL, AccountKeyRef, AccountKeySHA256, TLSBundleRef, SettingsSHA256 string
}
type ACMEStage string

const (
	ACMEPreparing  ACMEStage = "PREPARING"
	ACMECreating   ACMEStage = "ORDER_CREATING"
	ACMEBound      ACMEStage = "ORDER_BOUND"
	ACMEFinalizing ACMEStage = "FINALIZE_SENT"
	ACMEIssued     ACMEStage = "ISSUED"
	ACMEInvalid    ACMEStage = "INVALID"
)

type ACMEChallenge struct {
	AuthorizationURL, Identifier, ChallengeURL, TokenSHA256, TXTValueSHA256 string
	Presented, Notified, Cleaned                                            bool
}
type ACMERecord struct {
	Binding                               ACMEBinding
	Revision                              int64
	CSRSHA256                             string
	Stage                                 ACMEStage
	OrderURL, FinalizeURL, CertificateURL string
	AuthorizationURLs                     []string
	Challenges                            []ACMEChallenge
	Attempts                              int
	NextAttemptAt                         time.Time
}

var acmeReference = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:/.@_-]{0,255}$`)
var acmePath = regexp.MustCompile(`^/[A-Za-z0-9/_.~-]+$`)

func acmeURL(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	return u, err == nil && len(raw) <= 2048 && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawPath == "" && u.Host == strings.ToLower(u.Host) && u.Path == path.Clean(u.Path) && acmePath.MatchString(u.Path) && !strings.Contains(raw, "\\")
}

// ValidACMEResource restricts every ACME resource to one configured HTTPS
// origin and profile path. Encoded paths, redirects and query credentials are
// not a mechanism for crossing profile/account boundaries.
func ValidACMEResource(directory, resource string) bool {
	d, ok := acmeURL(directory)
	if !ok || !strings.HasSuffix(d.Path, "/directory") {
		return false
	}
	u, ok := acmeURL(resource)
	return ok && u.Host == d.Host && strings.HasPrefix(u.Path, strings.TrimSuffix(d.Path, "/directory")+"/")
}
func validACMEBinding(b ACMEBinding) bool {
	return ValidACMEResource(b.DirectoryURL, b.DirectoryURL) && acmeReference.MatchString(b.AccountKeyRef) && acmeReference.MatchString(b.TLSBundleRef) && digest.MatchString(b.AccountKeySHA256) && digest.MatchString(b.SettingsSHA256)
}
func acmeBindingID(b ACMEBinding) string { raw, _ := json.Marshal(b); return certpolicy.SHA256(raw) }
func validACMERecord(r ACMERecord) bool {
	if !validACMEBinding(r.Binding) || r.Revision < 1 || !digest.MatchString(r.CSRSHA256) || r.Attempts < 0 || r.Attempts > 1000000 || len(r.AuthorizationURLs) > 16 || len(r.Challenges) > 16 {
		return false
	}
	switch r.Stage {
	case ACMEPreparing, ACMECreating:
		return r.OrderURL == "" && r.FinalizeURL == "" && r.CertificateURL == "" && len(r.AuthorizationURLs) == 0 && len(r.Challenges) == 0
	case ACMEBound, ACMEFinalizing, ACMEIssued, ACMEInvalid:
	default:
		return false
	}
	valid := func(s string) bool { return ValidACMEResource(r.Binding.DirectoryURL, s) }
	if !valid(r.OrderURL) || !valid(r.FinalizeURL) || len(r.AuthorizationURLs) == 0 || r.OrderURL == r.FinalizeURL || r.Stage == ACMEIssued && r.CertificateURL == "" {
		return false
	}
	if r.CertificateURL != "" && (!valid(r.CertificateURL) || r.Stage != ACMEFinalizing && r.Stage != ACMEIssued) {
		return false
	}
	seen := map[string]bool{}
	for _, s := range r.AuthorizationURLs {
		if !valid(s) || seen[s] {
			return false
		}
		seen[s] = true
	}
	challenges := map[string]bool{}
	for _, c := range r.Challenges {
		if !seen[c.AuthorizationURL] || challenges[c.AuthorizationURL] || !valid(c.ChallengeURL) || c.Identifier == "" || len(c.Identifier) > 253 || !digest.MatchString(c.TokenSHA256) || !digest.MatchString(c.TXTValueSHA256) || c.Notified && !c.Presented {
			return false
		}
		challenges[c.AuthorizationURL] = true
	}
	return true
}
func acmeChangeAllowed(old, next ACMERecord) bool {
	if !validACMERecord(next) || old.Binding != next.Binding || old.CSRSHA256 != next.CSRSHA256 || next.Attempts < old.Attempts || old.OrderURL != "" && (old.OrderURL != next.OrderURL || old.FinalizeURL != next.FinalizeURL || !slices.Equal(old.AuthorizationURLs, next.AuthorizationURLs)) || old.CertificateURL != "" && old.CertificateURL != next.CertificateURL {
		return false
	}
	allowed := old.Stage == next.Stage || old.Stage == ACMEPreparing && next.Stage == ACMECreating || old.Stage == ACMECreating && (next.Stage == ACMEBound || next.Stage == ACMEPreparing) || old.Stage == ACMEBound && (next.Stage == ACMEFinalizing || next.Stage == ACMEInvalid) || old.Stage == ACMEFinalizing && (next.Stage == ACMEIssued || next.Stage == ACMEInvalid || next.Stage == ACMEBound)
	if !allowed {
		return false
	}
	for _, c := range old.Challenges {
		i := slices.IndexFunc(next.Challenges, func(n ACMEChallenge) bool { return n.AuthorizationURL == c.AuthorizationURL })
		if i < 0 {
			return false
		}
		n := next.Challenges[i]
		if n.Identifier != c.Identifier || n.ChallengeURL != c.ChallengeURL || n.TokenSHA256 != c.TokenSHA256 || n.TXTValueSHA256 != c.TXTValueSHA256 || c.Presented && !n.Presented || c.Notified && !n.Notified || c.Cleaned && !n.Cleaned {
			return false
		}
	}
	return true
}

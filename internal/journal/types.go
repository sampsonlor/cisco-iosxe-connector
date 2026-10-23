// Package journal stores operation intent and HTTPS service ownership on one
// local SQLite WAL volume. It is not an authorization or device adapter.
package journal

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrStore       = errors.New("operation journal unavailable")
	ErrInstance    = errors.New("operation journal already has an active instance")
	ErrCorrelation = errors.New("operation correlation rejected")
	ErrBusy        = errors.New("HTTPS service has an unfinished operation")
	ErrConflict    = errors.New("operation revision or configuration conflict")
	ErrState       = errors.New("operation transition rejected")
	ErrReconcile   = errors.New("import outcome requires independent reconciliation")
)

type Owner string

const (
	ILMCore    Owner = "ilm-core"
	ACMEWorker Owner = "acme-worker"
)

type State string

const (
	Precheck         State = "PRECHECK"
	KeyCreating      State = "KEY_CREATING"
	CSRReady         State = "CSR_READY"
	AwaitingIssuance State = "AWAITING_ISSUANCE"
	CertReady        State = "CERT_READY"
	Importing        State = "IMPORTING"
	Staged           State = "STAGED"
	FailedNoSwitch   State = "FAILED_NO_SWITCH"
)

// Binding is supplied by trusted host configuration, never directly by Core
// attributes. PolicySHA256 identifies the reviewed effective issuance policy.
type Binding struct {
	EntityID, LocationID, DeviceID, Target, HostKeySHA256, PolicySHA256 string
	Owner                                                               Owner
}
type Service struct {
	Binding
	StagingTrustpoints []string
}
type Correlation struct {
	Binding
	ActiveTrustpoint, BaselineSHA256, StagingTrustpoint string
}
type Ref struct {
	ID          string
	Correlation Correlation
}
type Record struct {
	ID, RequestID        string
	Correlation          Correlation
	State                State
	Revision             int64
	CertificateSHA256    string
	CreatedAt, UpdatedAt time.Time
}

func (r Record) Ref() Ref { return Ref{ID: r.ID, Correlation: r.Correlation} }

type Event struct {
	Revision          int64
	From, To          State
	At                time.Time
	CertificateSHA256 string
}

var token = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

func canonicalID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}
func validService(s Service) bool {
	ip, err := netip.ParseAddr(s.Target)
	key, keyErr := base64.RawStdEncoding.Strict().DecodeString(strings.TrimPrefix(s.HostKeySHA256, "SHA256:"))
	if !canonicalID(s.EntityID) || s.LocationID != uuid.NewSHA1(uuid.NameSpaceURL, []byte("iosxe:"+s.EntityID+":https")).String() || !token.MatchString(s.DeviceID) || err != nil || ip.String() != s.Target || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" || !strings.HasPrefix(s.HostKeySHA256, "SHA256:") || keyErr != nil || len(key) != 32 || !digest.MatchString(s.PolicySHA256) || (s.Owner != ILMCore && s.Owner != ACMEWorker) || len(s.StagingTrustpoints) == 0 || len(s.StagingTrustpoints) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, name := range s.StagingTrustpoints {
		lower := strings.ToLower(name)
		if !token.MatchString(name) || seen[lower] {
			return false
		}
		seen[lower] = true
	}
	return true
}
func (s *Store) approved(c Correlation) bool {
	p, ok := s.services[c.LocationID]
	return ok && p.Binding == c.Binding && digest.MatchString(c.BaselineSHA256) && token.MatchString(c.ActiveTrustpoint) && slices.Contains(p.StagingTrustpoints, c.StagingTrustpoint) && !strings.EqualFold(c.ActiveTrustpoint, c.StagingTrustpoint)
}
func validState(s State) bool {
	switch s {
	case Precheck, KeyCreating, CSRReady, AwaitingIssuance, CertReady, Importing, Staged, FailedNoSwitch:
		return true
	}
	return false
}

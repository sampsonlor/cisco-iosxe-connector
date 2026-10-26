package inventory

import (
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
)

// VerifyCSRBaseline is the semantic verifier for a CSR adapter's complete
// before/after public inventory. An unenrolled slot has no identity leaf.
func VerifyCSRBaseline(e device.Evidence, q csr.Request) error {
	s, err := Parse(e, nil)
	if err != nil || s.ActiveTrustpoint != q.ActiveTrustpoint {
		return ErrIncomplete
	}
	matched := false
	for _, cert := range s.Certificates {
		if cert.Trustpoint == q.Trustpoint {
			return ErrIncomplete
		}
		if cert.Role == "ACTIVE" && cert.SHA256 == q.BaselineSHA256 {
			matched = true
		}
	}
	if !matched {
		return ErrIncomplete
	}
	return nil
}

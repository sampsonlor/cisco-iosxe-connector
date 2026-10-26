package inventory

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
)

// VerifyStageInventory uses the complete ordinary inventory parser, without
// synthesizing a STAGED assignment from the requested certificate digest.
func VerifyStageInventory(e device.Evidence, q staging.Request, ancestors map[string]string) (staging.Observation, error) {
	if staging.Validate(q) != nil {
		return staging.Observation{}, ErrIncomplete
	}
	s, err := Parse(e, nil)
	if err != nil || s.ActiveTrustpoint != q.CSR.ActiveTrustpoint {
		return staging.Observation{}, ErrIncomplete
	}
	o := staging.Observation{ActiveTrustpoint: s.ActiveTrustpoint}
	other := []string{}
	for _, c := range s.Certificates {
		if c.Role == "ACTIVE" {
			if c.SHA256 != q.CSR.BaselineSHA256 {
				return staging.Observation{}, ErrIncomplete
			}
			o.ActiveDER = bytes.Clone(c.DER)
		}
		if strings.EqualFold(c.Trustpoint, q.CSR.Trustpoint) {
			if c.Trustpoint != q.CSR.Trustpoint {
				return staging.Observation{}, ErrIncomplete
			}
			switch c.Kind {
			case "LEAF":
				if len(o.LeafDER) != 0 || c.Role != "INACTIVE" {
					return staging.Observation{}, ErrIncomplete
				}
				o.LeafDER = bytes.Clone(c.DER)
			case "CA":
				if len(o.IssuerDER) != 0 {
					return staging.Observation{}, ErrIncomplete
				}
				o.IssuerDER = bytes.Clone(c.DER)
			default:
				return staging.Observation{}, ErrIncomplete
			}
		} else {
			other = append(other, c.Trustpoint+":"+c.Kind+":"+c.SHA256)
		}
	}
	for _, name := range s.UnenrolledTrustpoints {
		if !strings.EqualFold(name, q.CSR.Trustpoint) {
			other = append(other, name+":UNENROLLED")
		}
	}
	for _, der := range q.ChainDER[2:] {
		name, ok := ancestors[certpolicy.SHA256(der)]
		found := false
		if !ok || strings.EqualFold(name, q.CSR.Trustpoint) {
			return staging.Observation{}, ErrIncomplete
		}
		for _, c := range s.Certificates {
			found = found || c.Trustpoint == name && c.Kind == "CA" && bytes.Equal(c.DER, der)
		}
		if !found {
			return staging.Observation{}, ErrIncomplete
		}
	}
	if len(o.ActiveDER) == 0 {
		return staging.Observation{}, ErrIncomplete
	}
	slices.Sort(other)
	raw, _ := json.Marshal(other)
	o.OtherStateSHA256 = certpolicy.SHA256(raw)
	return o, nil
}

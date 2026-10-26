// Package staging defines public-certificate requests and independent readback
// evidence. It contains no credentials, router commands or activation capability.
package staging

import (
	"bytes"
	"crypto/x509"
	"errors"
	"regexp"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

var ErrEvidence = errors.New("staging evidence does not match the approved operation")

type Request struct {
	CSR      csr.Request
	Material csr.Result
	LeafDER  []byte
	ChainDER [][]byte // verified path, leaf first; no keys
}
type Observation struct {
	ActiveTrustpoint                            string
	ActiveDER, LeafDER, IssuerDER, PublicKeyDER []byte
	NonExportable                               bool
	OtherStateSHA256                            string
}

var hash = regexp.MustCompile(`^[a-f0-9]{64}$`)

func Validate(q Request) error {
	if q.CSR.KeyLabel() == "" || csr.Validate(q.Material, q.CSR.Spec) != nil || len(q.ChainDER) < 2 || len(q.ChainDER) > 8 || len(q.LeafDER) > 64<<10 || !bytes.Equal(q.LeafDER, q.ChainDER[0]) {
		return ErrEvidence
	}
	var child *x509.Certificate
	seen := map[string]bool{}
	for i, der := range q.ChainDER {
		if len(der) == 0 || len(der) > 64<<10 {
			return ErrEvidence
		}
		cert, err := x509.ParseCertificate(der)
		id := certpolicy.SHA256(der)
		if err != nil || seen[id] {
			return ErrEvidence
		}
		seen[id] = true
		if i == 0 {
			if cert.IsCA || !bytes.Equal(cert.RawSubjectPublicKeyInfo, q.Material.PublicKeyDER) {
				return ErrEvidence
			}
		} else if !cert.IsCA || child.CheckSignatureFrom(cert) != nil {
			return ErrEvidence
		}
		child = cert
	}
	return nil
}
func (o Observation) Check(q Request, other string) error {
	if Validate(q) != nil || o.ActiveTrustpoint != q.CSR.ActiveTrustpoint || certpolicy.SHA256(o.ActiveDER) != q.CSR.BaselineSHA256 || len(o.ActiveDER) == 0 || !bytes.Equal(o.PublicKeyDER, q.Material.PublicKeyDER) || !o.NonExportable || !hash.MatchString(o.OtherStateSHA256) || other != "" && other != o.OtherStateSHA256 {
		return ErrEvidence
	}
	if _, err := x509.ParseCertificate(o.ActiveDER); err != nil {
		return ErrEvidence
	}
	if len(o.IssuerDER) != 0 && !bytes.Equal(o.IssuerDER, q.ChainDER[1]) || len(o.LeafDER) != 0 && (!bytes.Equal(o.LeafDER, q.LeafDER) || len(o.IssuerDER) == 0) {
		return ErrEvidence
	}
	return nil
}
func (o Observation) Complete(q Request) bool {
	return len(q.ChainDER) >= 2 && len(q.LeafDER) > 0 && bytes.Equal(o.LeafDER, q.LeafDER) && bytes.Equal(o.IssuerDER, q.ChainDER[1])
}

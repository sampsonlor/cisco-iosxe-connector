// Package csr validates public CSR artifacts. It never generates a private key.
package csr

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
)

var ErrPolicy = errors.New("CSR policy rejected")
var ErrInvalid = errors.New("CSR or device key proof rejected")

type Spec struct {
	CommonName, Organization, OrganizationalUnit string
	DNSNames                                     []string
	RSABits                                      int
}
type Request struct {
	OperationID, DeviceID, Target, HostKeySHA256, PolicySHA256, ActiveTrustpoint, BaselineSHA256, Trustpoint string
	Spec                                                                                                     Spec
}
type Result struct {
	DER, PublicKeyDER []byte
	NonExportable     bool
}

func KeyLabel(id string) string {
	u, err := uuid.Parse(id)
	if err != nil || u == uuid.Nil || u.String() != id {
		return ""
	}
	return "ILM-K-" + strings.ReplaceAll(id, "-", "")
}
func (r Request) KeyLabel() string { return KeyLabel(r.OperationID) }

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var dnValue = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`)

func dnsName(s string) bool {
	if len(s) == 0 || len(s) > 253 || s != strings.ToLower(s) {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}
func Normalize(s Spec) (Spec, error) {
	s.CommonName = strings.ToLower(s.CommonName)
	s.DNSNames = slices.Clone(s.DNSNames)
	if !dnsName(s.CommonName) || len(s.CommonName) > 64 || len(s.DNSNames) < 1 || len(s.DNSNames) > 16 || (s.RSABits != 2048 && s.RSABits != 3072 && s.RSABits != 4096) {
		return Spec{}, ErrPolicy
	}
	for _, value := range []string{s.Organization, s.OrganizationalUnit} {
		if value != "" && (!dnValue.MatchString(value) || strings.TrimSpace(value) != value) {
			return Spec{}, ErrPolicy
		}
	}
	seen := map[string]bool{}
	for i, name := range s.DNSNames {
		name = strings.ToLower(name)
		if !dnsName(name) || seen[name] {
			return Spec{}, ErrPolicy
		}
		seen[name] = true
		s.DNSNames[i] = name
	}
	if !seen[s.CommonName] {
		return Spec{}, ErrPolicy
	}
	slices.Sort(s.DNSNames)
	if len("subject-alt-name "+strings.Join(s.DNSNames, ",")) > 512 {
		return Spec{}, ErrPolicy
	}
	return s, nil
}
func Validate(r Result, s Spec) error {
	s, err := Normalize(s)
	if err != nil {
		return err
	}
	if !r.NonExportable || len(r.DER) == 0 || len(r.DER) > 16<<10 || len(r.PublicKeyDER) > 2048 {
		return ErrInvalid
	}
	q, err := x509.ParseCertificateRequest(r.DER)
	if err != nil || q.CheckSignature() != nil || q.SignatureAlgorithm != x509.SHA256WithRSA || !bytes.Equal(q.RawSubjectPublicKeyInfo, r.PublicKeyDER) {
		return ErrInvalid
	}
	key, ok := q.PublicKey.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != s.RSABits || key.E != 65537 {
		return ErrInvalid
	}
	want := map[string]string{"2.5.4.3": s.CommonName}
	if s.Organization != "" {
		want["2.5.4.10"] = s.Organization
	}
	if s.OrganizationalUnit != "" {
		want["2.5.4.11"] = s.OrganizationalUnit
	}
	if len(q.Subject.Names) != len(want) {
		return ErrInvalid
	}
	for _, at := range q.Subject.Names {
		value, ok := at.Value.(string)
		expected, present := want[at.Type.String()]
		if !ok || !present || expected != value {
			return ErrInvalid
		}
		delete(want, at.Type.String())
	}
	if len(want) != 0 {
		return ErrInvalid
	}
	for _, at := range q.Attributes {
		if at.Type.String() != "1.2.840.113549.1.9.14" {
			return ErrInvalid
		}
	}
	if len(q.Attributes) > 1 {
		return ErrInvalid
	}
	seen := map[string]bool{}
	san := false
	for _, ext := range q.Extensions {
		id := ext.Id.String()
		if seen[id] {
			return ErrInvalid
		}
		seen[id] = true
		switch id {
		case "2.5.29.17":
			var sequence asn1.RawValue
			rest, err := asn1.Unmarshal(ext.Value, &sequence)
			if err != nil || len(rest) != 0 || sequence.Class != 0 || sequence.Tag != 16 || !sequence.IsCompound {
				return ErrInvalid
			}
			names := []string{}
			for body := sequence.Bytes; len(body) > 0; {
				var item asn1.RawValue
				body, err = asn1.Unmarshal(body, &item)
				if err != nil || item.Class != 2 || item.Tag != 2 || item.IsCompound {
					return ErrInvalid
				}
				names = append(names, strings.ToLower(string(item.Bytes)))
			}
			slices.Sort(names)
			if !slices.Equal(names, s.DNSNames) {
				return ErrInvalid
			}
			san = true
		case "2.5.29.15":
			var bits asn1.BitString
			rest, err := asn1.Unmarshal(ext.Value, &bits)
			if err != nil || len(rest) != 0 || bits.BitLength > 9 {
				return ErrInvalid
			}
			for i := 0; i < bits.BitLength; i++ {
				if i != 0 && i != 2 && bits.At(i) != 0 {
					return ErrInvalid
				}
			}
		case "2.5.29.37":
			var usages []asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(ext.Value, &usages)
			if err != nil || len(rest) != 0 || len(usages) != 1 || usages[0].String() != "1.3.6.1.5.5.7.3.1" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	if !san || len(q.IPAddresses) > 0 || len(q.EmailAddresses) > 0 || len(q.URIs) > 0 {
		return ErrInvalid
	}
	return nil
}

package certpolicy

import (
	"crypto/x509"
	"encoding/asn1"
	"strconv"
	"strings"
)

const (
	v1TemplateOID          = "1.3.6.1.4.1.311.20.2"
	v2TemplateOID          = "1.3.6.1.4.1.311.21.7"
	applicationPoliciesOID = "1.3.6.1.4.1.311.21.10"
	serverAuthOID          = "1.3.6.1.5.5.7.3.1"
)

func parseOID(s string) (asn1.ObjectIdentifier, error) {
	if len(s) == 0 || len(s) > 256 {
		return nil, ErrTemplate
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 32 {
		return nil, ErrTemplate
	}
	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 31)
		if err != nil || strconv.FormatUint(n, 10) != part {
			return nil, ErrTemplate
		}
		oid[i] = int(n)
	}
	if oid[0] > 2 || oid[0] < 2 && oid[1] > 39 {
		return nil, ErrTemplate
	}
	if _, err := asn1.Marshal(oid); err != nil {
		return nil, ErrTemplate
	}
	return oid, nil
}

func rawValue(der []byte, tag int, compound bool) (asn1.RawValue, error) {
	var r asn1.RawValue
	rest, err := asn1.Unmarshal(der, &r)
	if err != nil || len(rest) != 0 || r.Class != 0 || r.Tag != tag || r.IsCompound != compound {
		return asn1.RawValue{}, ErrTemplate
	}
	return r, nil
}

func v1Name(der []byte) (string, error) {
	if r, err := rawValue(der, 16, true); err == nil {
		// MS-WCCE also describes the name as SEQUENCE { UTF8String }.
		// Accept exactly one ASCII technical name, with no trailing fields.
		name, err := rawValue(r.Bytes, 12, false)
		if err != nil || !templateName.Match(name.Bytes) {
			return "", ErrTemplate
		}
		return string(name.Bytes), nil
	}
	r, err := rawValue(der, 30, false)
	if err != nil || len(r.Bytes) == 0 || len(r.Bytes) > 256 || len(r.Bytes)%2 != 0 {
		return "", ErrTemplate
	}
	// This connector accepts ASCII technical template names. Reject invalid
	// UTF-16, NULs and lossy replacement instead of comparing display strings.
	name := make([]byte, len(r.Bytes)/2)
	for i := range name {
		if r.Bytes[2*i] != 0 {
			return "", ErrTemplate
		}
		name[i] = r.Bytes[2*i+1]
	}
	if !templateName.Match(name) {
		return "", ErrTemplate
	}
	return string(name), nil
}

func v2Identity(der []byte) (Template, error) {
	r, err := rawValue(der, 16, true)
	if err != nil || len(der) > 1024 {
		return Template{}, ErrTemplate
	}
	var oid asn1.ObjectIdentifier
	body, err := asn1.Unmarshal(r.Bytes, &oid)
	if err != nil {
		return Template{}, ErrTemplate
	}
	t := Template{Kind: V2, OID: oid.String()}
	if _, err := parseOID(t.OID); err != nil {
		return Template{}, ErrTemplate
	}
	for _, dest := range []**uint32{&t.Major, &t.Minor} {
		if len(body) == 0 {
			break
		}
		var n int64
		body, err = asn1.Unmarshal(body, &n)
		if err != nil || n < 0 || n > 1<<32-1 {
			return Template{}, ErrTemplate
		}
		value := uint32(n)
		*dest = &value
	}
	if len(body) != 0 {
		return Template{}, ErrTemplate
	}
	return t, nil
}

func checkTemplate(c *x509.Certificate, expected Template) error {
	var name string
	var identity Template
	seenName, seenOID := false, false
	for _, ext := range c.Extensions {
		switch ext.Id.String() {
		case v1TemplateOID:
			if seenName || ext.Critical {
				return ErrTemplate
			}
			seenName = true
			var err error
			name, err = v1Name(ext.Value)
			if err != nil {
				return err
			}
		case v2TemplateOID:
			if seenOID || ext.Critical {
				return ErrTemplate
			}
			seenOID = true
			var err error
			identity, err = v2Identity(ext.Value)
			if err != nil {
				return err
			}
		}
	}
	if expected.Kind == V1 {
		if !seenName || seenOID || name != expected.Name {
			return ErrTemplate
		}
	} else if !seenOID || identity.OID != expected.OID || !sameVersion(identity.Major, expected.Major) || !sameVersion(identity.Minor, expected.Minor) || seenName && name != expected.Name {
		return ErrTemplate
	}
	return nil
}

// Microsoft Application Policies uses CertificatePolicies syntax, and can
// constrain purpose in addition to EKU. This HTTPS-only policy allows precisely
// serverAuth without qualifiers; it never treats anyPolicy as serverAuth.
func checkApplicationPolicies(c *x509.Certificate) error {
	for _, ext := range c.Extensions {
		if ext.Id.String() != applicationPoliciesOID {
			continue
		}
		outer, err := rawValue(ext.Value, 16, true)
		if err != nil {
			return ErrLeaf
		}
		policy, err := rawValue(outer.Bytes, 16, true)
		if err != nil {
			return ErrLeaf
		}
		var oid asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(policy.Bytes, &oid)
		if err != nil || len(rest) != 0 || oid.String() != serverAuthOID {
			return ErrLeaf
		}
	}
	return nil
}

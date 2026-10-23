package provider

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"sort"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
)

func inventoryMetadata(c PublicCertificate, parsed *x509.Certificate) ([]mdl.MetadataAttribute, error) {
	if len(c.Bindings) == 0 {
		return nil, nil
	} // Existing reader contract remains usable.
	if len(c.Bindings) > 64 || c.WithKey {
		return nil, errors.New("unsupported binding or key proof")
	}
	var roles, purposes []string
	aliasPresent := false
	seen := map[string]bool{}
	for _, b := range c.Bindings {
		if !cliToken.MatchString(b.Trustpoint) || seen[b.Trustpoint] {
			return nil, errors.New("invalid Trustpoint binding")
		}
		seen[b.Trustpoint] = true
		if b.SelfSignedIdentity {
			if !parsed.IsCA || !bytes.Equal(parsed.RawIssuer, parsed.RawSubject) || parsed.CheckSignature(parsed.SignatureAlgorithm, parsed.RawTBSCertificate, parsed.Signature) != nil {
				return nil, errors.New("invalid self-signed identity proof")
			}
			aliasPresent = true
			purposes = append(purposes, b.Trustpoint+"=CA_AND_IDENTITY")
		} else if parsed.IsCA {
			purposes = append(purposes, b.Trustpoint+"=CA")
		} else {
			purposes = append(purposes, b.Trustpoint+"=IDENTITY")
		}
		if parsed.IsCA && !b.SelfSignedIdentity {
			if b.Role != "CA" {
				return nil, errors.New("invalid CA role")
			}
		} else {
			switch b.Role {
			case "ACTIVE", "INACTIVE", "STAGED", "ROLLBACK":
			default:
				return nil, errors.New("invalid leaf role")
			}
		}
		roles = append(roles, b.Trustpoint+"="+b.Role)
	}
	sort.Strings(roles)
	h := sha256.Sum256(c.DER)
	kind := "LEAF"
	if parsed.IsCA {
		kind = "CA"
	}
	metadata := []mdl.MetadataAttribute{inventoryAttribute("0201", "trustpointRoles", roles), inventoryAttribute("0202", "certificateKind", []string{kind}), inventoryAttribute("0203", "sha256Fingerprint", []string{hex.EncodeToString(h[:])}), inventoryAttribute("0204", "keyAssociation", []string{"UNKNOWN"})}
	if aliasPresent {
		sort.Strings(purposes)
		metadata = append(metadata, inventoryAttribute("0205", "trustpointPurposes", purposes))
	}
	return metadata, nil
}
func inventoryAttribute(suffix, name string, values []string) mdl.MetadataAttribute {
	// Use only properties present in the pinned 2.19.0 contract. Location-local
	// metadata replaces prior observations; it is never an editable request.
	no, yes := false, true
	p := mdl.MetadataAttributeProperties{Label: name, Visible: true, Global: &no, Overwrite: &yes}
	a := mdl.NewMetadataAttributeV3("4c198a4c-0f9a-4b65-a378-1a8996a2"+suffix, name, 3, mdl.ATTRIBUTETYPE_META, mdl.ATTRIBUTECONTENTTYPE_STRING, p, mdl.ATTRIBUTEVERSION_V3)
	for _, v := range values {
		a.Content = append(a.Content, mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(mdl.NewStringAttributeContentV3(v, mdl.ATTRIBUTECONTENTTYPE_STRING)))
	}
	return mdl.MetadataAttributeV3AsMetadataAttribute(a)
}

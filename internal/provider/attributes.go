package provider

import (
	"encoding/base64"
	"net/netip"
	"slices"
	"strings"
	"unicode"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
)

type attributeSpec struct{ id, name string }

var (
	entitySpecs   = []attributeSpec{{DeviceIDAttribute, "deviceId"}, {TargetAddressAttribute, "targetAddress"}}
	locationSpecs = []attributeSpec{{ServiceAttribute, "service"}}
	csrSpecs      = []attributeSpec{{StagingTrustpointAttribute, "stagingTrustpoint"}}
	pushSpecs     = []attributeSpec{{OperationIDAttribute, "operationId"}}
)

func scalarAttributes(value any, specs []attributeSpec) (map[string]string, bool) {
	list, ok := value.([]any)
	if !ok || len(list) != len(specs) {
		return nil, false
	}
	result := make(map[string]string, len(specs))
	for _, item := range list {
		m, ok := object(item, []string{"uuid", "name", "contentType", "version", "content"})
		if !ok || m["contentType"] != "string" || m["version"] != "v3" {
			return nil, false
		}
		name, ok := m["name"].(string)
		if !ok {
			return nil, false
		}
		if _, exists := result[name]; exists {
			return nil, false
		}
		known := false
		for _, spec := range specs {
			if name == spec.name && m["uuid"] == spec.id {
				known = true
				break
			}
		}
		if !known {
			return nil, false
		}
		content, ok := m["content"].([]any)
		if !ok || len(content) != 1 {
			return nil, false
		}
		c, ok := object(content[0], []string{"contentType", "data"})
		if !ok || c["contentType"] != "string" {
			return nil, false
		}
		data, ok := c["data"].(string)
		if !ok || len(data) == 0 || len(data) > 128 {
			return nil, false
		}
		result[name] = data
	}
	return result, true
}

func (b *boundary) validEntityAttrs(value any, boundDevice string) bool {
	attrs, ok := scalarAttributes(value, entitySpecs)
	if !ok {
		return false
	}
	if boundDevice != "" && attrs["deviceId"] != boundDevice {
		return false
	}
	p, approved := b.cfg.Devices[attrs["deviceId"]]
	addr, err := netip.ParseAddr(attrs["targetAddress"])
	return approved && err == nil && addr == p.Target && addr.String() == attrs["targetAddress"]
}

func validLocationAttrs(value any) bool {
	attrs, ok := scalarAttributes(value, locationSpecs)
	return ok && attrs["service"] == "https"
}

func (b *boundary) validCSRAttrs(value any, deviceID string) bool {
	attrs, ok := scalarAttributes(value, csrSpecs)
	return ok && cliToken.MatchString(attrs["stagingTrustpoint"]) &&
		slices.Contains(b.cfg.Devices[deviceID].StagingTrustpoints, attrs["stagingTrustpoint"])
}

func validPushAttrs(value any) bool {
	attrs, ok := scalarAttributes(value, pushSpecs)
	return ok && canonicalUUID(attrs["operationId"])
}

func (b *boundary) validRequest(shape, deviceID string, value any) bool {
	switch shape {
	case "entityAttrs":
		return b.validEntityAttrs(value, "")
	case "locationAttrs":
		return validLocationAttrs(value)
	case "csrAttrs":
		return b.validCSRAttrs(value, deviceID)
	case "pushAttrs":
		return validPushAttrs(value)
	case "entity":
		m, ok := object(value, []string{"name", "kind", "attributes"})
		if !ok || m["kind"] != "iosxe" {
			return false
		}
		name, ok := m["name"].(string)
		return ok && len(name) > 0 && len(name) <= 128 && strings.TrimSpace(name) == name &&
			!strings.ContainsFunc(name, unicode.IsControl) && b.validEntityAttrs(m["attributes"], deviceID)
	case "location":
		m, ok := object(value, []string{"locationAttributes"})
		return ok && validLocationAttrs(m["locationAttributes"])
	case "csr":
		m, ok := object(value, []string{"locationAttributes", "csrAttributes", "renewal"})
		if !ok {
			return false
		}
		_, boolean := m["renewal"].(bool)
		return boolean && validLocationAttrs(m["locationAttributes"]) && b.validCSRAttrs(m["csrAttributes"], deviceID)
	case "push":
		m, ok := object(value, []string{"certificate", "locationAttributes", "pushAttributes"}, "certificateType")
		if !ok {
			return false
		}
		if typ, exists := m["certificateType"]; exists && typ != string(mdl.CERTIFICATETYPE_X_509) {
			return false
		}
		certificate, ok := m["certificate"].(string)
		if !ok || certificate == "" || strings.ContainsAny(certificate, "\r\n") {
			return false
		}
		_, err := base64.StdEncoding.Strict().DecodeString(certificate)
		// This checks the wire encoding only. X.509, CSR key, chain and SAN/EKU
		// policy checks must run in the lifecycle backend before any import.
		return err == nil && validLocationAttrs(m["locationAttributes"]) && validPushAttrs(m["pushAttributes"])
	default:
		return false
	}
}

// Package inventory interprets public, read-only IOS XE evidence.
package inventory

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"regexp"
	"sort"
	"strings"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
)

var ErrIncomplete = errors.New("inventory evidence incomplete or inconsistent")
var ErrUnsupported = errors.New("inventory format unsupported")

type Assignment struct {
	Trustpoint, SHA256, Role string
}

type Certificate struct {
	SelfSignedIdentity             bool
	Trustpoint, SHA256, Kind, Role string
	DER                            []byte
}

type Snapshot struct {
	Complete         bool
	ActiveTrustpoint string
	Certificates     []Certificate
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var versionPattern = regexp.MustCompile(`(?m)^Cisco IOS XE Software, Version [0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.]*\s*$`)

// Parse is atomic: no partial certificates or raw transcript escape on failure.
// ACTIVE means independently observed management binding, not a TLS handshake,
// certificate chain validation, renewal authorization, or a private-key proof.
func Parse(e device.Evidence, assignments []Assignment) (Snapshot, error) {
	if !e.Complete {
		return Snapshot{}, ErrIncomplete
	}
	for _, op := range []device.Operation{device.ReadVersion, device.ReadPKI, device.ReadBinding, device.ReadCertificates, device.ReadHTTPSStatus} {
		cap := e.Capabilities[op]
		if !cap.Available || len(e.Raw[op]) == 0 || len(e.Raw[op]) > 4<<20 {
			return Snapshot{}, ErrIncomplete
		}
		if cap.Transport != "ssh" && !(cap.Transport == "netconf" && (op == device.ReadPKI || op == device.ReadBinding)) {
			return Snapshot{}, ErrUnsupported
		}
	}
	version, err := cliLines(e.Raw[device.ReadVersion], device.ReadVersion)
	if err != nil || len(versionPattern.FindAllString(strings.Join(version, "\n"), -1)) != 1 {
		return Snapshot{}, ErrUnsupported
	}
	groups, err := parsePEM(e.Raw[device.ReadCertificates])
	if err != nil {
		return Snapshot{}, err
	}
	if e.Capabilities[device.ReadPKI].Transport == "netconf" {
		err = checkPKIXML(e.Raw[device.ReadPKI], groups)
	} else {
		err = checkPKICLI(e.Raw[device.ReadPKI], groups)
	}
	if err != nil {
		return Snapshot{}, err
	}
	active, err := parseBinding(e.Raw[device.ReadBinding], e.Capabilities[device.ReadBinding].Transport)
	if err != nil {
		return Snapshot{}, err
	}
	if err = checkHTTPS(e.Raw[device.ReadHTTPSStatus], active); err != nil {
		return Snapshot{}, err
	}
	owned := map[string]Assignment{}
	if len(assignments) > 32 {
		return Snapshot{}, ErrIncomplete
	}
	for _, a := range assignments {
		if !namePattern.MatchString(a.Trustpoint) || !shaPattern.MatchString(a.SHA256) || (a.Role != "STAGED" && a.Role != "ROLLBACK") || a.Trustpoint == active {
			return Snapshot{}, ErrIncomplete
		}
		if _, duplicate := owned[a.Trustpoint]; duplicate {
			return Snapshot{}, ErrIncomplete
		}
		owned[a.Trustpoint] = a
	}
	s := Snapshot{ActiveTrustpoint: active}
	var names []string
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	activeLeaves := 0
	for _, name := range names {
		leaves := 0
		for _, entry := range groups[name] {
			der := entry.der
			cert, _ := x509.ParseCertificate(der) // parsePEM already validates every DER.
			h := sha256.Sum256(der)
			c := Certificate{Trustpoint: name, SHA256: hex.EncodeToString(h[:]), DER: bytes.Clone(der), Kind: "LEAF", Role: "INACTIVE"}
			if !entry.identity {
				c.Kind = "CA"
				c.Role = "CA"
			} else {
				if cert.IsCA {
					c.Kind = "CA_IDENTITY"
					c.SelfSignedIdentity = entry.selfCA
				}
				leaves++
				if name == active {
					c.Role = "ACTIVE"
					activeLeaves++
				}
				if a, ok := owned[name]; ok {
					if a.SHA256 != c.SHA256 {
						return Snapshot{}, ErrIncomplete
					}
					c.Role = a.Role
					delete(owned, name)
				}
			}
			s.Certificates = append(s.Certificates, c)
		}
		// Separate signature/encryption and rollover leaf selection are not yet
		// supported. Never choose an active identity by certificate order.
		if leaves > 1 {
			return Snapshot{}, ErrUnsupported
		}
	}
	if activeLeaves != 1 || len(owned) != 0 {
		return Snapshot{}, ErrIncomplete
	}
	s.Complete = true
	return s, nil
}

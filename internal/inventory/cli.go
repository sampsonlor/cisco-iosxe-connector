package inventory

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
)

var commands = map[device.Operation]string{
	device.ReadVersion:      "show version",
	device.ReadPKI:          "show crypto pki trustpoints",
	device.ReadBinding:      "show running-config | include ^ip http secure-trustpoint",
	device.ReadCertificates: "show crypto pki certificates pem",
	device.ReadHTTPSStatus:  "show ip http server status",
}
var prompt = regexp.MustCompile(`^[A-Za-z0-9_.-]+[#>]$`)
var groupHeader = regexp.MustCompile(`^-{6}Trustpoint:\s*([A-Za-z0-9][A-Za-z0-9_.-]{0,63})-{6}$`)
var trustpointHeader = regexp.MustCompile(`^Trustpoint ([A-Za-z0-9][A-Za-z0-9_.-]{0,63}):$`)

func cliLines(raw []byte, op device.Operation) ([]string, error) {
	if len(raw) == 0 || len(raw) > 4<<20 || !utf8.Valid(raw) {
		return nil, ErrIncomplete
	}
	for _, b := range raw {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' || b == 127 {
			return nil, ErrUnsupported
		}
	}
	s := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if strings.Contains(s, "\r") {
		return nil, ErrUnsupported
	}
	for _, v := range []string{"--more--", "<--- more --->", "authorization failed", "authorization denied", "access denied", "not authorized", "permission denied"} {
		if strings.Contains(strings.ToLower(s), v) {
			return nil, ErrIncomplete
		}
	}
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) == 0 {
		return nil, ErrIncomplete
	}
	first := strings.TrimSpace(lines[0])
	command := commands[op]
	if first == command {
		lines = lines[1:]
	} else if at := strings.IndexAny(first, "#>"); at >= 0 && prompt.MatchString(first[:at+1]) && strings.TrimSpace(first[at+1:]) == command {
		lines = lines[1:]
	}
	if len(lines) > 0 && prompt.MatchString(strings.TrimSpace(lines[len(lines)-1])) {
		lines = lines[:len(lines)-1]
	}
	for _, line := range lines {
		if len(line) > 65536 {
			return nil, ErrIncomplete
		}
		t := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(t, "%") && !(op == device.ReadCertificates && (t == "% ca certificate:" || t == "% self-signed ca certificate:" || t == "% general purpose certificate:" || t == "% only export the ca certificate in pem format." || strings.HasPrefix(t, "% the specified trustpoint is not enrolled ("))) {
			return nil, ErrIncomplete
		}
	}
	return lines, nil
}

// Certificates are accepted only inside an explicit Trustpoint group with an
// explicit purpose marker. Naked PEM cannot establish certificate ownership.
type pemCertificate struct {
	der              []byte
	identity, selfCA bool
}

func parsePEM(raw []byte) (map[string][]pemCertificate, error) {
	lines, err := cliLines(raw, device.ReadCertificates)
	if err != nil {
		return nil, err
	}
	groups := map[string][]pemCertificate{}
	name, kind := "", ""
	count := 0
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if m := groupHeader.FindStringSubmatch(line); m != nil {
			if kind != "" || (name != "" && len(groups[name]) == 0) {
				return nil, ErrIncomplete
			}
			name = m[1]
			if _, ok := groups[name]; ok || len(groups) >= 64 {
				return nil, ErrIncomplete
			}
			groups[name] = nil
			continue
		}
		if name == "" {
			return nil, ErrUnsupported
		}
		switch strings.ToLower(line) {
		case "% ca certificate:", "% general purpose certificate:", "% self-signed ca certificate:":
			if kind != "" {
				return nil, ErrIncomplete
			}
			kind = "LEAF"
			if strings.EqualFold(line, "% ca certificate:") {
				kind = "CA"
			}
			if strings.EqualFold(line, "% self-signed ca certificate:") {
				kind = "SELF_CA"
			}
			continue
		case "% only export the ca certificate in pem format.":
			if len(groups[name]) != 0 || kind != "" {
				return nil, ErrIncomplete
			}
			continue
		}
		if line == "% The specified trustpoint is not enrolled ("+name+")." {
			if len(groups[name]) != 0 || kind != "" {
				return nil, ErrIncomplete
			}
			continue
		}
		if line != "-----BEGIN CERTIFICATE-----" || kind == "" {
			return nil, ErrUnsupported
		}
		var encoded strings.Builder
		ended := false
		for i++; i < len(lines); i++ {
			part := strings.TrimSpace(lines[i])
			if part == "-----END CERTIFICATE-----" {
				ended = true
				break
			}
			if strings.ContainsAny(part, "-:% ") || encoded.Len()+len(part) > 2<<20 {
				return nil, ErrIncomplete
			}
			encoded.WriteString(part)
		}
		if !ended {
			return nil, ErrIncomplete
		}
		der, err := base64.StdEncoding.Strict().DecodeString(encoded.String())
		if err != nil || len(der) > 1<<20 {
			return nil, ErrIncomplete
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, ErrIncomplete
		}
		alias := false
		for j, old := range groups[name] {
			if bytes.Equal(der, old.der) {
				if kind == "LEAF" && cert.IsCA && old.selfCA && !old.identity {
					groups[name][j].identity = true
					alias = true
					break
				}
				return nil, ErrIncomplete
			}
		}
		if !alias {
			if (kind != "LEAF") != cert.IsCA {
				return nil, ErrIncomplete
			}
			if kind == "SELF_CA" && (!bytes.Equal(cert.RawIssuer, cert.RawSubject) || cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) != nil) {
				return nil, ErrIncomplete
			}
			groups[name] = append(groups[name], pemCertificate{der: der, identity: kind == "LEAF", selfCA: kind == "SELF_CA"})
		}
		kind = ""
		count++
		if count > 128 {
			return nil, ErrIncomplete
		}
	}
	if kind != "" || len(groups) == 0 {
		return nil, ErrIncomplete
	}
	for _, certs := range groups {
		if len(certs) == 0 {
			return nil, ErrIncomplete
		}
	}
	return groups, nil
}

func checkPKICLI(raw []byte, groups map[string][]pemCertificate) error {
	lines, err := cliLines(raw, device.ReadPKI)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	current := ""
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m := trustpointHeader.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			current = m[1]
			if seen[current] || groups[current] == nil {
				return ErrIncomplete
			}
			seen[current] = true
			continue
		}
		// The command reference defines indented descriptive fields below each
		// Trustpoint. They are not used as key proof or certificate fingerprints.
		if current == "" || (!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")) {
			return ErrUnsupported
		}
	}
	if len(seen) != len(groups) {
		return ErrIncomplete
	}
	return nil
}

func parseBinding(raw []byte, transport string) (string, error) {
	if transport == "netconf" {
		return bindingXML(raw)
	}
	lines, err := cliLines(raw, device.ReadBinding)
	if err != nil {
		return "", err
	}
	name := ""
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 4 || strings.Join(parts[:3], " ") != "ip http secure-trustpoint" || !namePattern.MatchString(parts[3]) || name != "" {
			return "", ErrIncomplete
		}
		name = parts[3]
	}
	if name == "" {
		return "", ErrIncomplete
	}
	return name, nil
}

func checkHTTPS(raw []byte, active string) error {
	lines, err := cliLines(raw, device.ReadHTTPSStatus)
	if err != nil {
		return err
	}
	fields := map[string]string{}
	cipherContinuation := false
	cipherNames := regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)+(?:\s+[a-z0-9]+(?:-[a-z0-9]+)+)*$`)
	authRetry := regexp.MustCompile(`^HTTP server auth-retry [0-9]{1,5} time-window [0-9]{1,5}$`)
	for _, line := range lines {
		indented := strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok {
			if cipherContinuation && indented && cipherNames.MatchString(line) {
				continue
			}
			if authRetry.MatchString(line) {
				cipherContinuation = false
				continue
			}
			return ErrUnsupported
		}
		cipherContinuation = key == "HTTP secure server ciphersuite"
		switch key {
		case "HTTP secure server status", "HTTP secure server trustpoint", "HTTP secure server port", "HTTP secure server capability":
			if _, seen := fields[key]; seen {
				return ErrIncomplete
			}
			fields[key] = value
		}
	}
	if fields["HTTP secure server status"] != "Enabled" || fields["HTTP secure server trustpoint"] != active {
		return ErrIncomplete
	}
	if c, ok := fields["HTTP secure server capability"]; ok && c != "Present" {
		return ErrIncomplete
	}
	port, err := strconv.ParseUint(fields["HTTP secure server port"], 10, 16)
	if err != nil || port == 0 {
		return ErrIncomplete
	}
	return nil
}

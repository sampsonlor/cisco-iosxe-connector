package lab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
)

type Scope string

const (
	CLIOnly       Scope = "cli-only"
	NETCONFAndCLI Scope = "netconf-and-cli"
)

// Assessment evaluates already-recorded observations, never current device state
// or permission to write. Original reports remain immutable.
type Assessment struct {
	Mode, PolicyVersion, Status, OriginalReportSHA256 string
	Scope                                             Scope
	EvaluatedAt                                       time.Time
	Checks                                            map[string]bool
	Notes                                             []string
}

func Assess(r Report, scope Scope) Assessment {
	a := Assessment{Mode: "RECORDED_EVIDENCE_ASSESSMENT", PolicyVersion: "read-only-v2", Status: "INCOMPLETE", Scope: scope, EvaluatedAt: time.Now().UTC(), Checks: map[string]bool{}, Notes: []string{
		"An operator-approved account may have write privileges; this acceptance covers only fixed read operations, not write authorization or restricted-account proof.",
		"Time synchronization is recorded, not required for read-only acceptance. Recheck it at the next live test before issuance/staging.",
		"This assessment does not reconnect, rerun TLS, establish current state or authorize renewal/deployment.",
	}}
	if (scope != CLIOnly && scope != NETCONFAndCLI) || (r.Scope != "" && r.Scope != scope) || (r.Status != "PASS" && r.Status != "INCOMPLETE") {
		a.Status = "FAIL"
		a.Notes = append(a.Notes, "Unknown/conflicting scope or failed execution cannot be promoted.")
		return a
	}
	if scope == CLIOnly && (len(r.NETCONF.Audit) != 0 || len(r.NETCONF.NETCONFHello) != 0 || len(r.NETCONF.Raw) != 0) {
		a.Status = "FAIL"
		a.Notes = append(a.Notes, "Recorded NETCONF activity cannot be discarded by selecting CLI-only.")
		return a
	}
	clock := string(r.Readiness.Raw[device.ReadClock])
	a.Checks["clock-recorded"] = regexp.MustCompile(`(?m)[*. ]?[0-9]{2}:[0-9]{2}:[0-9]{2}`).MatchString(clock) && (strings.Contains(clock, "Time source is") || strings.Contains(clock, "No time source"))
	a.Checks["time-synchronized"] = strings.Contains(string(r.Readiness.Raw[device.ReadNTP]), "Clock is synchronized")
	a.Checks["readiness"] = completedReads(r.Readiness, device.ReadClock, device.ReadNTP, device.ReadPrivilege, device.ReadProtocolConfig, device.ReadHTTPSStatus) && len(r.Readiness.Raw[device.ReadPrivilege]) > 0 && !r.Started.IsZero() && !r.Finished.Before(r.Started)
	before, beforeErr := inventory.Parse(r.Before, nil)
	after, afterErr := inventory.Parse(r.After, nil)
	ops := []device.Operation{device.ReadVersion, device.ReadPKI, device.ReadBinding, device.ReadCertificates, device.ReadHTTPSStatus}
	a.Checks["inventory"] = beforeErr == nil && afterErr == nil && completedReads(r.Before, ops...) && completedReads(r.After, ops...)
	var expected []byte
	for _, cert := range before.Certificates {
		if cert.Role == "ACTIVE" {
			expected = cert.DER
		}
	}
	a.Checks["tls-matches"] = tlsEvidenceMatches(r.TLSBefore, expected) && tlsEvidenceMatches(r.TLSAfter, expected)
	a.Checks["chain-trusted"] = r.TLSBefore.ChainTrusted && r.TLSAfter.ChainTrusted
	a.Checks["stable-baseline"] = a.Checks["inventory"] && a.Checks["tls-matches"] && snapshotKey(before) == snapshotKey(after) && r.TLSBefore.SHA256 == r.TLSAfter.SHA256
	a.Checks["no-mutation-requests"] = readOnlyAudit(r.Readiness.Audit) && readOnlyAudit(r.Before.Audit) && readOnlyAudit(r.After.Audit) && (len(r.NETCONF.Audit) == 0 || readOnlyAudit(r.NETCONF.Audit))
	for _, observation := range r.WireReads {
		if !observation.Complete || !observation.Accepted || !readOnlyAudit([]device.Event{{Operation: observation.Operation}}) {
			a.Checks["no-mutation-requests"] = false
		}
	}
	required := []string{"clock-recorded", "readiness", "inventory", "tls-matches", "stable-baseline", "no-mutation-requests"}
	if scope == NETCONFAndCLI {
		a.Checks["models"] = verifiedModels(r.Before, r.NETCONF)
		required = append(required, "models")
		a.Notes = append(a.Notes, "NETCONF was selected: successful approved reads, advertised revisions and matching inventory semantics are required.")
	} else {
		a.Notes = append(a.Notes, "CLI-only scope: NETCONF/models were not tested. Empty protocol-filter output does not prove NETCONF disabled.")
	}
	a.Status = "PASS"
	for _, name := range required {
		if !a.Checks[name] {
			a.Status = "INCOMPLETE"
		}
	}
	return a
}

func completedReads(e device.Evidence, required ...device.Operation) bool {
	if !e.Complete || !readOnlyAudit(e.Audit) {
		return false
	}
	seen := map[device.Operation]bool{}
	for _, event := range e.Audit {
		if event.Outcome != "success" {
			return false
		}
		seen[event.Operation] = true
	}
	for _, op := range required {
		if _, present := e.Raw[op]; !seen[op] || !present {
			return false
		}
	}
	return true
}

func tlsEvidenceMatches(r TLSResult, expected []byte) bool {
	if len(expected) == 0 || len(r.Certificates) == 0 || !r.MatchesInventory || !r.HostnameValid || !bytes.Equal(r.Certificates[0], expected) {
		return false
	}
	hash := sha256.Sum256(expected)
	return r.SHA256 == hex.EncodeToString(hash[:])
}

func verifiedModels(cli, netconf device.Evidence) bool {
	if !completedReads(netconf, device.ReadPKI, device.ReadBinding) || !modelRevisionsPresent(netconf.NETCONFHello) {
		return false
	}
	combined := cli
	combined.Raw = map[device.Operation][]byte{}
	combined.Capabilities = map[device.Operation]device.Capability{}
	for op, raw := range cli.Raw {
		combined.Raw[op] = raw
	}
	for op, cap := range cli.Capabilities {
		combined.Capabilities[op] = cap
	}
	for _, op := range []device.Operation{device.ReadPKI, device.ReadBinding} {
		combined.Raw[op] = netconf.Raw[op]
		combined.Capabilities[op] = netconf.Capabilities[op]
	}
	a, errA := inventory.Parse(cli, nil)
	b, errB := inventory.Parse(combined, nil)
	return errA == nil && errB == nil && snapshotKey(a) == snapshotKey(b)
}

// AssessFile saves a new hash-linked sidecar beside a private report. It never
// overwrites the live report or an earlier assessment and performs no network IO.
func AssessFile(path string, scope Scope) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("private report must have an absolute path")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("private report unavailable")
	}
	directory, err := privateDirectory(filepath.Dir(resolved))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return "", errors.New("invalid private report")
	}
	data, err := os.ReadFile(resolved)
	if err != nil || len(data) > 64<<20 {
		return "", errors.New("cannot read private report")
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return "", errors.New("cannot decode private report")
	}
	a := Assess(r, scope)
	hash := sha256.Sum256(data)
	a.OriginalReportSHA256 = hex.EncodeToString(hash[:])
	return writePrivateJSON(directory, "acceptance-assessment.json", a)
}

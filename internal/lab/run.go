package lab

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
)

type Collector interface {
	Collect(context.Context, string) (device.Evidence, error)
	Readiness(context.Context, string) (device.Evidence, error)
}
type Config struct {
	DeviceID, TLSAddress, Hostname string
	NETCONF                        func(context.Context) (device.Evidence, error)
}
type Report struct {
	WireReads                         []ReadObservation
	Target                            map[string]string
	Started, Finished                 time.Time
	Status                            string
	Checks                            map[string]bool
	Notes                             []string
	Readiness, Before, After, NETCONF device.Evidence
	TLSBefore, TLSAfter               TLSResult
}

// WireReads are private diagnostics, never a parsed/healthy inventory. Complete
// means exec finished; Accepted means transport checks accepted the response.
type ReadObservation struct {
	Operation          device.Operation
	Data               []byte
	Complete, Accepted bool
}

func Run(ctx context.Context, c Collector, cfg Config) (r Report) {
	r = Report{Started: time.Now().UTC(), Status: "INCOMPLETE", Checks: map[string]bool{}}
	defer func() {
		total := 0
		valid := true
		for _, e := range []device.Evidence{r.Readiness, r.Before, r.After, r.NETCONF} {
			if len(e.Audit) > 0 {
				total += len(e.Audit)
				valid = valid && readOnlyAudit(e.Audit)
			}
		}
		r.Checks["no-mutation-requests"] = total > 0 && valid
		r.Finished = time.Now().UTC()
	}()
	var err error
	r.Readiness, err = c.Readiness(ctx, cfg.DeviceID)
	if err != nil || !r.Readiness.Complete {
		r.Status = "FAIL"
		r.Notes = append(r.Notes, "readiness: "+safeError(err))
		return r
	}
	clock := string(r.Readiness.Raw[device.ReadClock])
	r.Checks["clock-recorded"] = regexp.MustCompile(`(?m)[*. ]?[0-9]{2}:[0-9]{2}:[0-9]{2}`).MatchString(clock) && (strings.Contains(clock, "Time source is") || strings.Contains(clock, "No time source"))
	r.Checks["time-synchronized"] = strings.Contains(string(r.Readiness.Raw[device.ReadNTP]), "Clock is synchronized")
	r.Notes = append(r.Notes, "Account write restrictions require separate operator/AAA policy evidence; no mutating permission test was attempted.")
	r.Checks["restricted-identity"] = false
	r.Before, err = c.Collect(ctx, cfg.DeviceID)
	if err != nil {
		r.Status = "FAIL"
		r.Notes = append(r.Notes, "inventory-before: "+safeError(err))
		return r
	}
	before, err := inventory.Parse(r.Before, nil)
	if err != nil {
		r.Status = "FAIL"
		r.Notes = append(r.Notes, "inventory-before: "+safeError(err))
		return r
	}
	r.Checks["inventory"] = true
	for _, line := range strings.Split(string(r.Readiness.Raw[device.ReadProtocolConfig]), "\n") {
		if strings.TrimSpace(line) != "netconf-yang" {
			continue
		}
		if cfg.NETCONF == nil {
			r.Notes = append(r.Notes, "NETCONF is configured but no approved endpoint was supplied.")
			break
		}
		r.NETCONF, err = cfg.NETCONF(ctx)
		if err != nil {
			r.Notes = append(r.Notes, "netconf: "+safeError(err))
			if !errors.Is(err, device.ErrUnsupported) {
				r.Status = "FAIL"
				return r
			}
			break
		}
		combined := r.Before
		combined.Raw = map[device.Operation][]byte{}
		combined.Capabilities = map[device.Operation]device.Capability{}
		for op, raw := range r.Before.Raw {
			combined.Raw[op] = raw
		}
		for op, cap := range r.Before.Capabilities {
			combined.Capabilities[op] = cap
		}
		for _, op := range []device.Operation{device.ReadPKI, device.ReadBinding} {
			combined.Raw[op] = r.NETCONF.Raw[op]
			combined.Capabilities[op] = r.NETCONF.Capabilities[op]
		}
		_, parseErr := inventory.Parse(combined, nil)
		r.Checks["models"] = modelRevisionsPresent(r.NETCONF.NETCONFHello) && parseErr == nil
		break
	}
	if !r.Checks["models"] {
		r.Notes = append(r.Notes, "Live NETCONF model revisions/semantics not fully verified; no protocol was enabled.")
	}
	var expected []byte
	for _, cert := range before.Certificates {
		if cert.Role == "ACTIVE" {
			expected = cert.DER
		}
	}
	r.TLSBefore, err = ProbeTLS(ctx, cfg.TLSAddress, cfg.Hostname, expected, nil)
	if err != nil {
		r.Status = "FAIL"
		r.Notes = append(r.Notes, "tls-before: "+safeError(err))
		return r
	}
	r.After, err = c.Collect(ctx, cfg.DeviceID)
	if err != nil {
		r.Status = "FAIL"
		r.Notes = append(r.Notes, "inventory-after: "+safeError(err))
		return r
	}
	after, err := inventory.Parse(r.After, nil)
	if err != nil {
		r.Status = "FAIL"
		r.Notes = append(r.Notes, "inventory-after: "+safeError(err))
		return r
	}
	r.TLSAfter, err = ProbeTLS(ctx, cfg.TLSAddress, cfg.Hostname, expected, nil)
	if err != nil {
		r.Status = "FAIL"
		r.Notes = append(r.Notes, "tls-after: "+safeError(err))
		return r
	}
	r.Checks["tls-matches"] = r.TLSBefore.MatchesInventory && r.TLSAfter.MatchesInventory
	r.Checks["stable-baseline"] = snapshotKey(before) == snapshotKey(after) && r.TLSBefore.SHA256 == r.TLSAfter.SHA256
	r.Checks["no-mutation-requests"] = readOnlyAudit(r.Readiness.Audit) && readOnlyAudit(r.Before.Audit) && readOnlyAudit(r.After.Audit)
	if len(r.NETCONF.Audit) > 0 {
		r.Checks["no-mutation-requests"] = r.Checks["no-mutation-requests"] && readOnlyAudit(r.NETCONF.Audit)
	}
	// PASS requires every gate. Successful reads do not prove no write privilege.
	r.Status = "PASS"
	for _, gate := range []string{"clock-recorded", "inventory", "tls-matches", "stable-baseline", "no-mutation-requests", "models", "restricted-identity"} {
		if !r.Checks[gate] {
			r.Status = "INCOMPLETE"
		}
	}
	return r
}
func safeError(err error) string {
	for _, known := range []error{device.ErrPolicy, device.ErrHostKey, device.ErrAuthentication, device.ErrPermission, device.ErrSessionRejected, device.ErrUnsupported, device.ErrProtocol, device.ErrTransport, device.ErrLimit, device.ErrRead, inventory.ErrIncomplete, inventory.ErrUnsupported, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "read/verification failed; inspect private evidence"
}
func snapshotKey(s inventory.Snapshot) string {
	parts := []string{s.ActiveTrustpoint}
	for _, c := range s.Certificates {
		parts = append(parts, c.Trustpoint+"="+c.SHA256+"="+c.Role)
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n")
}
func readOnlyAudit(events []device.Event) bool {
	if len(events) == 0 {
		return false
	}
	for _, e := range events {
		switch e.Operation {
		case device.ReadVersion, device.ReadPKI, device.ReadBinding, device.ReadCertificates, device.ReadHTTPSStatus, device.ReadClock, device.ReadNTP, device.ReadPrivilege, device.ReadProtocolConfig:
		default:
			return false
		}
	}
	return true
}
func modelRevisionsPresent(raw []byte) bool {
	var h struct {
		Capabilities struct {
			Items []string `xml:"capability"`
		} `xml:"capabilities"`
	}
	if len(raw) == 0 || len(raw) > 64<<10 || xml.Unmarshal(raw, &h) != nil {
		return false
	}
	seen := map[string]bool{}
	for _, s := range h.Capabilities.Items {
		u, err := url.Parse(s)
		if err != nil {
			continue
		}
		m := u.Query().Get("module")
		if m == "Cisco-IOS-XE-native" || m == "Cisco-IOS-XE-http" || m == "Cisco-IOS-XE-crypto-pki-oper" {
			_, err = time.Parse("2006-01-02", u.Query().Get("revision"))
			if err == nil {
				seen[m] = true
			}
		}
	}
	return len(seen) == 3
}

// Evidence stays outside every Git checkout and never overwrites an old run.
func ValidateEvidenceDirectory(directory string) error {
	if !filepath.IsAbs(directory) {
		return errors.New("evidence directory must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return errors.New("evidence directory must exist")
	}
	for path := resolved; ; path = filepath.Dir(path) {
		if _, err := os.Lstat(filepath.Join(path, ".git")); err == nil {
			return errors.New("evidence directory cannot be in a Git checkout")
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	if _, err = os.Lstat(filepath.Join(resolved, "report.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("evidence report already exists or is inaccessible")
	}
	return nil
}
func WriteReport(directory string, r Report) (string, error) {
	if err := ValidateEvidenceDirectory(directory); err != nil {
		return "", err
	}
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", errors.New("cannot encode private evidence")
	}
	path := filepath.Join(directory, "report.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", errors.New("cannot create private evidence")
	}
	_, writeErr := f.Write(append(data, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return "", errors.New("private evidence write incomplete")
	}
	return path, nil
}

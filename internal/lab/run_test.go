package lab

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
)

type fakeCollector struct {
	der      []byte
	calls    int
	denied   bool
	drift    bool
	netconf  bool
	unsynced bool
}

func (f *fakeCollector) Readiness(context.Context, string) (device.Evidence, error) {
	if f.denied {
		return device.Evidence{}, device.ErrPermission
	}
	e := device.Evidence{Complete: true, Raw: map[device.Operation][]byte{device.ReadClock: []byte("12:00:00.000 UTC Fri Oct 23 2026\nTime source is NTP\n"), device.ReadNTP: []byte("Clock is synchronized"), device.ReadPrivilege: []byte("Current privilege level is 15"), device.ReadProtocolConfig: []byte("")}}
	if f.netconf {
		e.Raw[device.ReadProtocolConfig] = []byte("netconf-yang\n")
	}
	if f.unsynced {
		e.Raw[device.ReadClock] = []byte("*12:00:00.000 UTC Fri Oct 23 2026\nNo time source\n")
		e.Raw[device.ReadNTP] = []byte("%NTP is not enabled.")
	}
	e.Raw[device.ReadHTTPSStatus] = []byte("HTTP secure server status: Enabled\n")
	for _, op := range []device.Operation{device.ReadClock, device.ReadNTP, device.ReadPrivilege, device.ReadProtocolConfig, device.ReadHTTPSStatus} {
		e.Audit = append(e.Audit, device.Event{Transport: "ssh", Operation: op, Outcome: "success"})
	}
	return e, nil
}
func (f *fakeCollector) Collect(context.Context, string) (device.Evidence, error) {
	f.calls++
	if f.drift && f.calls > 1 {
		return device.Evidence{}, device.ErrRead
	}
	e := device.Evidence{Complete: true, Raw: map[device.Operation][]byte{
		device.ReadVersion: []byte("Cisco IOS XE Software, Version 26.01.02\n"), device.ReadPKI: []byte("Trustpoint HTTPS-ACTIVE:\n  Certificate configured.\n"), device.ReadBinding: []byte("ip http secure-trustpoint HTTPS-ACTIVE\n"), device.ReadHTTPSStatus: []byte("HTTP secure server status: Enabled\nHTTP secure server port: 443\nHTTP secure server trustpoint: HTTPS-ACTIVE\n"), device.ReadCertificates: append([]byte("------Trustpoint: HTTPS-ACTIVE------\n% General Purpose Certificate:\n"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.der})...)}, Capabilities: map[device.Operation]device.Capability{}}
	for op := range e.Raw {
		e.Capabilities[op] = device.Capability{Available: true, Transport: "ssh"}
		e.Audit = append(e.Audit, device.Event{Transport: "ssh", Operation: op, Outcome: "success"})
	}
	return e, nil
}
func TestLabReportSeparatesObservedAndUnverifiedGates(t *testing.T) {
	address, der, _ := tlsFixture(t)
	src := &fakeCollector{der: der}
	r := Run(context.Background(), src, Config{DeviceID: "router-a", TLSAddress: address, Hostname: "router.example.test"})
	for _, name := range []string{"inventory", "clock-recorded", "tls-matches", "stable-baseline", "no-mutation-requests"} {
		if !r.Checks[name] {
			t.Errorf("missing observation: %s", name)
		}
	}
	if r.Status != "PASS" || r.Checks["models"] || r.Checks["restricted-identity"] {
		t.Fatal("approved CLI reads were blocked by unselected models/account write restrictions")
	}
	src = &fakeCollector{der: der, denied: true}
	r = Run(context.Background(), src, Config{DeviceID: "router-a", TLSAddress: address, Hostname: "router.example.test"})
	if src.calls != 0 || r.Status == "PASS" {
		t.Fatal("AAA denial continued")
	}
	src = &fakeCollector{der: der, drift: true}
	r = Run(context.Background(), src, Config{DeviceID: "router-a", TLSAddress: address, Hostname: "router.example.test"})
	if r.Checks["stable-baseline"] || r.Status == "PASS" {
		t.Fatal("failed second read reported stable")
	}
}

func TestReadOnlyAcceptanceScope(t *testing.T) {
	address, der, _ := tlsFixture(t)
	r := Run(context.Background(), &fakeCollector{der: der, unsynced: true}, Config{DeviceID: "router-a", TLSAddress: address, Hostname: "router.example.test"})
	if r.Status != "PASS" || r.Scope != CLIOnly || r.Checks["time-synchronized"] || r.Checks["models"] {
		t.Fatal("CLI-only scope must permit approved privilege-15 reads and record unsynchronized time")
	}
	called := false
	r = Run(context.Background(), &fakeCollector{der: der}, Config{DeviceID: "router-a", TLSAddress: address, Hostname: "router.example.test", NETCONF: func(context.Context) (device.Evidence, error) {
		called = true
		return device.Evidence{}, device.ErrUnsupported
	}})
	if !called || r.Scope != NETCONFAndCLI || r.Status != "INCOMPLETE" || r.Checks["models"] {
		t.Fatal("selected NETCONF was skipped or passed from empty CLI filter output")
	}
}

func TestRecordedAcceptancePreservesEvidence(t *testing.T) {
	address, der, _ := tlsFixture(t)
	r := Run(context.Background(), &fakeCollector{der: der, unsynced: true}, Config{DeviceID: "router-a", TLSAddress: address, Hostname: "router.example.test"})
	// A completed legacy run used broader gates; keep that historical report.
	r.Scope, r.Status = "", "INCOMPLETE"
	r.Checks["restricted-identity"] = false
	directory := t.TempDir()
	path, err := WriteReport(directory, r)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(path)
	digest := sha256.Sum256(original)
	assessmentPath, err := AssessFile(path, CLIOnly)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(assessmentPath)
	var a Assessment
	if err = json.Unmarshal(data, &a); err != nil {
		t.Fatal(err)
	}
	if a.Status != "PASS" || a.Mode != "RECORDED_EVIDENCE_ASSESSMENT" || a.OriginalReportSHA256 != hex.EncodeToString(digest[:]) || a.Checks["time-synchronized"] || a.Checks["models"] {
		t.Fatal("derived assessment lost its scope, original hash or unverified observations")
	}
	unchanged, _ := os.ReadFile(path)
	if string(original) != string(unchanged) {
		t.Fatal("historical report overwritten")
	}
	if _, err := AssessFile(path, CLIOnly); err == nil {
		t.Fatal("assessment overwritten")
	}
	for name, change := range map[string]func(*Report){
		"failed-run": func(r *Report) { r.Status = "FAIL" },
		"partial":    func(r *Report) { r.After.Complete = false },
		"write": func(r *Report) {
			r.Before.Audit = append(r.Before.Audit, device.Event{Operation: device.Import, Outcome: "success"})
		},
		"denied-read":      func(r *Report) { r.Readiness.Audit[0].Outcome = "permission-denied" },
		"tls-name":         func(r *Report) { r.TLSAfter.HostnameValid = false },
		"tls-der":          func(r *Report) { r.TLSAfter.Certificates = nil },
		"clock":            func(r *Report) { delete(r.Readiness.Raw, device.ReadClock) },
		"selected-netconf": func(r *Report) { r.Scope = NETCONFAndCLI },
	} {
		t.Run(name, func(t *testing.T) {
			var changed Report
			if err := json.Unmarshal(original, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			if Assess(changed, CLIOnly).Status == "PASS" {
				t.Fatal("inconsistent evidence promoted")
			}
		})
	}
	if Assess(r, NETCONFAndCLI).Status == "PASS" || Assess(r, "unknown").Status == "PASS" {
		t.Fatal("missing models or unknown scope accepted")
	}
	checkout := t.TempDir()
	if err := os.Mkdir(filepath.Join(checkout, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(checkout, "report.json"), original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := AssessFile(filepath.Join(checkout, "report.json"), CLIOnly); err == nil {
		t.Fatal("private assessment entered Git")
	}
}
func TestPrivateEvidenceNeverOverwritesOrEntersCheckout(t *testing.T) {
	root := t.TempDir()
	r := Report{Status: "INCOMPLETE", Checks: map[string]bool{"inventory": true}}
	p, err := WriteReport(root, r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil || !strings.Contains(string(b), "INCOMPLETE") {
		t.Fatal("missing evidence")
	}
	if _, err = WriteReport(root, r); err == nil {
		t.Fatal("overwrote private evidence")
	}
	repo := t.TempDir()
	if err = os.Mkdir(filepath.Join(repo, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = WriteReport(repo, r); err == nil {
		t.Fatal("evidence entered a checkout")
	}
	if _, err = WriteReport("relative", r); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatal("relative evidence location accepted")
	}
}

func TestNETCONFIdentityFailureStopsLab(t *testing.T) {
	_, der, _ := tlsFixture(t)
	src := &fakeCollector{der: der, netconf: true}
	r := Run(context.Background(), src, Config{DeviceID: "router-a", Hostname: "router.example.test", NETCONF: func(context.Context) (device.Evidence, error) { return device.Evidence{}, device.ErrHostKey }})
	if r.Status != "FAIL" || src.calls != 1 || r.Checks["tls-matches"] {
		t.Fatal("NETCONF identity rejection did not stop lab")
	}
}

func TestReplayRequiresCompletedCapturedReads(t *testing.T) {
	_, der, _ := tlsFixture(t)
	src := &fakeCollector{der: der}
	e, err := src.Collect(context.Background(), "router-a")
	if err != nil {
		t.Fatal(err)
	}
	r := Report{Status: "FAIL"}
	for op, raw := range e.Raw {
		r.WireReads = append(r.WireReads, ReadObservation{Operation: op, Data: raw, Complete: true, Accepted: false})
	}
	if s, err := Replay(r); err != nil || !s.Complete {
		t.Fatal("complete captured reads could not be revalidated")
	}
	r.WireReads[0].Complete = false
	if s, err := Replay(r); err == nil || s.Complete {
		t.Fatal("incomplete wire execution was promoted")
	}
}

package lab

import (
	"context"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
)

type fakeCollector struct {
	der     []byte
	calls   int
	denied  bool
	drift   bool
	netconf bool
}

func (f *fakeCollector) Readiness(context.Context, string) (device.Evidence, error) {
	if f.denied {
		return device.Evidence{}, device.ErrPermission
	}
	e := device.Evidence{Complete: true, Raw: map[device.Operation][]byte{device.ReadClock: []byte("12:00:00.000 UTC Fri Oct 23 2026\nTime source is NTP\n"), device.ReadNTP: []byte("Clock is synchronized"), device.ReadPrivilege: []byte("Current privilege level is 15"), device.ReadProtocolConfig: []byte("")}}
	if f.netconf {
		e.Raw[device.ReadProtocolConfig] = []byte("netconf-yang\n")
	}
	for _, op := range []device.Operation{device.ReadClock, device.ReadNTP, device.ReadPrivilege, device.ReadProtocolConfig} {
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
	if r.Status != "INCOMPLETE" || r.Checks["models"] || r.Checks["restricted-identity"] {
		t.Fatal("unverified environment gates silently passed")
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

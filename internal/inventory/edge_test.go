package inventory_test

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
)

func TestInventoryCAOnlyAndBounds(t *testing.T) {
	f := synthetic(t, false)
	// Cisco's documented CA-only output includes two informational notices.
	block := "% General Purpose Certificate:\n" + string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.der["UNMANAGED"]}))
	f.e.Raw[device.ReadCertificates] = bytes.Replace(f.e.Raw[device.ReadCertificates], []byte(block), nil, 1)
	header := "------Trustpoint: UNMANAGED------\n"
	f.e.Raw[device.ReadCertificates] = bytes.Replace(f.e.Raw[device.ReadCertificates], []byte(header), []byte(header+"% The specified trustpoint is not enrolled (UNMANAGED).\n% Only export the CA certificate in PEM format.\n"), 1)
	s, err := inventory.Parse(f.e, f.roles)
	if err != nil || !s.Complete || len(s.Certificates) != 7 {
		t.Fatalf("CA-only incomplete: %v", err)
	}
	cases := map[string]func(*fixture){
		"unknown transport": func(f *fixture) {
			f.e.Capabilities[device.ReadPKI] = device.Capability{Available: true, Transport: "restconf"}
		},
		"duplicate CLI binding": func(f *fixture) {
			f.e.Raw[device.ReadBinding] = []byte("ip http secure-trustpoint HTTPS-LIVE\nip http secure-trustpoint HTTPS-LIVE")
		},
		"CA as active": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = bytes.Replace(f.e.Raw[device.ReadCertificates], []byte("% General Purpose Certificate:\n"+string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.der["HTTPS-LIVE"]}))), nil, 1)
		},
		"unknown trustpoint format": func(f *fixture) { f.e.Raw[device.ReadPKI] = []byte("Unknown vNext output") },
		"two identities in active TP": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = append(f.e.Raw[device.ReadCertificates], []byte("% General Purpose Certificate:\n"+string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.der["UNMANAGED"]})))...)
		},
		"invalid DER": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = bytes.Replace(f.e.Raw[device.ReadCertificates], []byte(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.der["HTTPS-LIVE"]})), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}), 1)
		},
		"PEM header unknown": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = bytes.Replace(f.e.Raw[device.ReadCertificates], []byte("BEGIN CERTIFICATE"), []byte("BEGIN UNKNOWN"), 1)
		},
		"unknown http status": func(f *fixture) { f.e.Raw[device.ReadHTTPSStatus] = []byte("unknown output") },
		"invalid http port": func(f *fixture) {
			f.e.Raw[device.ReadHTTPSStatus] = bytes.ReplaceAll(f.e.Raw[device.ReadHTTPSStatus], []byte("443"), []byte("65536"))
		},
		"unavailable capability": func(f *fixture) {
			f.e.Raw[device.ReadHTTPSStatus] = bytes.ReplaceAll(f.e.Raw[device.ReadHTTPSStatus], []byte("Present"), []byte("Not present"))
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := synthetic(t, false)
			mutate(&f)
			s, err := inventory.Parse(f.e, nil)
			if err == nil || s.Complete || len(s.Certificates) != 0 {
				t.Fatal("invalid evidence accepted")
			}
			if !errors.Is(err, inventory.ErrIncomplete) && !errors.Is(err, inventory.ErrUnsupported) {
				t.Fatal("untyped error")
			}
		})
	}
}

func TestInventoryXMLAndAssignmentBoundaries(t *testing.T) {
	cases := map[string]func(*fixture){
		"duplicate attributes": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.Replace(f.e.Raw[device.ReadPKI], []byte(`message-id="1"`), []byte(`message-id="1" message-id="2"`), 1)
		},
		"second root": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = append(f.e.Raw[device.ReadPKI], f.e.Raw[device.ReadPKI]...)
		},
		"excessive depth": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = reply(strings.Repeat("<x>", 70) + strings.Repeat("</x>", 70))
		},
		"entity": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.Replace(f.e.Raw[device.ReadPKI], []byte("HTTPS-LIVE"), []byte("&unknown;"), 1)
		},
		"foreign child": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.Replace(f.e.Raw[device.ReadPKI], []byte("<label>HTTPS-LIVE</label>"), []byte(`<label xmlns="urn:wrong">HTTPS-LIVE</label>`), 1)
		},
		"association mismatch": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.Replace(f.e.Raw[device.ReadPKI], []byte("<tp-name>HTTPS-LIVE</tp-name>"), []byte("<tp-name>MISSING</tp-name>"), 1)
		},
		"duplicate serial": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.Replace(f.e.Raw[device.ReadPKI], []byte("<serial-number>1</serial-number>"), []byte("<serial-number>1</serial-number><serial-number>1</serial-number>"), 1)
		},
		"unknown schema child": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.Replace(f.e.Raw[device.ReadPKI], []byte("<cert>"), []byte("<unexpected/><cert>"), 1)
		},
		"mixed data": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.Replace(f.e.Raw[device.ReadPKI], []byte("<data>"), []byte("<data>garbage"), 1)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := synthetic(t, true)
			mutate(&f)
			s, err := inventory.Parse(f.e, nil)
			if err == nil || s.Complete || len(s.Certificates) != 0 {
				t.Fatal("ambiguous XML accepted")
			}
		})
	}
	f := synthetic(t, false)
	for _, a := range [][]inventory.Assignment{{{Trustpoint: "bad;command", SHA256: strings.Repeat("0", 64), Role: "STAGED"}}, {f.roles[0], f.roles[0]}, {{Trustpoint: "HTTPS-OLD", SHA256: "", Role: "ROLLBACK"}}, {{Trustpoint: "HTTPS-OLD", SHA256: strings.Repeat("0", 64), Role: "ACTIVE"}}} {
		if _, err := inventory.Parse(f.e, a); err == nil {
			t.Fatal("invalid assignment accepted")
		}
		if _, err := inventory.NewReader(&source{}, map[string][]inventory.Assignment{"router-a": a}); err == nil {
			t.Fatal("reader accepted invalid assignment")
		}
	}
	var nilSource *source
	if _, err := inventory.NewReader(nilSource, nil); err == nil {
		t.Fatal("typed nil source accepted")
	}
	r, err := inventory.NewReader(&source{evidence: f.e}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.ReadHTTPS(ctx, access()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancel lost")
	}
}

func TestInventoryConcurrentParsing(t *testing.T) {
	f := synthetic(t, true)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 3 {
				s, err := inventory.Parse(f.e, f.roles)
				if err != nil || !s.Complete {
					t.Error("concurrent parse failed")
				}
			}
		})
	}
	wg.Wait()
}

func TestHTTPSStatusWrappedCipherFields(t *testing.T) {
	f := synthetic(t, false)
	f.e.Raw[device.ReadHTTPSStatus] = append(f.e.Raw[device.ReadHTTPSStatus], []byte("HTTP server auth-retry 0 time-window 0\nHTTP secure server ciphersuite: aes-128-cbc\n        ecdhe-rsa-aes-gcm-sha2 tls13-aes128-gcm-sha256\n")...)
	if s, err := inventory.Parse(f.e, nil); err != nil || !s.Complete {
		t.Fatalf("wrapped status: %v", err)
	}
	f.e.Raw[device.ReadHTTPSStatus] = append(f.e.Raw[device.ReadHTTPSStatus], []byte("        HTTP secure server trustpoint HTTPS-OLD\n")...)
	if s, err := inventory.Parse(f.e, nil); err == nil || s.Complete {
		t.Fatal("unknown wrapped field accepted")
	}
}

func FuzzInventoryRejectsPartial(f *testing.F) {
	baseline := synthetic(f, true)
	f.Add(uint8(0), []byte("------Trustpoint: TEST------\n% CA certificate:\n"))
	f.Add(uint8(1), []byte(`<rpc-reply xmlns="`+nc+`"><data/></rpc-reply>`))
	f.Add(uint8(2), baseline.e.Raw[device.ReadBinding])
	f.Add(uint8(0), baseline.e.Raw[device.ReadCertificates])
	f.Fuzz(func(t *testing.T, choice uint8, raw []byte) {
		if len(raw) > 4<<20 {
			t.Skip()
		}
		e := baseline.e
		e.Raw = map[device.Operation][]byte{}
		for op, b := range baseline.e.Raw {
			e.Raw[op] = b
		}
		e.Raw[[]device.Operation{device.ReadCertificates, device.ReadPKI, device.ReadBinding, device.ReadHTTPSStatus, device.ReadVersion}[int(choice)%5]] = raw
		s, err := inventory.Parse(e, nil)
		if err != nil && (s.Complete || len(s.Certificates) != 0) {
			t.Fatal("partial inventory exposed")
		}
	})
}

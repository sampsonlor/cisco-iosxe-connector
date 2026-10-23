package inventory_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
)

const nc = "urn:ietf:params:xml:ns:netconf:base:1.0"
const pki = "http://cisco.com/ns/yang/Cisco-IOS-XE-crypto-pki-oper"
const native = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
const httpNS = "http://cisco.com/ns/yang/Cisco-IOS-XE-http"

type fixture struct {
	e     device.Evidence
	der   map[string][]byte
	roles []inventory.Assignment
}

func certificate(t *testing.T, serial int64, ca bool) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "synthetic.example.test"}, NotBefore: time.Unix(1700000000, 0), NotAfter: time.Unix(2000000000, 0), BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageDigitalSignature}
	if ca {
		c.KeyUsage |= x509.KeyUsageCertSign
	}
	b, err := x509.CreateCertificate(rand.Reader, c, c, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func fingerprint(der []byte) string { h := sha256.Sum256(der); return hex.EncodeToString(h[:]) }
func reply(s string) []byte {
	return []byte(`<rpc-reply xmlns="` + nc + `" message-id="1"><data>` + s + `</data></rpc-reply>`)
}
func synthetic(t *testing.T, netconf bool) fixture {
	t.Helper()
	f := fixture{der: map[string][]byte{}, e: device.Evidence{Complete: true, Raw: map[device.Operation][]byte{}, Capabilities: map[device.Operation]device.Capability{}}}
	var pemText, labels, bundles strings.Builder
	ca := certificate(t, 1, true)
	// Activity is deliberately NOT the first leaf, nor a name convention.
	for i, name := range []string{"HTTPS-STAGE-A", "UNMANAGED", "HTTPS-OLD", "HTTPS-LIVE"} {
		leaf := certificate(t, int64(i+2), false)
		f.der[name] = leaf
		fmt.Fprintf(&pemText, "------Trustpoint: %s------\n%% CA certificate:\n%s\n%% General Purpose Certificate:\n%s", name, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}))
		fmt.Fprintf(&labels, "Trustpoint %s:\n    Subject Name:\n    cn=Synthetic CA\n    Certificate configured.\n", name)
		fmt.Fprintf(&bundles, "<crypto-pki-bundle><label>%s</label><tp-keys-generated>true</tp-keys-generated>", name)
		for _, der := range [][]byte{ca, leaf} {
			cert, _ := x509.ParseCertificate(der)
			h := md5.Sum(der)
			fmt.Fprintf(&bundles, "<cert><serial-number>%s</serial-number><md5-fp>%X</md5-fp><is-ca-cert>%t</is-ca-cert><asc-tp><tp-name>%s</tp-name></asc-tp></cert>", cert.SerialNumber.Text(16), h, cert.IsCA, name)
		}
		bundles.WriteString("</crypto-pki-bundle>")
	}
	f.e.Raw[device.ReadVersion] = []byte("Cisco IOS XE Software, Version 26.01.02\nCisco IOS Software\n")
	f.e.Raw[device.ReadCertificates] = []byte(pemText.String())
	f.e.Raw[device.ReadPKI] = []byte(labels.String())
	f.e.Raw[device.ReadBinding] = []byte("ip http secure-trustpoint HTTPS-LIVE\n")
	f.e.Raw[device.ReadHTTPSStatus] = []byte("HTTP server status: Disabled\nHTTP secure server capability: Present\nHTTP secure server status: Enabled\nHTTP secure server port: 443\nHTTP secure server trustpoint: HTTPS-LIVE\n")
	for op := range f.e.Raw {
		f.e.Capabilities[op] = device.Capability{Available: true, Transport: "ssh"}
	}
	if netconf {
		f.e.Raw[device.ReadPKI] = reply(`<crypto-pki-oper-data xmlns="` + pki + `">` + bundles.String() + `</crypto-pki-oper-data>`)
		f.e.Raw[device.ReadBinding] = reply(`<native xmlns="` + native + `"><ip><http xmlns="` + httpNS + `"><secure-trustpoint>HTTPS-LIVE</secure-trustpoint></http></ip></native>`)
		for _, op := range []device.Operation{device.ReadPKI, device.ReadBinding} {
			f.e.Capabilities[op] = device.Capability{Available: true, Transport: "netconf"}
		}
	}
	f.roles = []inventory.Assignment{{Trustpoint: "HTTPS-STAGE-A", SHA256: fingerprint(f.der["HTTPS-STAGE-A"]), Role: "STAGED"}, {Trustpoint: "HTTPS-OLD", SHA256: fingerprint(f.der["HTTPS-OLD"]), Role: "ROLLBACK"}}
	return f
}

func TestPEMTrustpointInventory(t *testing.T) {
	for _, netconf := range []bool{false, true} {
		t.Run(fmt.Sprint(netconf), func(t *testing.T) {
			f := synthetic(t, netconf)
			// CRLF, whitespace and prompt/command echoes must preserve attribution.
			f.e.Raw[device.ReadCertificates] = []byte("router-test#show crypto pki certificates pem\r\n" + strings.ReplaceAll(string(f.e.Raw[device.ReadCertificates]), "\n", "\r\n") + "router-test#\r\n")
			s, err := inventory.Parse(f.e, f.roles)
			if err != nil || !s.Complete || len(s.Certificates) != 8 || s.ActiveTrustpoint != "HTTPS-LIVE" {
				t.Fatalf("snapshot complete=%v count=%d err=%v", s.Complete, len(s.Certificates), err)
			}
			caCount := 0
			for _, c := range s.Certificates {
				if c.SHA256 != fingerprint(c.DER) {
					t.Fatal("fingerprint not derived from full DER")
				}
				if c.Kind == "CA" {
					caCount++
					if c.Role != "CA" {
						t.Fatal("CA marked as leaf role")
					}
				} else if !bytes.Equal(c.DER, f.der[c.Trustpoint]) {
					t.Fatal("leaf attributed to wrong Trustpoint")
				}
			}
			if caCount != 4 {
				t.Fatalf("shared CA occurrences lost: %d", caCount)
			}
		})
	}
}

func TestIndependentHTTPSBindingAndRoles(t *testing.T) {
	f := synthetic(t, true)
	s, err := inventory.Parse(f.e, f.roles)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"HTTPS-LIVE": "ACTIVE", "HTTPS-STAGE-A": "STAGED", "HTTPS-OLD": "ROLLBACK", "UNMANAGED": "INACTIVE"}
	for _, c := range s.Certificates {
		if c.Kind == "LEAF" && c.Role != want[c.Trustpoint] {
			t.Errorf("%s role=%s", c.Trustpoint, c.Role)
		}
	}
	// No operation ownership evidence: a stage-like name is simply inactive.
	s, err = inventory.Parse(f.e, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range s.Certificates {
		if c.Trustpoint == "HTTPS-STAGE-A" && c.Kind == "LEAF" && c.Role != "INACTIVE" {
			t.Fatal("role guessed from name")
		}
	}
	bad := []inventory.Assignment{{Trustpoint: "HTTPS-STAGE-A", SHA256: strings.Repeat("0", 64), Role: "STAGED"}}
	if s, err := inventory.Parse(f.e, bad); err == nil || s.Complete || len(s.Certificates) != 0 {
		t.Fatal("stale assignment accepted")
	}
	bad = []inventory.Assignment{{Trustpoint: "HTTPS-LIVE", SHA256: fingerprint(f.der["HTTPS-LIVE"]), Role: "ROLLBACK"}}
	if _, err := inventory.Parse(f.e, bad); err == nil {
		t.Fatal("active rollback contradiction accepted")
	}
}

func TestIncompleteInventoryNeverHealthyEmpty(t *testing.T) {
	cases := map[string]func(*fixture){
		"missing read":     func(f *fixture) { delete(f.e.Raw, device.ReadVersion) },
		"unavailable read": func(f *fixture) { f.e.Capabilities[device.ReadPKI] = device.Capability{} },
		"wrong platform":   func(f *fixture) { f.e.Raw[device.ReadVersion] = []byte("some other OS") },
		"truncated pem": func(f *fixture) {
			b := f.e.Raw[device.ReadCertificates]
			f.e.Raw[device.ReadCertificates] = b[:len(b)-35]
		},
		"paging": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = append(f.e.Raw[device.ReadCertificates], []byte("--More--")...)
		},
		"cli denied": func(f *fixture) { f.e.Raw[device.ReadCertificates] = []byte("% Authorization failed") },
		"trailing unknown": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = append(f.e.Raw[device.ReadCertificates], []byte("unexpected trailer")...)
		},
		"unattributed pem": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = bytes.ReplaceAll(f.e.Raw[device.ReadCertificates], []byte("------Trustpoint: HTTPS-STAGE-A------\n"), nil)
		},
		"marker mismatch": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = bytes.Replace(f.e.Raw[device.ReadCertificates], []byte("% CA certificate:"), []byte("% General Purpose Certificate:"), 1)
		},
		"duplicate block": func(f *fixture) {
			f.e.Raw[device.ReadCertificates] = append(f.e.Raw[device.ReadCertificates], f.e.Raw[device.ReadCertificates]...)
		},
		"empty inventory": func(f *fixture) { f.e.Raw[device.ReadCertificates] = []byte("\n") },
		"false complete":  func(f *fixture) { f.e.Complete = false },
		"bad control":     func(f *fixture) { f.e.Raw[device.ReadCertificates] = append(f.e.Raw[device.ReadCertificates], 0x1b) },
		"binding mismatch": func(f *fixture) {
			f.e.Raw[device.ReadBinding] = bytes.ReplaceAll(f.e.Raw[device.ReadBinding], []byte("HTTPS-LIVE"), []byte("HTTPS-OLD"))
		},
		"duplicate binding": func(f *fixture) {
			f.e.Raw[device.ReadBinding] = reply(`<native xmlns="` + native + `"><ip><http xmlns="` + httpNS + `"><secure-trustpoint>HTTPS-LIVE</secure-trustpoint><secure-trustpoint>HTTPS-OLD</secure-trustpoint></http></ip></native>`)
		},
		"missing xml node": func(f *fixture) { f.e.Raw[device.ReadPKI] = reply("") },
		"wrong xml namespace": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.ReplaceAll(f.e.Raw[device.ReadPKI], []byte(pki), []byte("urn:wrong"))
		},
		"xml rpc error": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = []byte(`<rpc-reply xmlns="` + nc + `"><rpc-error/></rpc-reply>`)
		},
		"xml doctype": func(f *fixture) { f.e.Raw[device.ReadPKI] = append([]byte(`<!DOCTYPE x>`), f.e.Raw[device.ReadPKI]...) },
		"xml duplicate label": func(f *fixture) {
			f.e.Raw[device.ReadPKI] = bytes.Replace(f.e.Raw[device.ReadPKI], []byte("<label>HTTPS-OLD</label>"), []byte("<label>HTTPS-OLD</label><label>HTTPS-LIVE</label>"), 1)
		},
		"xml fingerprint mismatch": func(f *fixture) {
			b := f.e.Raw[device.ReadPKI]
			a := bytes.Index(b, []byte("<md5-fp>")) + 8
			b[a] = 'Z'
		},
		"xml missing certificate": func(f *fixture) {
			b := f.e.Raw[device.ReadPKI]
			a := bytes.Index(b, []byte("<cert>"))
			z := bytes.Index(b, []byte("</cert>")) + 7
			f.e.Raw[device.ReadPKI] = append(b[:a:a], b[z:]...)
		},
		"http disabled": func(f *fixture) {
			f.e.Raw[device.ReadHTTPSStatus] = bytes.Replace(f.e.Raw[device.ReadHTTPSStatus], []byte("status: Enabled"), []byte("status: Disabled"), 1)
		},
		"http duplicate critical": func(f *fixture) {
			f.e.Raw[device.ReadHTTPSStatus] = append(f.e.Raw[device.ReadHTTPSStatus], []byte("HTTP secure server trustpoint: HTTPS-OLD\n")...)
		},
		"too big": func(f *fixture) { f.e.Raw[device.ReadCertificates] = bytes.Repeat([]byte("x"), 4<<20+1) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := synthetic(t, true)
			mutate(&f)
			s, err := inventory.Parse(f.e, f.roles)
			if err == nil || s.Complete || len(s.Certificates) != 0 || s.ActiveTrustpoint != "" {
				t.Fatalf("partial/empty success escaped: complete=%v count=%d err=%v", s.Complete, len(s.Certificates), err)
			}
			if strings.Contains(err.Error(), "CERTIFICATE") {
				t.Fatal("raw output leaked in error")
			}
		})
	}
	// CLI PKI group mismatch is also incomplete, not silently ignored.
	f := synthetic(t, false)
	f.e.Raw[device.ReadPKI] = append(f.e.Raw[device.ReadPKI], []byte("Trustpoint MISSING:\n")...)
	if _, err := inventory.Parse(f.e, nil); err == nil {
		t.Fatal("unobserved Trustpoint accepted")
	}
}

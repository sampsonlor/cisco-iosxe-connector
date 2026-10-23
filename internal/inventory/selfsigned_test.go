package inventory_test

import (
	"encoding/pem"
	"strings"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
)

func selfSignedFixture(t *testing.T) fixture {
	t.Helper()
	f := synthetic(t, false)
	der := certificate(t, 80, true)
	raw := string(f.e.Raw[device.ReadCertificates])
	start := strings.Index(raw, "------Trustpoint: UNMANAGED------")
	end := strings.Index(raw[start+1:], "------Trustpoint:") + start + 1
	block := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	raw = raw[:start] + "------Trustpoint: UNMANAGED------\n% Self-signed CA certificate:\n" + block + "% General Purpose Certificate:\n" + block + raw[end:]
	f.e.Raw[device.ReadCertificates] = []byte(raw)
	return f
}

func TestSelfSignedCAIdentityAlias(t *testing.T) {
	for _, active := range []bool{false, true} {
		t.Run(map[bool]string{false: "inactive", true: "active"}[active], func(t *testing.T) {
			f := selfSignedFixture(t)
			if active {
				f.e.Raw[device.ReadBinding] = []byte("ip http secure-trustpoint UNMANAGED\n")
				f.e.Raw[device.ReadHTTPSStatus] = []byte("HTTP secure server status: Enabled\nHTTP secure server port: 443\nHTTP secure server trustpoint: UNMANAGED\n")
			}
			s, err := inventory.Parse(f.e, nil)
			if err != nil || !s.Complete || len(s.Certificates) != 7 {
				t.Fatalf("self-signed alias: count=%d err=%v", len(s.Certificates), err)
			}
			count := 0
			for _, c := range s.Certificates {
				if c.Trustpoint == "UNMANAGED" {
					count++
					if !c.SelfSignedIdentity {
						t.Fatal("identity purpose was lost")
					}
					want := "INACTIVE"
					if active {
						want = "ACTIVE"
					}
					if c.Role != want {
						t.Fatalf("alias role=%s", c.Role)
					}
				}
			}
			if count != 1 {
				t.Fatal("alias duplicated DER")
			}
		})
	}
}

func TestSelfSignedAliasRequiresExplicitMatchingProof(t *testing.T) {
	f := selfSignedFixture(t)
	raw := string(f.e.Raw[device.ReadCertificates])
	f.e.Raw[device.ReadCertificates] = []byte(strings.Replace(raw, "% Self-signed CA certificate:", "% CA certificate:", 1))
	if s, err := inventory.Parse(f.e, nil); err == nil || s.Complete {
		t.Fatal("general-purpose CA accepted without self-signed alias proof")
	}
}

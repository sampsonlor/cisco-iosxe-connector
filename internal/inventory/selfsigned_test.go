package inventory_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
	"path/filepath"
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

func TestSelfSignedIdentityProviderMetadata(t *testing.T) {
	f := selfSignedFixture(t)
	reader, err := inventory.NewReader(&source{evidence: f.e}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := reader.ReadHTTPS(context.Background(), access())
	if err != nil {
		t.Fatal(err)
	}
	aliases := 0
	for _, c := range s.Certificates {
		for _, b := range c.Bindings {
			if b.SelfSignedIdentity {
				aliases++
			}
		}
	}
	if aliases != 1 {
		t.Fatal("reader lost dual purpose")
	}
	store, err := provider.OpenEntityStore(filepath.Join(t.TempDir(), "entities.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	h, err := provider.NewReadOnlyHandler(store, provider.ReadOnlyConfig{Devices: map[string]provider.ManagedDevice{"router-a": access().Device}}, reader)
	if err != nil {
		t.Fatal(err)
	}
	w := serve(h, "POST", "/v1/entityProvider/entities", `{"name":"synthetic.example.test","kind":"iosxe","attributes":[`+attr("0101", "deviceId", "router-a")+`,`+attr("0102", "targetAddress", "192.0.2.10")+`]}`)
	// Extract the generated entity without depending on its random UUID.
	var entity struct{ Uuid string }
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &entity) != nil {
		t.Fatal("entity creation failed")
	}
	w = serve(h, "POST", "/v1/entityProvider/entities/"+entity.Uuid+"/locations", `{"locationAttributes":[`+attr("0103", "service", "https")+`]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "trustpointPurposes") || !strings.Contains(w.Body.String(), "UNMANAGED=CA_AND_IDENTITY") {
		t.Fatalf("dual purpose mapping: %d %s", w.Code, w.Body)
	}
}

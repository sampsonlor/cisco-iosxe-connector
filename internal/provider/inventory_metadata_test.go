package provider_test

import (
	"path/filepath"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

func TestInventoryMetadataFailsClosed(t *testing.T) {
	der := publicDER(t, 1)
	r := &readInventory{}
	h, _ := openRO(t, filepath.Join(t.TempDir(), "entities.sqlite"), roConfig(), r)
	id := createRO(t, h)
	for _, tc := range []struct {
		name     string
		bindings []provider.TrustpointBinding
		withKey  bool
	}{
		{"duplicate ownership", []provider.TrustpointBinding{{Trustpoint: "HTTPS-ACTIVE", Role: "ACTIVE"}, {Trustpoint: "HTTPS-ACTIVE", Role: "INACTIVE"}}, false},
		{"invalid name", []provider.TrustpointBinding{{Trustpoint: "bad;command", Role: "ACTIVE"}}, false},
		{"unknown role", []provider.TrustpointBinding{{Trustpoint: "HTTPS-ACTIVE", Role: "UNKNOWN-ROLE"}}, false},
		{"leaf as CA", []provider.TrustpointBinding{{Trustpoint: "HTTPS-ACTIVE", Role: "CA"}}, false},
		{"unimplemented key proof", []provider.TrustpointBinding{{Trustpoint: "HTTPS-ACTIVE", Role: "ACTIVE"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r.result = provider.InventorySnapshot{Complete: true, Certificates: []provider.PublicCertificate{{DER: der, Bindings: tc.bindings, WithKey: tc.withKey}}}
			w := request(h, "POST", "/v1/entityProvider/entities/"+id+"/locations", `{"locationAttributes":`+locationAttrs()+`}`)
			if w.Code != 502 {
				t.Fatalf("invalid metadata accepted: %d", w.Code)
			}
		})
	}
}

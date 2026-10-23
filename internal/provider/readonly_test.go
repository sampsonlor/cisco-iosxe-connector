package provider_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

func roConfig() provider.ReadOnlyConfig {
	cfg := provider.ReadOnlyConfig{Devices: map[string]provider.ManagedDevice{}}
	for id, p := range policy().Devices {
		cfg.Devices[id] = provider.ManagedDevice{Policy: p, CredentialRef: "secret://devices/" + id, HostKeyRef: "hostkey://devices/" + id}
	}
	return cfg
}
func openRO(t *testing.T, path string, cfg provider.ReadOnlyConfig, r provider.InventoryReader) (http.Handler, *provider.EntityStore) {
	t.Helper()
	s, err := provider.OpenEntityStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	h, err := provider.NewReadOnlyHandler(s, cfg, r)
	if err != nil {
		t.Fatal(err)
	}
	return h, s
}
func createRO(t *testing.T, h http.Handler) string {
	t.Helper()
	w := request(h, "POST", "/v1/entityProvider/entities", entityBody("router-a", "192.0.2.10"))
	if w.Code != 200 {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var dto struct {
		Uuid string `json:"uuid"`
	}
	if json.Unmarshal(w.Body.Bytes(), &dto) != nil || dto.Uuid == "" {
		t.Fatalf("missing ID: %s", w.Body)
	}
	return dto.Uuid
}

func TestEntityPersistenceAndIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entities.sqlite")
	h, s := openRO(t, path, roConfig(), nil)
	id := createRO(t, h)
	loc := provider.HTTPSLocationID(id)
	if loc == "" || loc == id {
		t.Fatal("missing stable service identity")
	}
	if w := request(h, "PUT", "/v1/entityProvider/entities/"+id, strings.Replace(entityBody("router-a", "192.0.2.10"), "router.example.test", "renamed.example.test", 1)); w.Code != 200 {
		t.Fatalf("update: %d %s", w.Code, w.Body)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	h, _ = openRO(t, path, roConfig(), nil)
	w := request(h, "GET", "/v1/entityProvider/entities/"+id, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "renamed.example.test") || strings.Contains(w.Body.String(), "secret://") {
		t.Fatalf("restart: %d %s", w.Code, w.Body)
	}
	if provider.HTTPSLocationID(id) != loc {
		t.Fatal("Location changed after restart")
	}
	if w := request(h, "POST", "/v1/entityProvider/entities", entityBody("router-a", "192.0.2.10")); w.Code != 409 {
		t.Fatalf("duplicate entity allowed: %d", w.Code)
	}
	if w := request(h, "PUT", "/v1/entityProvider/entities/"+id, entityBody("router-b", "192.0.2.11")); w.Code != 422 {
		t.Fatalf("rebind allowed: %d", w.Code)
	}
	if w := request(h, "DELETE", "/v1/entityProvider/entities/"+id, ""); w.Code != 204 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if w := request(h, "GET", "/v1/entityProvider/entities/"+id, ""); w.Code != 404 {
		t.Fatalf("deleted entity: %d", w.Code)
	}
	w = request(h, "GET", "/v1/entityProvider/entities", "")
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("list: %d %s", w.Code, w.Body)
	}
}

type readInventory struct {
	calls  atomic.Int32
	result provider.InventorySnapshot
	err    error
	seen   provider.DeviceAccess
}

func (r *readInventory) ReadHTTPS(ctx context.Context, a provider.DeviceAccess) (provider.InventorySnapshot, error) {
	r.calls.Add(1)
	r.seen = a
	if ctx.Err() != nil {
		return provider.InventorySnapshot{}, ctx.Err()
	}
	return r.result, r.err
}
func publicDER(t *testing.T, serial int64) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "router.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
func TestReadOnlyLocationAndCapabilities(t *testing.T) {
	r := &readInventory{result: provider.InventorySnapshot{Complete: true, Certificates: []provider.PublicCertificate{{DER: publicDER(t, 1), WithKey: true}, {DER: publicDER(t, 2)}}}}
	h, _ := openRO(t, filepath.Join(t.TempDir(), "entities.sqlite"), roConfig(), r)
	id := createRO(t, h)
	loc := provider.HTTPSLocationID(id)
	b := "/v1/entityProvider/entities/" + id
	w := request(h, "POST", b+"/locations", `{"locationAttributes":`+locationAttrs()+`}`)
	var dto struct {
		MultipleEntries      bool `json:"multipleEntries"`
		SupportKeyManagement bool `json:"supportKeyManagement"`
		Certificates         []struct {
			CertificateType string `json:"certificateType"`
			WithKey         bool   `json:"withKey"`
			PushAttributes  []any  `json:"pushAttributes"`
			CsrAttributes   []any  `json:"csrAttributes"`
		} `json:"certificates"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &dto) != nil || !dto.MultipleEntries || dto.SupportKeyManagement || len(dto.Certificates) != 2 || !dto.Certificates[0].WithKey {
		t.Fatalf("location: %d %s", w.Code, w.Body)
	}
	for _, c := range dto.Certificates {
		if c.CertificateType != "X.509" || len(c.PushAttributes) != 0 || len(c.CsrAttributes) != 0 {
			t.Fatalf("write capabilities/default enum leaked: %s", w.Body)
		}
	}
	if r.seen.DeviceID != "router-a" || r.seen.Device.Policy.Target.String() != "192.0.2.10" || r.seen.Device.CredentialRef != "secret://devices/router-a" {
		t.Fatalf("wrong read binding: %+v", r.seen)
	}
	// Rotating public inventory must not change the service identity/attributes.
	r.result.Certificates = []provider.PublicCertificate{{DER: publicDER(t, 3), WithKey: true}}
	w = request(h, "POST", b+"/locations", `{"locationAttributes":`+locationAttrs()+`}`)
	if w.Code != 200 || provider.HTTPSLocationID(id) != loc {
		t.Fatalf("service changed: %d", w.Code)
	}
	for _, tc := range []struct{ path, body string }{{b + "/locations/csr", csrBody("HTTPS-STAGE-A")}, {b + "/locations/push", pushBody()}, {b + "/locations/remove", `{}`}, {b + "/locations/csr/attributes/validate", csrAttrs("HTTPS-STAGE-A")}, {b + "/locations/push/attributes/validate", pushAttrs()}} {
		w = request(h, "POST", tc.path, tc.body)
		if w.Code != 501 {
			t.Errorf("write entry enabled: %s %d %s", tc.path, w.Code, w.Body)
		}
	}
	if r.calls.Load() != 2 {
		t.Fatalf("mutating routes called reader: %d", r.calls.Load())
	}
	w = request(h, "GET", "/v1", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "/locations/csr") || strings.Contains(w.Body.String(), "/locations/push") || strings.Contains(w.Body.String(), "/locations/remove") {
		t.Fatalf("unsupported write advertised: %s", w.Body)
	}
}

func TestReadOnlyInventoryFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		r      provider.InventoryReader
		status int
	}{
		{"no adapter", nil, 503},
		{"incomplete", &readInventory{}, 502},
		{"read error", &readInventory{err: errors.New("private transcript")}, 502},
		{"timeout", &readInventory{err: context.DeadlineExceeded}, 504},
		{"bad DER", &readInventory{result: provider.InventorySnapshot{Complete: true, Certificates: []provider.PublicCertificate{{DER: []byte("not a certificate")}}}}, 502},
		{"confirmed empty", &readInventory{result: provider.InventorySnapshot{Complete: true}}, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := openRO(t, filepath.Join(t.TempDir(), "entities.sqlite"), roConfig(), tc.r)
			id := createRO(t, h)
			w := request(h, "POST", "/v1/entityProvider/entities/"+id+"/locations", `{"locationAttributes":`+locationAttrs()+`}`)
			if w.Code != tc.status || strings.Contains(w.Body.String(), "private transcript") {
				t.Fatalf("bad observation accepted/leaked: %d %s", w.Code, w.Body)
			}
		})
	}
}

func TestReadOnlyAttributeDefinitions(t *testing.T) {
	h, _ := openRO(t, filepath.Join(t.TempDir(), "entities.sqlite"), roConfig(), nil)
	id := createRO(t, h)
	for _, tc := range []struct {
		path  string
		count int
	}{{"/v1/entityProvider/iosxe/attributes", 2}, {"/v1/entityProvider/entities/" + id + "/location/attributes", 1}, {"/v1/entityProvider/entities/" + id, 2}} {
		w := request(h, "GET", tc.path, "")
		var raw any
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &raw) != nil {
			t.Fatalf("attributes: %d %s", w.Code, w.Body)
		}
		var attrs []any
		if m, ok := raw.(map[string]any); ok {
			attrs = m["attributes"].([]any)
		} else {
			attrs = raw.([]any)
		}
		if len(attrs) != tc.count {
			t.Fatalf("missing definitions: %s", w.Body)
		}
		for _, a := range attrs {
			m := a.(map[string]any)
			props := m["properties"].(map[string]any)
			if m["schemaVersion"] != "v3" || m["version"] != float64(1) || m["type"] != "data" || m["contentType"] != "string" || props["required"] != true {
				t.Fatalf("wrong v3 definition: %v", m)
			}
		}
	}
	if w := request(h, "POST", "/v1/entityProvider/entities/"+id+"/location/attributes/validate", locationAttrs()); w.Code != 204 {
		t.Fatalf("validator: %d %s", w.Code, w.Body)
	}
}

func TestEntityStoreConcurrencyAndFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entities.sqlite")
	h, s := openRO(t, path, roConfig(), nil)
	h2, _ := openRO(t, path, roConfig(), nil)
	var wg sync.WaitGroup
	var created atomic.Int32
	for i := 0; i < 12; i++ {
		target := h
		if i%2 == 0 {
			target = h2
		}
		wg.Go(func() {
			w := request(target, "POST", "/v1/entityProvider/entities", entityBody("router-a", "192.0.2.10"))
			if w.Code == 200 {
				created.Add(1)
			} else if w.Code != 409 {
				t.Errorf("unexpected concurrent status: %d %s", w.Code, w.Body)
			}
		})
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatalf("duplicate persistent bindings: %d", created.Load())
	}
	_ = s.Close()
	if w := request(h, "GET", "/v1/entityProvider/entities", ""); w.Code != 500 {
		t.Fatalf("closed DB reported healthy: %d %s", w.Code, w.Body)
	}
	bad := filepath.Join(t.TempDir(), "corrupt.sqlite")
	if err := os.WriteFile(bad, []byte("corrupt database"), 0600); err != nil {
		t.Fatal(err)
	}
	if db, err := provider.OpenEntityStore(bad); err == nil {
		_ = db.Close()
		t.Fatal("corrupt DB silently replaced")
	}
}

func TestReadOnlyConfigurationAndDrift(t *testing.T) {
	cfg := roConfig()
	encoded, _ := json.Marshal(cfg)
	parsed, err := provider.LoadReadOnlyConfig(strings.NewReader(string(encoded)))
	if err != nil || len(parsed.Devices) != 2 {
		t.Fatalf("valid config: %v", err)
	}
	for _, raw := range []string{string(encoded) + "{}", strings.TrimSuffix(string(encoded), "}") + `,"password":"inline"}`, strings.Replace(string(encoded), "secret://devices/router-a", "inline-password", 1), strings.Replace(string(encoded), `"credentialRef"`, `"CredentialRef"`, 1)} {
		if _, err := provider.LoadReadOnlyConfig(strings.NewReader(raw)); err == nil {
			t.Error("unsafe config accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "entities.sqlite")
	h, s := openRO(t, path, cfg, nil)
	id := createRO(t, h)
	d := cfg.Devices["router-a"]
	d.Policy = cfg.Devices["router-b"].Policy
	delete(cfg.Devices, "router-b")
	cfg.Devices["router-a"] = d
	if _, err := provider.NewReadOnlyHandler(s, cfg, nil); err == nil {
		t.Fatal("stored binding silently retargeted")
	}
	// Metadata deletion and restart do not perform device cleanup.
	if provider.HTTPSLocationID(id) == provider.HTTPSLocationID(otherID) {
		t.Fatal("service IDs collide")
	}
}

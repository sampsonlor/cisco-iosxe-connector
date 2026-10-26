package lifecycle_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/nativeflow"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

type nativeCSRDevice struct {
	material csr.Result
	calls    atomic.Int32
	lost     bool
}

func (d *nativeCSRDevice) Generate(context.Context, csr.Request) (csr.Result, error) {
	d.calls.Add(1)
	if d.lost {
		return csr.Result{}, errors.New("synthetic lost CSR reply")
	}
	return d.material, nil
}
func (d *nativeCSRDevice) Inspect(context.Context, csr.Request) error { return nil }

type nativeInventory struct{}

func (nativeInventory) ReadHTTPS(context.Context, provider.DeviceAccess) (provider.InventorySnapshot, error) {
	return provider.InventorySnapshot{Complete: true}, nil
}

type nativeFixture struct {
	f       *stageFixture
	device  *nativeCSRDevice
	engine  *nativeflow.Engine
	es      *provider.EntityStore
	cfg     provider.ReadOnlyConfig
	h       http.Handler
	target  provider.NativeTarget
	service nativeflow.Service
}

func nativeHTTP(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func nativeAttr(id, name, value string) string {
	v, _ := json.Marshal(value)
	return `{"uuid":"` + id + `","name":"` + name + `","contentType":"string","version":"v3","content":[{"contentType":"string","data":` + string(v) + `}]}`
}
func newNativeFixture(t *testing.T) *nativeFixture {
	t.Helper()
	f := newStageFixture(t)
	stageMust(t, f.s.Close())
	n := &nativeFixture{f: f, device: &nativeCSRDevice{material: f.material}}
	n.cfg = provider.ReadOnlyConfig{Devices: map[string]provider.ManagedDevice{"router-a": {Policy: provider.DevicePolicy{Target: netip.MustParseAddr("192.0.2.10"), ActiveTrustpoint: "HTTPS-LIVE", StagingTrustpoints: []string{"HTTPS-STAGE-A"}}, CredentialRef: "secret://devices/a", HostKeyRef: "hostkey://devices/a"}}}
	var err error
	n.es, err = provider.OpenEntityStore(filepath.Join(t.TempDir(), "entities.sqlite"))
	stageMust(t, err)
	t.Cleanup(func() { n.es.Close() })
	ro, err := provider.NewReadOnlyHandler(n.es, n.cfg, nativeInventory{})
	stageMust(t, err)
	w := nativeHTTP(ro, "POST", "/v1/entityProvider/entities", `{"name":"router.example.test","kind":"iosxe","attributes":[`+nativeAttr(provider.DeviceIDAttribute, "deviceId", "router-a")+`,`+nativeAttr(provider.TargetAddressAttribute, "targetAddress", "192.0.2.10")+`]}`)
	var e struct {
		ID string `json:"uuid"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &e) != nil || e.ID == "" {
		t.Fatalf("entity bootstrap: %d %s", w.Code, w.Body)
	}
	b := f.services[0].Binding
	b.EntityID = e.ID
	b.LocationID = provider.HTTPSLocationID(e.ID)
	f.services = []journal.Service{{Binding: b, StagingTrustpoints: []string{"HTTPS-STAGE-A"}}}
	f.path = filepath.Join(t.TempDir(), "native.sqlite")
	f.s, err = journal.Open(f.path, f.services)
	stageMust(t, err)
	c := f.r.Correlation
	c.Binding = b
	n.service = nativeflow.Service{Correlation: c, Spec: f.spec}
	n.target = provider.NativeTarget{EntityID: e.ID, LocationID: b.LocationID, DeviceID: b.DeviceID, Target: b.Target}
	n.rewire(t)
	return n
}
func (n *nativeFixture) rewire(t *testing.T) {
	n.f.rewire(t)
	cg, err := lifecycle.NewCSRGate(n.f.s, n.device)
	stageMust(t, err)
	cert, err := lifecycle.NewCertificateGate(n.f.s, n.f.v)
	stageMust(t, err)
	n.engine, err = nativeflow.New(n.f.s, cg, cert, n.f.gate, []nativeflow.Service{n.service})
	stageMust(t, err)
	n.h, err = provider.NewNativeHandler(n.es, n.cfg, nativeInventory{}, n.engine, func(*http.Request) error { return nil })
	stageMust(t, err)
}
func TestNativeCSRPushSQLiteStageIntegration(t *testing.T) {
	n := newNativeFixture(t)
	ctx := context.Background()
	p := "/v1/entityProvider/entities/" + n.target.EntityID + "/locations/"
	attrs := `[` + nativeAttr(provider.ServiceAttribute, "service", "https") + `]`
	body := `{"locationAttributes":` + attrs + `,"csrAttributes":[` + nativeAttr(provider.StagingTrustpointAttribute, "stagingTrustpoint", "HTTPS-STAGE-A") + `],"renewal":true}`
	w := nativeHTTP(n.h, "POST", p+"csr", body)
	var response struct {
		CSR  string          `json:"csr"`
		Push json.RawMessage `json:"pushAttributes"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &response) != nil || response.CSR != base64.StdEncoding.EncodeToString(n.f.material.DER) {
		t.Fatalf("CSR: %d %s", w.Code, w.Body)
	}
	for i := 0; i < 2; i++ {
		if w = nativeHTTP(n.h, "POST", p+"csr", body); w.Code != 200 {
			t.Fatalf("CSR retry: %d %s", w.Code, w.Body)
		}
	}
	if n.device.calls.Load() != 1 {
		t.Fatal("CSR regenerated")
	}
	stageMust(t, n.f.s.Close())
	var err error
	n.f.s, err = journal.Open(n.f.path, n.f.services)
	stageMust(t, err)
	n.rewire(t)
	push := `{"certificate":"` + base64.StdEncoding.EncodeToString(n.f.leaf) + `","certificateType":"X.509","locationAttributes":` + attrs + `,"pushAttributes":` + string(response.Push) + `}`
	if w = nativeHTTP(n.h, "POST", p+"push", push); w.Code != 200 || !strings.Contains(w.Body.String(), `"withKey":true`) || !strings.Contains(w.Body.String(), "STAGED") {
		t.Fatalf("leaf-only push: %d %s", w.Code, w.Body)
	}
	if n.f.backend.imports != 1 || !bytes.Equal(n.f.backend.obs.ActiveDER, n.f.baseline) {
		t.Fatal("staging changed live HTTPS or skipped import")
	}
	if w = nativeHTTP(n.h, "POST", p+"push", push); w.Code != 200 || n.f.backend.imports != 1 {
		t.Fatalf("duplicate push: %d %s", w.Code, w.Body)
	}
	n.f.backend.obs.PublicKeyDER = nil
	if w = nativeHTTP(n.h, "POST", p+"push", push); w.Code == 200 || strings.Contains(w.Body.String(), `"withKey":true`) || n.f.backend.imports != 1 {
		t.Fatal("cached state fabricated key evidence")
	}
	if _, err = n.engine.CSR(ctx, n.target, "HTTPS-STAGE-A", true); err == nil {
		t.Fatal("staged operation allowed another issuance")
	}
}
func TestNativeOwnershipCorrelationAndUnknownCSR(t *testing.T) {
	n := newNativeFixture(t)
	ctx := context.Background()
	bad := n.target
	bad.EntityID = uuid.NewString()
	if _, err := n.engine.CSR(ctx, bad, "HTTPS-STAGE-A", true); err == nil || n.device.calls.Load() != 0 {
		t.Fatal("cross entity CSR")
	}
	n.device.lost = true
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() { _, _ = n.engine.CSR(ctx, n.target, "HTTPS-STAGE-A", true) })
	}
	wg.Wait()
	if n.device.calls.Load() != 1 {
		t.Fatal("concurrent unknown result regenerated key")
	}
	stageMust(t, n.f.s.Close())
	var err error
	n.f.s, err = journal.Open(n.f.path, n.f.services)
	stageMust(t, err)
	n.rewire(t)
	if _, err = n.engine.CSR(ctx, n.target, "HTTPS-STAGE-A", true); err == nil || n.device.calls.Load() != 1 {
		t.Fatal("restart replayed unknown CSR")
	}
	if _, err = n.engine.CSR(ctx, n.target, "HTTPS-STAGE-A", false); err == nil {
		t.Fatal("renewal flag changed operation identity")
	}
	if _, err = n.engine.Push(ctx, n.target, uuid.NewString(), n.f.leaf); err == nil || n.f.backend.imports != 0 {
		t.Fatal("unknown push ID")
	}
	c := n.service.Correlation
	c.Owner = journal.ACMEWorker
	worker, err := nativeflow.New(n.f.s, nil, nil, nil, []nativeflow.Service{{Correlation: c, Spec: n.service.Spec}})
	if err == nil && worker.Enabled(ctx, n.target) == nil {
		t.Fatal("ACME owner accepted native lifecycle")
	}
}

package provider_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
	entity "github.com/OmniTrustILM/go-sdk/connector/provider/entity/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

const (
	entityID    = "11111111-2222-4333-8444-555555555555"
	otherID     = "11111111-2222-4333-8444-666666666666"
	base        = "/v1/entityProvider/entities/" + entityID
	operationID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
)

func policy() provider.Config {
	return provider.Config{
		Devices: map[string]provider.DevicePolicy{
			"router-a": {Target: netip.MustParseAddr("192.0.2.10"), ActiveTrustpoint: "HTTPS-ACTIVE", StagingTrustpoints: []string{"HTTPS-STAGE-A"}},
			"router-b": {Target: netip.MustParseAddr("192.0.2.11"), ActiveTrustpoint: "HTTPS-ACTIVE", StagingTrustpoints: []string{"HTTPS-STAGE-B"}},
		},
		ResolveEntity: func(_ context.Context, id string) (string, error) {
			if id == entityID {
				return "router-a", nil
			}
			if id == otherID {
				return "router-b", nil
			}
			return "", nil
		},
	}
}

func attr(id, name, value string) string {
	b, _ := json.Marshal(value)
	return `{"uuid":"` + id + `","name":"` + name + `","contentType":"string","version":"v3","content":[{"contentType":"string","data":` + string(b) + `}]}`
}
func entityAttrs(device, target string) string {
	return `[` + attr(provider.DeviceIDAttribute, "deviceId", device) + `,` + attr(provider.TargetAddressAttribute, "targetAddress", target) + `]`
}
func locationAttrs() string { return `[` + attr(provider.ServiceAttribute, "service", "https") + `]` }
func csrAttrs(value string) string {
	return `[` + attr(provider.StagingTrustpointAttribute, "stagingTrustpoint", value) + `]`
}
func pushAttrs() string {
	return `[` + attr(provider.OperationIDAttribute, "operationId", operationID) + `]`
}
func entityBody(device, target string) string {
	return `{"name":"router.example.test","kind":"iosxe","attributes":` + entityAttrs(device, target) + `}`
}
func csrBody(value string) string {
	return `{"locationAttributes":` + locationAttrs() + `,"csrAttributes":` + csrAttrs(value) + `,"renewal":true}`
}
func pushBody() string {
	return `{"certificate":"c3ludGhldGlj","locationAttributes":` + locationAttrs() + `,"pushAttributes":` + pushAttrs() + `}`
}

func sdkHarness(t *testing.T) (http.Handler, *backend) {
	t.Helper()
	p := &backend{}
	h, err := entity.NewHandler(p, entity.Base(handlerbase.WithStrictDecode(true)), entity.WithKinds("iosxe"), entity.WithLocationAttributes(p))
	if err != nil {
		t.Fatal(err)
	}
	c, err := shared.New(
		shared.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		shared.WithInfoVersion(shared.VersionV1), shared.WithHealthVersion(shared.VersionV1),
		shared.WithErrorRenderer(shared.WriteV1Error),
		shared.WithInfo(shared.Info{ID: "boundary-test", Name: "Offline boundary", Version: "0.0.0"}), shared.Register(h),
	)
	if err != nil {
		t.Fatal(err)
	}
	return c.Handler(), p
}
func harness(t *testing.T, cfg provider.Config) (http.Handler, *backend) {
	t.Helper()
	sdk, p := sdkHarness(t)
	h, err := provider.NewBoundary(sdk, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return h, p
}
func request(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestBoundaryV1Contract(t *testing.T) {
	h, _ := harness(t, policy())
	for _, tc := range []struct{ path, body string }{
		{base + "/location/attributes/validate", locationAttrs()},
		{base + "/locations/csr/attributes/validate", csrAttrs("HTTPS-STAGE-A")},
		{base + "/locations/push/attributes/validate", pushAttrs()},
	} {
		t.Run(tc.path, func(t *testing.T) {
			w := request(h, "POST", tc.path, tc.body)
			if w.Code != 204 || w.Body.Len() != 0 || w.Header().Get("Content-Length") != "" {
				t.Fatalf("want target 204 without body, got %d %s", w.Code, w.Body)
			}
		})
	}
	if w := request(h, "POST", "/v1/entityProvider/iosxe/attributes/validate", entityAttrs("router-a", "192.0.2.10")); w.Code != 200 {
		t.Fatalf("kind validator changed: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/v1", "/v1/health"} {
		w := request(h, "GET", path, "")
		if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body)
		}
		if path == "/v1" {
			var groups []shared.V1FunctionGroup
			if json.Unmarshal(w.Body.Bytes(), &groups) != nil || len(groups) != 1 || groups[0].FunctionGroupCode != "entityProvider" {
				t.Fatalf("not v1 info: %s", w.Body)
			}
		} else {
			var health map[string]any
			if json.Unmarshal(w.Body.Bytes(), &health) != nil || health["status"] != "ok" || health["components"] != nil {
				t.Fatalf("not v1 health: %s", w.Body)
			}
		}
	}
}

func TestBoundaryAcceptedRequests(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/v1/entityProvider/entities", entityBody("router-a", "192.0.2.10"), 200},
		{"PUT", base, entityBody("router-a", "192.0.2.10"), 200},
		{"GET", base, "", 200},
		{"POST", base + "/locations", `{"locationAttributes":` + locationAttrs() + `}`, 200},
		{"POST", base + "/locations/csr", csrBody("HTTPS-STAGE-A"), 200},
		{"POST", base + "/locations/push", pushBody(), 200},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			h, p := harness(t, policy())
			w := request(h, tc.method, tc.path, tc.body)
			if w.Code != tc.status || p.calls.Load() != 1 {
				t.Fatalf("valid request not forwarded once: %d calls=%d body=%s", w.Code, p.calls.Load(), w.Body)
			}
		})
	}
}

func TestBoundaryAttributes(t *testing.T) {
	valid := csrBody("HTTPS-STAGE-A")
	for _, tc := range []struct{ name, body string }{
		{"unknown top-level field", strings.TrimSuffix(valid, "}") + `,"command":"reload"}`},
		{"case alias", strings.Replace(valid, `"renewal"`, `"Renewal"`, 1)},
		{"missing required", strings.Replace(valid, `,"renewal":true`, "", 1)},
		{"null required", strings.Replace(valid, `"renewal":true`, `"renewal":null`, 1)},
		{"non boolean", strings.Replace(valid, `"renewal":true`, `"renewal":"true"`, 1)},
		{"null list", strings.Replace(valid, locationAttrs(), "null", 1)},
		{"empty list", strings.Replace(valid, locationAttrs(), "[]", 1)},
		{"unknown attribute", strings.Replace(valid, "stagingTrustpoint", "command", 1)},
		{"wrong identity", strings.Replace(valid, provider.StagingTrustpointAttribute, provider.ServiceAttribute, 1)},
		{"v2", strings.Replace(valid, `"v3"`, `"v2"`, 1)},
		{"unsupported subtype", strings.Replace(valid, `"contentType":"string"`, `"contentType":"secret"`, 1)},
		{"unknown attribute property", strings.Replace(valid, `"version":"v3"`, `"version":"v3","extra":true`, 1)},
		{"unknown content property", strings.Replace(valid, `"data":"https"`, `"data":"https","extra":true`, 1)},
		{"reference indirection", strings.Replace(valid, `"data":"https"`, `"data":"https","reference":"other-device"`, 1)},
		{"null content", strings.Replace(valid, `[{"contentType":"string","data":"https"}]`, "null", 1)},
		{"multiple scalar values", strings.Replace(valid, `[{"contentType":"string","data":"https"}]`, `[{"contentType":"string","data":"https"},{"contentType":"string","data":"http"}]`, 1)},
		{"duplicate attribute", strings.Replace(valid, locationAttrs(), `[`+attr(provider.ServiceAttribute, "service", "https")+`,`+attr(provider.ServiceAttribute, "service", "https")+`]`, 1)},
		{"wrong service", strings.Replace(valid, `"data":"https"`, `"data":"http"`, 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, p := harness(t, policy())
			w := request(h, "POST", base+"/locations/csr", tc.body)
			if w.Code != 422 || p.calls.Load() != 0 {
				t.Fatalf("invalid attributes reached backend: %d calls=%d %s", w.Code, p.calls.Load(), w.Body)
			}
			var messages []string
			if json.Unmarshal(w.Body.Bytes(), &messages) != nil || len(messages) == 0 {
				t.Fatalf("not a v1 validation array: %s", w.Body)
			}
		})
	}
}

func TestBoundaryIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
	}{
		{"cross-device update", "PUT", base, entityBody("router-b", "192.0.2.11"), 422},
		{"unapproved target", "POST", "/v1/entityProvider/entities", entityBody("router-a", "192.0.2.99"), 422},
		{"target URL", "POST", "/v1/entityProvider/entities", entityBody("router-a", "https://192.0.2.10/"), 422},
		{"unapproved device", "POST", "/v1/entityProvider/entities", entityBody("router-c", "192.0.2.10"), 422},
		{"other staging pool", "POST", base + "/locations/csr", csrBody("HTTPS-STAGE-B"), 422},
		{"active Trustpoint", "POST", base + "/locations/csr", csrBody("HTTPS-ACTIVE"), 422},
		{"newline injection", "POST", base + "/locations/csr", csrBody("HTTPS-STAGE-A\nreload"), 422},
		{"CLI separator", "POST", base + "/locations/csr", csrBody("HTTPS-STAGE-A;reload"), 422},
		{"entity override", "POST", base + "/locations", `{"locationAttributes":` + entityAttrs("router-b", "192.0.2.11") + `}`, 422},
		{"operation syntax", "POST", base + "/locations/push", strings.Replace(pushBody(), operationID, "../../other", 1), 422},
		{"unknown entity", "GET", "/v1/entityProvider/entities/22222222-2222-4333-8444-555555555555", "", 404},
		{"unimplemented removal", "POST", base + "/locations/remove", `{"certificateMetadata":[],"locationAttributes":` + locationAttrs() + `}`, 501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, p := harness(t, policy())
			w := request(h, tc.method, tc.path, tc.body)
			if w.Code != tc.status || p.calls.Load() != 0 {
				t.Fatalf("scope violation forwarded: %d calls=%d %s", w.Code, p.calls.Load(), w.Body)
			}
		})
	}
}

func TestBoundaryPushPolicy(t *testing.T) {
	// The DTO annotation's default X509 is not the JSON value. Pin the enum's
	// @JsonValue evidence independently of the SDK constant used by production.
	source, err := os.ReadFile(filepath.Join("..", "..", "contracts", "ilm-2.19.0", "java", "CertificateType.java"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), `String X509 = "X.509"`) || !strings.Contains(string(source), "@JsonValue") {
		t.Fatal("review pinned certificate type wire semantics")
	}
	valid := pushBody()
	for _, body := range []string{
		strings.TrimSuffix(valid, "}") + `,"unapprovedField":"synthetic"}`,
		strings.TrimSuffix(valid, "}") + `,"chain":[]}`,
		strings.TrimSuffix(valid, "}") + `,"certificateType":"PKCS12"}`,
		strings.TrimSuffix(valid, "}") + `,"certificateType":"X509"}`,
		strings.TrimSuffix(valid, "}") + `,"certificateType":null}`,
		strings.Replace(valid, `"certificate":"c3ludGhldGlj"`, `"certificate":null`, 1),
		strings.Replace(valid, `"certificate":"c3ludGhldGlj"`, `"certificate":"invalid base64"`, 1),
		strings.Replace(valid, `"certificate":"c3ludGhldGlj"`, `"certificate":"c3ludGhl\ndGlj"`, 1),
		strings.Replace(valid, pushAttrs(), "[]", 1),
	} {
		h, p := harness(t, policy())
		w := request(h, "POST", base+"/locations/push", body)
		if w.Code != 422 || p.calls.Load() != 0 {
			t.Errorf("invalid push reached backend: %d calls=%d %s", w.Code, p.calls.Load(), w.Body)
		}
	}
	h, p := harness(t, policy())
	w := request(h, "POST", base+"/locations/push", strings.TrimSuffix(valid, "}")+`,"certificateType":"X.509"}`)
	if w.Code != 200 || p.calls.Load() != 1 {
		t.Fatalf("X.509 wire value rejected: %d %s", w.Code, w.Body)
	}
}

func TestBoundaryJSON(t *testing.T) {
	valid := csrBody("HTTPS-STAGE-A")
	for _, body := range []string{
		"", "{", valid + "{}", strings.Replace(valid, `"renewal":true`, `"renewal":false,"renewal":true`, 1),
		strings.Replace(valid, `"data":"https"`, `"data":"http","data":"https"`, 1),
		strings.Replace(valid, `"renewal":true`, `"renewal":false,"\u0072enewal":true`, 1),
		strings.Repeat("[", 64) + "0" + strings.Repeat("]", 64),
		"{\"bad\":\"" + string([]byte{0xff}) + "\"}",
	} {
		h, p := harness(t, policy())
		w := request(h, "POST", base+"/locations/csr", body)
		if w.Code != 400 || p.calls.Load() != 0 {
			t.Errorf("ambiguous/malformed JSON accepted: %d calls=%d", w.Code, p.calls.Load())
		}
	}
	cfg := policy()
	cfg.MaxBodyBytes = 128
	h, p := harness(t, cfg)
	w := request(h, "POST", base+"/locations/csr", valid)
	if w.Code != 413 || p.calls.Load() != 0 {
		t.Fatalf("size limit ignored: %d calls=%d", w.Code, p.calls.Load())
	}
}

func TestBoundaryHTTP(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", base + "/../" + otherID, "", 400},
		{"GET", strings.Replace(base, "entities/", "entities//", 1), "", 400},
		{"GET", strings.Replace(base, "1111", "%31%31%31%31", 1), "", 400},
		{"GET", base + "?targetAddress=192.0.2.11", "", 400},
		{"GET", "/v2/health", "", 404},
		{"GET", base + "/unknown", "", 404},
		{"GET", "/v1/entityProvider/entities/not-a-uuid", "", 400},
		{"PATCH", base, "{}", 405},
		{"GET", base, "{}", 400},
	} {
		h, p := harness(t, policy())
		w := request(h, tc.method, tc.path, tc.body)
		var envelope map[string]any
		if w.Code != tc.status || p.calls.Load() != 0 || json.Unmarshal(w.Body.Bytes(), &envelope) != nil || len(envelope) != 1 || envelope["message"] == nil {
			t.Errorf("%s %s: want v1 %d, got %d calls=%d %s", tc.method, tc.path, tc.status, w.Code, p.calls.Load(), w.Body)
		}
	}
	h, p := harness(t, policy())
	r := httptest.NewRequest("POST", base+"/locations/csr", strings.NewReader(csrBody("HTTPS-STAGE-A")))
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 415 || p.calls.Load() != 0 {
		t.Fatalf("media type accepted: %d", w.Code)
	}
}

func TestBoundaryPolicy(t *testing.T) {
	sdk, _ := sdkHarness(t)
	for _, mutate := range []func(*provider.Config){
		func(c *provider.Config) { c.Devices = nil },
		func(c *provider.Config) { c.ResolveEntity = nil },
		func(c *provider.Config) { c.MaxBodyBytes = -1 },
		func(c *provider.Config) { c.MaxBodyBytes = 4<<20 + 1 },
		func(c *provider.Config) {
			p := c.Devices["router-a"]
			p.Target = netip.Addr{}
			c.Devices["router-a"] = p
		},
		func(c *provider.Config) {
			p := c.Devices["router-a"]
			p.Target = netip.MustParseAddr("127.0.0.1")
			c.Devices["router-a"] = p
		},
		func(c *provider.Config) {
			p := c.Devices["router-a"]
			p.Target = c.Devices["router-b"].Target
			c.Devices["router-a"] = p
		},
		func(c *provider.Config) {
			p := c.Devices["router-a"]
			p.StagingTrustpoints = []string{p.ActiveTrustpoint}
			c.Devices["router-a"] = p
		},
		func(c *provider.Config) {
			p := c.Devices["router-a"]
			p.StagingTrustpoints = []string{"unsafe\nreload"}
			c.Devices["router-a"] = p
		},
		func(c *provider.Config) {
			p := c.Devices["router-a"]
			p.Target = netip.MustParseAddr("fe80::1%eth0")
			c.Devices["router-a"] = p
		},
		func(c *provider.Config) {
			p := c.Devices["router-a"]
			p.Target = netip.MustParseAddr("::ffff:192.0.2.10")
			c.Devices["router-a"] = p
		},
		func(c *provider.Config) {
			p := c.Devices["router-a"]
			p.StagingTrustpoints = []string{"HTTPS-STAGE-A", "https-stage-a"}
			c.Devices["router-a"] = p
		},
		func(c *provider.Config) { c.Devices["unsafe;id"] = c.Devices["router-a"] },
	} {
		cfg := policy()
		mutate(&cfg)
		if _, err := provider.NewBoundary(sdk, cfg); err == nil {
			t.Error("unsafe operator policy accepted")
		}
	}
	if _, err := provider.NewBoundary(nil, policy()); err == nil {
		t.Error("nil handler accepted")
	}
	cfg := policy()
	h, p := harness(t, cfg)
	// A caller changing its input after construction cannot expand the policy.
	cfg.Devices["router-a"].StagingTrustpoints[0] = "UNAPPROVED"
	delete(cfg.Devices, "router-a")
	w := request(h, "POST", base+"/locations/csr", csrBody("HTTPS-STAGE-A"))
	if w.Code != 200 || p.calls.Load() != 1 {
		t.Fatalf("policy was not copied: %d %s", w.Code, w.Body)
	}
	cfg = policy()
	cfg.ResolveEntity = func(context.Context, string) (string, error) { return "", errors.New("sensitive resolver details") }
	h, _ = harness(t, cfg)
	w = request(h, "GET", base, "")
	if w.Code != 500 || strings.Contains(w.Body.String(), "sensitive") {
		t.Fatalf("resolver error leaked or ignored: %d %s", w.Code, w.Body)
	}
	cfg.ResolveEntity = func(context.Context, string) (string, error) { return "unapproved-device", nil }
	h, p = harness(t, cfg)
	w = request(h, "GET", base, "")
	if w.Code != 404 || p.calls.Load() != 0 {
		t.Fatalf("unapproved binding accepted: %d", w.Code)
	}
}

func TestBoundaryIPv6AndContext(t *testing.T) {
	cfg := policy()
	dev := cfg.Devices["router-a"]
	dev.Target = netip.MustParseAddr("2001:db8::10")
	cfg.Devices["router-a"] = dev
	h, p := harness(t, cfg)
	w := request(h, "POST", "/v1/entityProvider/entities", entityBody("router-a", "2001:db8::10"))
	if w.Code != 200 || p.calls.Load() != 1 {
		t.Fatalf("approved IPv6 rejected: %d %s", w.Code, w.Body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cfg.ResolveEntity = func(ctx context.Context, _ string) (string, error) { return "", ctx.Err() }
	h, p = harness(t, cfg)
	r := httptest.NewRequest("GET", base, nil).WithContext(ctx)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 500 || p.calls.Load() != 0 {
		t.Fatalf("cancelled resolver was ignored: %d", w.Code)
	}
}

func TestBoundaryBackendErrors(t *testing.T) {
	for _, status := range []int{400, 403, 404, 422, 500} {
		h, p := harness(t, policy())
		p.failure = &shared.Error{Status: status, ErrorCode: "SYNTHETIC", Detail: "synthetic backend failure"}
		w := request(h, "GET", base, "")
		if w.Code != status {
			t.Fatalf("backend status changed: %d", w.Code)
		}
		if status == 422 {
			var messages []string
			if json.Unmarshal(w.Body.Bytes(), &messages) != nil || len(messages) != 1 {
				t.Fatalf("bad v1 validation error: %s", w.Body)
			}
		} else {
			var envelope map[string]any
			if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || envelope["message"] != "synthetic backend failure" {
				t.Fatalf("bad v1 error: %s", w.Body)
			}
			if status == 403 && (envelope["code"] != "SYNTHETIC" || envelope["statusCode"] != float64(403)) {
				t.Fatalf("bad v1 authentication error: %s", w.Body)
			}
			if status != 403 && len(envelope) != 1 {
				t.Fatalf("unexpected v2 error fields: %s", w.Body)
			}
		}
	}
}

func TestValidationStatusAdapter(t *testing.T) {
	path := base + "/location/attributes/validate"
	for _, status := range []int{200, 204, 400, 403, 422, 500} {
		next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", "4")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, "body")
		})
		h, err := provider.NewBoundary(next, policy())
		if err != nil {
			t.Fatal(err)
		}
		w := request(h, "POST", path, locationAttrs())
		want := status
		if status == 200 {
			want = 204
		}
		if w.Code != want {
			t.Errorf("status %d became %d", status, w.Code)
		}
		if want == 204 && (w.Body.Len() != 0 || w.Header().Get("Content-Length") != "") {
			t.Errorf("204 retained body/length: %s", w.Body)
		}
		if want != 204 && w.Body.String() != "body" {
			t.Errorf("error body was changed: %s", w.Body)
		}
	}
	h, p := harness(t, policy())
	p.invalid.Store(true)
	w := request(h, "POST", path, locationAttrs())
	var messages []string
	if w.Code != 422 || json.Unmarshal(w.Body.Bytes(), &messages) != nil || len(messages) != 1 {
		t.Fatalf("SDK validation error was masked: %d %s", w.Code, w.Body)
	}
}

func TestBoundaryConcurrent(t *testing.T) {
	h, p := harness(t, policy())
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Go(func() {
			w := request(h, "POST", base+"/locations/csr", csrBody("HTTPS-STAGE-A"))
			if w.Code != 200 {
				t.Errorf("concurrent request: %d %s", w.Code, w.Body)
			}
		})
	}
	wg.Wait()
	if p.calls.Load() != 32 {
		t.Fatalf("lost/duplicated requests: %d", p.calls.Load())
	}
}

// This backend records calls only. It never issues a certificate or contacts a
// device. Runtime-generated lifecycle semantics are deliberately outside #2.
type backend struct {
	calls   atomic.Int32
	invalid atomic.Bool
	failure error
}

var _ entity.Provider = (*backend)(nil)

func (p *backend) dto() *mdl.EntityInstanceDto {
	p.calls.Add(1)
	return &mdl.EntityInstanceDto{Uuid: entityID, Name: "router.example.test", Attributes: []mdl.BaseAttributeDto{}}
}
func (p *backend) ListEntityInstances(context.Context) ([]mdl.EntityInstanceDto, error) {
	return []mdl.EntityInstanceDto{*p.dto()}, nil
}
func (p *backend) CreateEntityInstance(context.Context, *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error) {
	return p.dto(), nil
}
func (p *backend) GetEntityInstance(context.Context, string) (*mdl.EntityInstanceDto, error) {
	if p.failure != nil {
		p.calls.Add(1)
		return nil, p.failure
	}
	return p.dto(), nil
}
func (p *backend) UpdateEntityInstance(context.Context, string, *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error) {
	return p.dto(), nil
}
func (p *backend) RemoveEntityInstance(context.Context, string) error { p.calls.Add(1); return nil }
func (p *backend) GetLocationDetail(context.Context, string, *mdl.LocationDetailRequestDto) (*mdl.LocationDetailResponseDto, error) {
	p.calls.Add(1)
	return &mdl.LocationDetailResponseDto{Certificates: []mdl.CertificateLocationDto{}}, nil
}
func (p *backend) PushCertificateToLocation(context.Context, string, *mdl.PushCertificateRequestDto) (*mdl.PushCertificateResponseDto, error) {
	p.calls.Add(1)
	return &mdl.PushCertificateResponseDto{}, nil
}
func (p *backend) RemoveCertificateFromLocation(context.Context, string, *mdl.RemoveCertificateRequestDto) (*mdl.RemoveCertificateResponseDto, error) {
	p.calls.Add(1)
	return &mdl.RemoveCertificateResponseDto{}, nil
}
func (p *backend) GenerateCsrLocation(context.Context, string, *mdl.GenerateCsrRequestDto) (*mdl.GenerateCsrResponseDto, error) {
	p.calls.Add(1)
	return &mdl.GenerateCsrResponseDto{Csr: "c3ludGhldGlj", PushAttributes: []mdl.RequestAttribute{}}, nil
}
func (p *backend) LocationAttributes(context.Context, string) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{}, nil
}
func (p *backend) ValidateLocationAttributes(context.Context, string, []mdl.RequestAttribute) ([]string, error) {
	if p.invalid.Load() {
		return []string{"synthetic policy failure"}, nil
	}
	return nil, nil
}

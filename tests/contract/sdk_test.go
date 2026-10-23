// This package characterizes upstream SDK behavior. Its provider is a test
// double, not the IOS XE connector, and performs no external IO or issuance.
package contract_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
	entity "github.com/OmniTrustILM/go-sdk/connector/provider/entity/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const entityID = "11111111-2222-4333-8444-555555555555"
const base = "/v1/entityProvider/entities/" + entityID

type route struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
}

type observation struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	TargetStatus int    `json:"targetStatus"`
	SDKStatus    int    `json:"sdkStatus"`
}

func readJSON(t *testing.T, name string, dst any) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "contracts", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		t.Fatal(err)
	}
}

func routes(t *testing.T) []route {
	t.Helper()
	var manifest struct {
		Routes []route `json:"routes"`
	}
	readJSON(t, "ilm-2.19.0/routes.json", &manifest)
	return manifest.Routes
}

func observations(t *testing.T) []observation {
	t.Helper()
	var manifest struct {
		Differences []observation `json:"differences"`
		Accepted    bool          `json:"strictCompatibilityAccepted"`
	}
	readJSON(t, "sdk-v1.1.0-observations.json", &manifest)
	if manifest.Accepted {
		t.Fatal("SDK characterization must not be marked strict connector compatibility")
	}
	return manifest.Differences
}

func newHarness(t *testing.T) (http.Handler, *fixtureProvider) {
	t.Helper()
	p := &fixtureProvider{}
	h, err := entity.NewHandler(p,
		entity.Base(handlerbase.WithStrictDecode(true)),
		entity.WithKinds("iosxe"),
	)
	if err != nil {
		t.Fatal(err)
	}
	c, err := shared.New(
		shared.WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
		shared.WithInfoVersion(shared.VersionV1),
		shared.WithHealthVersion(shared.VersionV1),
		shared.WithErrorRenderer(shared.WriteV1Error),
		shared.WithInfo(shared.Info{ID: "test-harness", Name: "SDK test harness", Version: "0.0.0"}),
		shared.Register(h),
		shared.WithExtraEndpoints(
			shared.ExtraEndpoint{FunctionGroupCode: entity.FunctionGroupCode, Method: http.MethodGet, Context: "/v1", Name: "listSupportedFunctions"},
			shared.ExtraEndpoint{FunctionGroupCode: entity.FunctionGroupCode, Method: http.MethodGet, Context: "/v1/health", Name: "checkHealth"},
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	return c.Handler(), p
}

func request(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, r)
	return w
}

func routeBody(r route) string {
	switch {
	case strings.HasSuffix(r.Path, "/validate"):
		return `[]`
	case strings.HasSuffix(r.Path, "/push"):
		return `{"certificate":"Zml4dHVyZQ==","locationAttributes":[],"pushAttributes":[]}`
	case strings.HasSuffix(r.Path, "/remove"):
		return `{"certificateMetadata":[],"locationAttributes":[]}`
	case strings.HasSuffix(r.Path, "/csr"):
		return `{"locationAttributes":[],"csrAttributes":[],"renewal":false}`
	case strings.HasSuffix(r.Path, "/locations"):
		return `{"locationAttributes":[]}`
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		return `{"name":"router.example.test","kind":"iosxe","attributes":[]}`
	default:
		return ""
	}
}

func TestSDKRouteSurface(t *testing.T) {
	h, _ := newHarness(t)
	info := request(h, http.MethodGet, "/v1", "")
	var groups []shared.V1FunctionGroup
	if err := json.Unmarshal(info.Body.Bytes(), &groups); err != nil {
		t.Fatal(err)
	}
	advertised := map[string]bool{}
	for _, g := range groups {
		if g.FunctionGroupCode == entity.FunctionGroupCode {
			for _, e := range g.EndPoints {
				advertised[e.Method+" "+e.Context] = true
			}
		}
	}
	deltas := observations(t)
	for _, r := range routes(t) {
		t.Run(r.Method+" "+r.Path, func(t *testing.T) {
			if !advertised[r.Method+" "+r.Path] {
				t.Fatal("required pinned route not advertised")
			}
			want := r.Status
			for _, d := range deltas {
				if r.Method == d.Method && r.Path == d.Path {
					want = d.SDKStatus
				}
			}
			path := strings.ReplaceAll(r.Path, "{entityUuid}", entityID)
			w := request(h, r.Method, path, routeBody(r))
			if w.Code != want {
				t.Fatalf("SDK status %d, want observed %d (target %d); body=%s", w.Code, want, r.Status, w.Body)
			}
		})
	}
}

func TestSDKV1InfoHealth(t *testing.T) {
	h, _ := newHarness(t)
	w := request(h, http.MethodGet, "/v1", "")
	var groups []shared.V1FunctionGroup
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &groups) != nil {
		t.Fatalf("info: %d %s", w.Code, w.Body)
	}
	found := false
	for _, g := range groups {
		if g.FunctionGroupCode == "entityProvider" && slices.Contains(g.Kinds, "iosxe") {
			found = true
		}
	}
	if !found {
		t.Fatal("v1 entityProvider group/kind missing")
	}
	w = request(h, http.MethodGet, "/v1/health", "")
	var health map[string]any
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &health) != nil || health["status"] != "ok" {
		t.Fatalf("v1 health: %d %s", w.Code, w.Body)
	}
	if _, exists := health["components"]; exists {
		t.Fatal("unexpected v2 health components field")
	}
}

func TestDTOFieldsAgainstPinnedJava(t *testing.T) {
	models := []any{
		mdl.GenerateCsrRequestDto{}, mdl.GenerateCsrResponseDto{},
		mdl.PushCertificateRequestDto{}, mdl.PushCertificateResponseDto{},
		mdl.LocationDetailResponseDto{}, mdl.CertificateLocationDto{},
	}
	fieldRE := regexp.MustCompile(`private\s+(?:List<[^>]+>|boolean|Boolean|String|CertificateType)\s*(\w+)\s*;`)
	for _, model := range models {
		typ := reflect.TypeOf(model)
		t.Run(typ.Name(), func(t *testing.T) {
			source, err := os.ReadFile(filepath.Join("..", "..", "contracts", "ilm-2.19.0", "java", typ.Name()+".java"))
			if err != nil {
				t.Fatal(err)
			}
			var javaFields, sdkFields []string
			for _, match := range fieldRE.FindAllStringSubmatch(string(source), -1) {
				javaFields = append(javaFields, match[1])
			}
			for i := 0; i < typ.NumField(); i++ {
				name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
				if name != "" && name != "-" {
					sdkFields = append(sdkFields, name)
				}
			}
			slices.Sort(javaFields)
			slices.Sort(sdkFields)
			if len(javaFields) == 0 || !slices.Equal(javaFields, sdkFields) {
				t.Fatalf("field set mismatch: 2.19.0=%v SDK=%v", javaFields, sdkFields)
			}
		})
	}
}

func TestCSRPushWireRoundTrip(t *testing.T) {
	attr := `[{"uuid":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","name":"operationId","contentType":"string","version":"v3","content":[{"contentType":"string","data":"synthetic-operation-1"}]}]`
	csrJSON := `{"csr":"c3ludGhldGljLWNzci1ieXRlcw==","pushAttributes":` + attr + `}`
	var csr mdl.GenerateCsrResponseDto
	if err := json.Unmarshal([]byte(csrJSON), &csr); err != nil {
		t.Fatal(err)
	}
	assertJSONRoundTrip(t, csrJSON, &csr)
	pushJSON := `{"certificate":"c3ludGhldGljLWNlcnQtYnl0ZXM=","locationAttributes":[],"pushAttributes":` + attr + `}`
	var push mdl.PushCertificateRequestDto
	if err := json.Unmarshal([]byte(pushJSON), &push); err != nil {
		t.Fatal(err)
	}
	assertJSONRoundTrip(t, pushJSON, &push)
}

func assertJSONRoundTrip(t *testing.T, original string, model any) {
	t.Helper()
	encoded, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal([]byte(original), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("wire content changed: want=%s got=%s", original, encoded)
	}
}

func TestSDKV1Errors(t *testing.T) {
	h, _ := newHarness(t)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{http.MethodPost, "/v1/entityProvider/entities", "{", http.StatusBadRequest},
		{http.MethodGet, "/v1/entityProvider/entities/missing", "", http.StatusNotFound},
	} {
		t.Run(tc.path+tc.method, func(t *testing.T) {
			w := request(h, tc.method, tc.path, tc.body)
			var envelope map[string]any
			if w.Code != tc.status || json.Unmarshal(w.Body.Bytes(), &envelope) != nil {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
			message, ok := envelope["message"].(string)
			if !ok || message == "" || len(envelope) != 1 {
				t.Fatalf("not a v1 message envelope: %s", w.Body)
			}
		})
	}
}

func TestKnownStatusDifferences(t *testing.T) {
	h, _ := newHarness(t)
	differences := observations(t)
	if len(differences) != 3 {
		t.Fatal("review the K-001 compatibility assessment before changing differences")
	}
	for _, d := range differences {
		t.Run(d.Path, func(t *testing.T) {
			var target *route
			for _, r := range routes(t) {
				if r.Path == d.Path && r.Method == d.Method {
					target = &r
				}
			}
			if target == nil || target.Status != d.TargetStatus || d.TargetStatus != 204 || d.SDKStatus != 200 {
				t.Fatal("difference does not describe pinned target/SDK behavior")
			}
			w := request(h, d.Method, strings.ReplaceAll(d.Path, "{entityUuid}", entityID), "[]")
			if w.Code != d.SDKStatus {
				t.Fatalf("SDK behavior changed: %d; update compatibility analysis, not just the expected code", w.Code)
			}
			t.Logf("Known K-001: target=%d SDK=%d; strict connector compatibility remains pending", d.TargetStatus, w.Code)
		})
	}
}

func TestRequiredPushFields(t *testing.T) {
	h, p := newHarness(t)
	w := request(h, http.MethodPost, base+"/locations/push", `{"locationAttributes":[],"pushAttributes":[]}`)
	if w.Code != http.StatusUnprocessableEntity || p.pushCalls != 0 {
		t.Fatalf("missing required field reached provider or wrong status: %d, calls=%d, body=%s", w.Code, p.pushCalls, w.Body)
	}
	var messages []string
	if json.Unmarshal(w.Body.Bytes(), &messages) != nil || len(messages) == 0 {
		t.Fatalf("expected v1 422 message array: %s", w.Body)
	}
}

func TestSDKUnknownPropertyPreservation(t *testing.T) {
	h, p := newHarness(t)
	w := request(h, http.MethodPost, base+"/locations/push", `{"certificate":"Zml4dHVyZQ==","locationAttributes":[],"pushAttributes":[],"unapprovedField":"synthetic"}`)
	if w.Code != http.StatusOK || p.pushCalls != 1 || p.extra["unapprovedField"] != "synthetic" {
		t.Fatalf("SDK unknown-property behavior changed; reassess application validation: %d %v", w.Code, p.extra)
	}
	t.Log("Generated AdditionalProperties bypasses decoder-level unknown-field rejection; application allowlisting is a future requirement")
}

type fixtureProvider struct {
	pushCalls int
	extra     map[string]any
}

var _ entity.Provider = (*fixtureProvider)(nil)

func fixtureEntity(name string) *mdl.EntityInstanceDto {
	return &mdl.EntityInstanceDto{Uuid: entityID, Name: name, Attributes: []mdl.BaseAttributeDto{}}
}

func (p *fixtureProvider) ListEntityInstances(context.Context) ([]mdl.EntityInstanceDto, error) {
	return []mdl.EntityInstanceDto{*fixtureEntity("router.example.test")}, nil
}
func (p *fixtureProvider) CreateEntityInstance(_ context.Context, in *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error) {
	return fixtureEntity(in.Name), nil
}
func (p *fixtureProvider) GetEntityInstance(_ context.Context, id string) (*mdl.EntityInstanceDto, error) {
	if id != entityID {
		return nil, shared.NotFound("NOT_FOUND", "synthetic entity not found")
	}
	return fixtureEntity("router.example.test"), nil
}
func (p *fixtureProvider) UpdateEntityInstance(_ context.Context, _ string, in *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error) {
	return fixtureEntity(in.Name), nil
}
func (p *fixtureProvider) RemoveEntityInstance(context.Context, string) error { return nil }
func (p *fixtureProvider) GetLocationDetail(context.Context, string, *mdl.LocationDetailRequestDto) (*mdl.LocationDetailResponseDto, error) {
	return &mdl.LocationDetailResponseDto{Certificates: []mdl.CertificateLocationDto{}, MultipleEntries: true, SupportKeyManagement: false}, nil
}
func (p *fixtureProvider) PushCertificateToLocation(_ context.Context, _ string, in *mdl.PushCertificateRequestDto) (*mdl.PushCertificateResponseDto, error) {
	p.pushCalls++
	p.extra = in.AdditionalProperties
	return &mdl.PushCertificateResponseDto{}, nil
}
func (p *fixtureProvider) RemoveCertificateFromLocation(context.Context, string, *mdl.RemoveCertificateRequestDto) (*mdl.RemoveCertificateResponseDto, error) {
	return &mdl.RemoveCertificateResponseDto{}, nil
}
func (p *fixtureProvider) GenerateCsrLocation(context.Context, string, *mdl.GenerateCsrRequestDto) (*mdl.GenerateCsrResponseDto, error) {
	return &mdl.GenerateCsrResponseDto{Csr: "c3ludGhldGlj", PushAttributes: []mdl.RequestAttribute{}}, nil
}

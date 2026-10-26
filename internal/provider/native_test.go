package provider_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

type nativeBackend struct {
	calls  int
	target provider.NativeTarget
	denied bool
}

func (b *nativeBackend) Enabled(_ context.Context, q provider.NativeTarget) error {
	b.target = q
	if b.denied {
		return provider.ErrNativeScope
	}
	return nil
}
func (b *nativeBackend) CSR(_ context.Context, q provider.NativeTarget, slot string, renewal bool) (provider.NativeCSR, error) {
	b.calls++
	b.target = q
	if slot != "HTTPS-STAGE-A" || !renewal {
		return provider.NativeCSR{}, errors.New("secret://unexpected-private-detail")
	}
	return provider.NativeCSR{DER: []byte("public-CSR"), OperationID: operationID, State: "AWAITING_ISSUANCE"}, nil
}
func (b *nativeBackend) Push(_ context.Context, q provider.NativeTarget, id string, leaf []byte) (provider.NativePush, error) {
	b.calls++
	b.target = q
	if id != operationID || string(leaf) != "synthetic" {
		return provider.NativePush{}, provider.ErrNativeRejected
	}
	return provider.NativePush{OperationID: id, State: "STAGED", WithKey: true}, nil
}
func TestNativeSDKContractAndAuthentication(t *testing.T) {
	ro, s := openRO(t, filepath.Join(t.TempDir(), "entities.sqlite"), roConfig(), nil)
	id := createRO(t, ro)
	b := &nativeBackend{}
	inv := &readInventory{result: provider.InventorySnapshot{Complete: true}}
	auth := func(r *http.Request) error {
		if r.Header.Get("Authorization") != "synthetic-host-auth" {
			return errors.New("private auth diagnostic")
		}
		return nil
	}
	h, err := provider.NewNativeHandler(s, roConfig(), inv, b, auth)
	if err != nil {
		t.Fatal(err)
	}
	p := "/v1/entityProvider/entities/" + id
	if w := request(h, "POST", p+"/locations/csr", csrBody("HTTPS-STAGE-A")); w.Code != 403 || b.calls != 0 || strings.Contains(w.Body.String(), "diagnostic") {
		t.Fatalf("authentication boundary: %d %s", w.Code, w.Body)
	}
	authed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("Authorization", "synthetic-host-auth")
		h.ServeHTTP(w, r)
	})
	for _, op := range []string{"csr", "push"} {
		w := request(authed, "GET", p+"/locations/"+op+"/attributes", "")
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"version":"v3"`) {
			t.Fatalf("definitions: %d %s", w.Code, w.Body)
		}
	}
	for _, x := range []struct{ path, body string }{{"csr", csrAttrs("HTTPS-STAGE-A")}, {"push", pushAttrs()}} {
		w := request(authed, "POST", p+"/locations/"+x.path+"/attributes/validate", x.body)
		if w.Code != 204 || w.Body.Len() != 0 {
			t.Fatalf("validation: %d %s", w.Code, w.Body)
		}
	}
	w := request(authed, "POST", p+"/locations/csr", csrBody("HTTPS-STAGE-A"))
	var dto struct {
		CSR      string `json:"csr"`
		Push     []any  `json:"pushAttributes"`
		Metadata []any  `json:"metadata"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &dto) != nil || dto.CSR != base64.StdEncoding.EncodeToString([]byte("public-CSR")) || len(dto.Push) != 1 || len(dto.Metadata) == 0 {
		t.Fatalf("CSR DTO: %d %s", w.Code, w.Body)
	}
	if b.target.EntityID != id || b.target.LocationID != provider.HTTPSLocationID(id) || b.target.DeviceID != "router-a" || b.target.Target != "192.0.2.10" {
		t.Fatal("server scope missing")
	}
	w = request(authed, "POST", p+"/locations/push", pushBody())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"withKey":true`) || !strings.Contains(w.Body.String(), "STAGED") {
		t.Fatalf("push: %d %s", w.Code, w.Body)
	}
	w = request(authed, "POST", p+"/locations", `{"locationAttributes":`+locationAttrs()+`}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"supportKeyManagement":true`) {
		t.Fatalf("Core capability guard: %d %s", w.Code, w.Body)
	}
	w = request(authed, "GET", "/v1", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "/locations/csr") || !strings.Contains(w.Body.String(), "/locations/push") || strings.Contains(w.Body.String(), "/locations/remove") {
		t.Fatalf("Info: %s", w.Body)
	}
	w = request(authed, "DELETE", p, "")
	if w.Code != 501 {
		t.Fatalf("native identity deletion: %d", w.Code)
	}
	before := b.calls
	for _, body := range []string{strings.Replace(pushBody(), `"certificate":`, `"chain":[],"certificate":`, 1), strings.Replace(pushBody(), `"version":"v3"`, `"version":"v2"`, 1)} {
		if w = request(authed, "POST", p+"/locations/push", body); w.Code != 422 {
			t.Fatalf("forged push: %d", w.Code)
		}
	}
	if b.calls != before {
		t.Fatal("invalid input reached native backend")
	}
	b.denied = true
	if w = request(authed, "POST", p+"/locations/csr", csrBody("HTTPS-STAGE-A")); w.Code != 403 || b.calls != before {
		t.Fatalf("owner gate: %d", w.Code)
	}
	if _, err = provider.NewNativeHandler(s, roConfig(), inv, b, nil); err == nil {
		t.Fatal("missing host authorizer accepted")
	}
	if _, err = provider.NewNativeHandler(s, roConfig(), inv, nil, auth); err == nil {
		t.Fatal("missing lifecycle accepted")
	}
}

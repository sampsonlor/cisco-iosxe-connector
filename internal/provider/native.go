package provider

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

var (
	ErrNativeScope       = errors.New("native lifecycle scope rejected")
	ErrNativeConflict    = errors.New("native lifecycle requires reconciliation")
	ErrNativeRejected    = errors.New("native certificate policy rejected")
	ErrNativeUnavailable = errors.New("native lifecycle unavailable")
)

// NativeTarget comes from the persisted Entity and approved device registry.
// Operation UUIDs are correlation values; they grant no authorization.
type NativeTarget struct{ EntityID, LocationID, DeviceID, Target string }
type NativeCSR struct {
	DER                []byte
	OperationID, State string
}
type NativePush struct {
	OperationID, State string
	WithKey            bool
}
type NativeAssociation struct{ OperationID, StagingTrustpoint string }
type NativeLifecycle interface {
	Enabled(context.Context, NativeTarget) error
	CSR(context.Context, NativeTarget, string, bool) (NativeCSR, error)
	Push(context.Context, NativeTarget, string, []byte) (NativePush, error)
	Association(context.Context, NativeTarget, []byte) (NativeAssociation, error)
}

// NewNativeHandler is an explicit host integration point, not a server. The host
// must authenticate AND authorize each request in authorize before any routing,
// database access or device action. Never supply an unconditional allow in a host.
// HTTPS transport, the Core identity and its allowed operations are host concerns.
func NewNativeHandler(s *EntityStore, cfg ReadOnlyConfig, r InventoryReader, n NativeLifecycle, authorize func(*http.Request) error) (http.Handler, error) {
	if n == nil || r == nil || authorize == nil {
		return nil, errors.New("native lifecycle, inventory and host authorizer are required")
	}
	h, err := newProviderHandler(s, cfg, r, n)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if authorize(r) != nil {
			shared.WriteV1Error(w, r, &shared.Error{Status: 403, ErrorCode: "NATIVE_ACCESS_DENIED", Detail: "connector access denied"})
			return
		}
		h.ServeHTTP(w, r)
	}), nil
}
func nativeTarget(r entityRecord) NativeTarget {
	return NativeTarget{EntityID: r.ID, LocationID: HTTPSLocationID(r.ID), DeviceID: r.DeviceID, Target: r.Target}
}
func nativeError(err error) error {
	switch {
	case errors.Is(err, ErrNativeScope):
		return &shared.Error{Status: 403, ErrorCode: "NATIVE_SCOPE_REJECTED", Detail: "native lifecycle is not enabled for this service"}
	case errors.Is(err, ErrNativeConflict):
		return &shared.Error{Status: 409, ErrorCode: "NATIVE_RECONCILIATION_REQUIRED", Detail: "operation conflict or independent reconciliation required"}
	case errors.Is(err, ErrNativeRejected):
		return shared.Invalid("NATIVE_POLICY_REJECTED", "certificate or lifecycle policy rejected")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return &shared.Error{Status: 504, ErrorCode: "NATIVE_TIMEOUT", Detail: "native operation did not complete"}
	default:
		return shared.Internal("NATIVE_UNAVAILABLE", "native lifecycle unavailable")
	}
}
func (p *readOnlyProvider) nativeScope(ctx context.Context, id string) (entityRecord, error) {
	if p.native == nil {
		return entityRecord{}, readOnlyError()
	}
	r, err := p.record(ctx, id)
	if err != nil {
		return r, err
	}
	if err = p.native.Enabled(ctx, nativeTarget(r)); err != nil {
		return r, nativeError(err)
	}
	return r, nil
}
func nativeMetadata(id, state string) []mdl.MetadataAttribute {
	return []mdl.MetadataAttribute{inventoryAttribute("0301", "operationId", []string{id}), inventoryAttribute("0302", "operationState", []string{state})}
}
func requestAttribute(s attributeSpec, value string) (mdl.RequestAttribute, error) {
	// Use the already constrained v3 request shape, not a data-definition DTO.
	raw, err := json.Marshal(map[string]any{"uuid": s.id, "name": s.name, "contentType": "string", "version": "v3", "content": []map[string]string{{"contentType": "string", "data": value}}})
	if err != nil {
		return mdl.RequestAttribute{}, err
	}
	var a mdl.RequestAttribute
	err = json.Unmarshal(raw, &a)
	return a, err
}
func (p *readOnlyProvider) nativeCSR(ctx context.Context, id string, in *mdl.GenerateCsrRequestDto) (*mdl.GenerateCsrResponseDto, error) {
	r, err := p.nativeScope(ctx, id)
	if err != nil {
		return nil, err
	}
	v, err := requestValue(in)
	if err != nil || !p.guard.validRequest("csr", r.DeviceID, v) {
		return nil, shared.Invalid("INVALID_CSR", "invalid native CSR attributes")
	}
	m := v.(map[string]any)
	a, _ := scalarAttributes(m["csrAttributes"], csrSpecs)
	result, err := p.native.CSR(ctx, nativeTarget(r), a["stagingTrustpoint"], m["renewal"].(bool))
	if err != nil {
		return nil, nativeError(err)
	}
	if !canonicalUUID(result.OperationID) || len(result.DER) == 0 || len(result.DER) > 16<<10 || result.State != "AWAITING_ISSUANCE" {
		return nil, nativeError(ErrNativeUnavailable)
	}
	attr, err := requestAttribute(pushSpecs[0], result.OperationID)
	if err != nil {
		return nil, nativeError(err)
	}
	typ := mdl.CERTIFICATETYPE_X_509
	return &mdl.GenerateCsrResponseDto{Csr: base64.StdEncoding.EncodeToString(result.DER), CertificateType: &typ, Metadata: nativeMetadata(result.OperationID, result.State), PushAttributes: []mdl.RequestAttribute{attr}}, nil
}
func (p *readOnlyProvider) nativePush(ctx context.Context, id string, in *mdl.PushCertificateRequestDto) (*mdl.PushCertificateResponseDto, error) {
	r, err := p.nativeScope(ctx, id)
	if err != nil {
		return nil, err
	}
	v, err := requestValue(in)
	if err != nil || !p.guard.validRequest("push", r.DeviceID, v) {
		return nil, shared.Invalid("INVALID_PUSH", "invalid native push attributes")
	}
	m := v.(map[string]any)
	a, _ := scalarAttributes(m["pushAttributes"], pushSpecs)
	leaf, err := base64.StdEncoding.Strict().DecodeString(m["certificate"].(string))
	if err != nil {
		return nil, shared.Invalid("INVALID_PUSH", "invalid certificate encoding")
	}
	result, err := p.native.Push(ctx, nativeTarget(r), a["operationId"], leaf)
	if err != nil {
		return nil, nativeError(err)
	}
	if result.OperationID != a["operationId"] || result.State != "STAGED" || !result.WithKey {
		return nil, nativeError(ErrNativeConflict)
	}
	withKey := result.WithKey
	return &mdl.PushCertificateResponseDto{WithKey: &withKey, CertificateMetadata: nativeMetadata(result.OperationID, result.State)}, nil
}

package provider

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
	entity "github.com/OmniTrustILM/go-sdk/connector/provider/entity/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
	"github.com/google/uuid"
)

type ManagedDevice struct {
	Policy        DevicePolicy `json:"policy"`
	CredentialRef string       `json:"credentialRef"`
	HostKeyRef    string       `json:"hostKeyRef"`
}
type ReadOnlyConfig struct {
	Devices map[string]ManagedDevice `json:"devices"`
}
type DeviceAccess struct {
	DeviceID string
	Device   ManagedDevice
}
type PublicCertificate struct {
	DER     []byte
	WithKey bool
}
type InventorySnapshot struct {
	Complete     bool
	Certificates []PublicCertificate
}

// InventoryReader deliberately has no mutation methods. Complete must be based
// on successful observation, including an explicitly empty inventory.
type InventoryReader interface {
	ReadHTTPS(context.Context, DeviceAccess) (InventorySnapshot, error)
}

// HTTPSLocationID is an internal correlation key, not an extra ILM DTO field.
// Core identifies this Location using the entity plus its fixed service attribute.
func HTTPSLocationID(entityUUID string) string {
	if !canonicalUUID(entityUUID) {
		return ""
	}
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("iosxe:"+entityUUID+":https")).String()
}

type readOnlyProvider struct {
	store   *EntityStore
	devices map[string]ManagedDevice
	guard   *boundary
	reader  InventoryReader
}

// readOnlySDK mounts the official routes but advertises only usable operations.
type readOnlySDK struct {
	*entity.Handler
	hasReader bool
}

func (h readOnlySDK) FunctionGroup() shared.V1FunctionGroup {
	g := h.Handler.FunctionGroup()
	g.EndPoints = slices.DeleteFunc(g.EndPoints, func(e shared.V1Endpoint) bool {
		return strings.Contains(e.Context, "/locations/csr") || strings.Contains(e.Context, "/locations/push") || strings.Contains(e.Context, "/locations/remove") || (!h.hasReader && strings.HasSuffix(e.Context, "/locations"))
	})
	return g
}

// NewReadOnlyHandler does not start a listener. The host must provide transport
// authentication/authorization before exposing it to Core.
func NewReadOnlyHandler(store *EntityStore, cfg ReadOnlyConfig, reader InventoryReader) (http.Handler, error) {
	if store == nil || store.db == nil {
		return nil, errors.New("entity store is required")
	}
	devices, policy, err := validateReadOnlyConfig(cfg)
	if err != nil {
		return nil, err
	}
	p := &readOnlyProvider{store: store, devices: devices, reader: reader}
	policy.ResolveEntity = func(ctx context.Context, id string) (string, error) {
		r, err := store.get(ctx, id)
		if errors.Is(err, errEntityMissing) {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		return r.DeviceID, nil
	}
	p.guard = &boundary{cfg: policy}
	// Reject changed/missing operator bindings at startup. A restart cannot
	// silently redirect an existing entity to a different management address.
	records, err := store.list(context.Background())
	if err != nil {
		return nil, err
	}
	for _, r := range records {
		if d, ok := devices[r.DeviceID]; !ok || d.Policy.Target.String() != r.Target {
			return nil, errors.New("stored entity conflicts with approved device policy")
		}
	}
	h, err := entity.NewHandler(p, entity.WithKinds("iosxe"), entity.Base(handlerbase.WithStrictDecode(true)), entity.WithKindAttributes(p), entity.WithLocationAttributes(p), entity.WithPushCertificateAttributes(p), entity.WithGenerateCsrAttributes(p))
	if err != nil {
		return nil, err
	}
	c, err := shared.New(shared.Register(readOnlySDK{h, reader != nil}), shared.WithInfoVersion(shared.VersionV1), shared.WithHealthVersion(shared.VersionV1), shared.WithErrorRenderer(shared.WriteV1Error), shared.WithLogger(slog.Default()), shared.WithInfo(shared.Info{ID: "cisco-iosxe-connector", Name: "Cisco IOS XE read-only provider", Version: "0.1.0-dev"}),
		shared.WithExtraEndpoints(
			shared.ExtraEndpoint{FunctionGroupCode: entity.FunctionGroupCode, Method: http.MethodGet, Context: "/v1", Name: "listSupportedFunctions"},
			shared.ExtraEndpoint{FunctionGroupCode: entity.FunctionGroupCode, Method: http.MethodGet, Context: "/v1/health", Name: "checkHealth"},
		),
	)
	if err != nil {
		return nil, err
	}
	return NewBoundary(c.Handler(), policy)
}

func (p *readOnlyProvider) entityDTO(r entityRecord) *mdl.EntityInstanceDto {
	return &mdl.EntityInstanceDto{Uuid: r.ID, Name: r.Name, Attributes: []mdl.BaseAttributeDto{
		definition(entitySpecs[0], r.DeviceID, true), definition(entitySpecs[1], r.Target, true),
	}}
}
func storageError(err error) error {
	if errors.Is(err, errEntityMissing) {
		return shared.NotFound("ENTITY_NOT_FOUND", "entity not found")
	}
	if errors.Is(err, errEntityConflict) {
		return &shared.Error{Status: 409, ErrorCode: "ENTITY_CONFLICT", Detail: "device already has an entity"}
	}
	return shared.Internal("ENTITY_STORE_UNAVAILABLE", "entity store unavailable")
}
func (p *readOnlyProvider) record(ctx context.Context, id string) (entityRecord, error) {
	r, err := p.store.get(ctx, id)
	if err != nil {
		return r, storageError(err)
	}
	if d, ok := p.devices[r.DeviceID]; !ok || d.Policy.Target.String() != r.Target {
		return r, shared.Internal("DEVICE_POLICY_CHANGED", "stored device binding is unavailable")
	}
	return r, nil
}
func (p *readOnlyProvider) ListEntityInstances(ctx context.Context) ([]mdl.EntityInstanceDto, error) {
	records, err := p.store.list(ctx)
	if err != nil {
		return nil, storageError(err)
	}
	out := make([]mdl.EntityInstanceDto, 0, len(records))
	for _, r := range records {
		if _, err := p.record(ctx, r.ID); err != nil {
			return nil, err
		}
		out = append(out, *p.entityDTO(r))
	}
	return out, nil
}
func (p *readOnlyProvider) CreateEntityInstance(ctx context.Context, in *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error) {
	v, err := requestValue(in)
	if err != nil || !p.guard.validRequest("entity", "", v) {
		return nil, shared.Invalid("INVALID_ENTITY", "invalid entity attributes")
	}
	m := v.(map[string]any)
	a, _ := scalarAttributes(m["attributes"], entitySpecs)
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, shared.Internal("ID_UNAVAILABLE", "entity ID unavailable")
	}
	r := entityRecord{ID: id.String(), Name: in.Name, DeviceID: a["deviceId"], Target: a["targetAddress"]}
	if err := p.store.create(ctx, r); err != nil {
		return nil, storageError(err)
	}
	return p.entityDTO(r), nil
}
func (p *readOnlyProvider) GetEntityInstance(ctx context.Context, id string) (*mdl.EntityInstanceDto, error) {
	r, err := p.record(ctx, id)
	if err != nil {
		return nil, err
	}
	return p.entityDTO(r), nil
}
func (p *readOnlyProvider) UpdateEntityInstance(ctx context.Context, id string, in *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error) {
	r, err := p.record(ctx, id)
	if err != nil {
		return nil, err
	}
	v, err := requestValue(in)
	if err != nil || !p.guard.validRequest("entity", r.DeviceID, v) {
		return nil, shared.Invalid("INVALID_ENTITY", "entity binding cannot change")
	}
	r.Name = in.Name
	if err := p.store.rename(ctx, r); err != nil {
		return nil, storageError(err)
	}
	return p.entityDTO(r), nil
}

// Deletion changes connector metadata only; no inventory/device method is called.
func (p *readOnlyProvider) RemoveEntityInstance(ctx context.Context, id string) error {
	if _, err := p.record(ctx, id); err != nil {
		return err
	}
	if err := p.store.remove(ctx, id); err != nil {
		return storageError(err)
	}
	return nil
}

func requestValue(in any) (any, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	return strictJSON(raw)
}

func (p *readOnlyProvider) GetLocationDetail(ctx context.Context, id string, in *mdl.LocationDetailRequestDto) (*mdl.LocationDetailResponseDto, error) {
	r, err := p.record(ctx, id)
	if err != nil {
		return nil, err
	}
	v, err := requestValue(in)
	if err != nil || !p.guard.validRequest("location", r.DeviceID, v) {
		return nil, shared.Invalid("INVALID_LOCATION", "invalid HTTPS Location")
	}
	if p.reader == nil {
		return nil, &shared.Error{Status: 503, ErrorCode: "INVENTORY_UNAVAILABLE", Detail: "inventory adapter is not configured"}
	}
	d := p.devices[r.DeviceID]
	d.Policy.StagingTrustpoints = slices.Clone(d.Policy.StagingTrustpoints)
	snapshot, err := p.reader.ReadHTTPS(ctx, DeviceAccess{DeviceID: r.DeviceID, Device: d})
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, &shared.Error{Status: 504, ErrorCode: "INVENTORY_TIMEOUT", Detail: "inventory read did not complete"}
	}
	if err != nil || !snapshot.Complete || len(snapshot.Certificates) > 128 {
		return nil, &shared.Error{Status: 502, ErrorCode: "INVENTORY_INCOMPLETE", Detail: "complete inventory is unavailable"}
	}
	certs := make([]mdl.CertificateLocationDto, 0, len(snapshot.Certificates))
	totalBytes := 0
	for _, c := range snapshot.Certificates {
		totalBytes += len(c.DER)
		if len(c.DER) > 1<<20 || totalBytes > 4<<20 {
			return nil, &shared.Error{Status: 502, ErrorCode: "INVENTORY_INVALID", Detail: "invalid public certificate inventory"}
		}
		if _, err := x509.ParseCertificate(c.DER); err != nil {
			return nil, &shared.Error{Status: 502, ErrorCode: "INVENTORY_INVALID", Detail: "invalid public certificate inventory"}
		}
		typ := mdl.CERTIFICATETYPE_X_509
		certs = append(certs, mdl.CertificateLocationDto{CertificateData: base64.StdEncoding.EncodeToString(c.DER), CertificateType: &typ, WithKey: c.WithKey})
	}
	return &mdl.LocationDetailResponseDto{Certificates: certs, MultipleEntries: true, SupportKeyManagement: false}, nil
}

func readOnlyError() error {
	return &shared.Error{Status: 501, ErrorCode: "READ_ONLY_PROVIDER", Detail: "certificate mutation is not implemented"}
}
func (p *readOnlyProvider) PushCertificateToLocation(context.Context, string, *mdl.PushCertificateRequestDto) (*mdl.PushCertificateResponseDto, error) {
	return nil, readOnlyError()
}
func (p *readOnlyProvider) RemoveCertificateFromLocation(context.Context, string, *mdl.RemoveCertificateRequestDto) (*mdl.RemoveCertificateResponseDto, error) {
	return nil, readOnlyError()
}
func (p *readOnlyProvider) GenerateCsrLocation(context.Context, string, *mdl.GenerateCsrRequestDto) (*mdl.GenerateCsrResponseDto, error) {
	return nil, readOnlyError()
}

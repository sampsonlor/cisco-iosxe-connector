package provider

import (
	"context"
	"io"
	"net/http"
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

type EntityStore struct{}

func OpenEntityStore(path string) (*EntityStore, error)      { return &EntityStore{}, nil }
func (s *EntityStore) Close() error                          { return nil }
func LoadReadOnlyConfig(r io.Reader) (ReadOnlyConfig, error) { return ReadOnlyConfig{}, nil }
func HTTPSLocationID(entityUUID string) string               { return "" }
func NewReadOnlyHandler(store *EntityStore, cfg ReadOnlyConfig, reader InventoryReader) (http.Handler, error) {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reject(w, 501, "not implemented") }), nil
}

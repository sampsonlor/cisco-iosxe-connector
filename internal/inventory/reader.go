package inventory

import (
	"context"
	"net/netip"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

// Source must be constructed from an operator-approved transport registry.
type Source interface {
	ApprovedTarget(string, netip.Addr, string, string) bool
	Collect(context.Context, string) (device.Evidence,error)
}
type Reader struct { source Source; assignments map[string][]Assignment }
func NewReader(Source,map[string][]Assignment)(*Reader,error) { return nil,ErrIncomplete }
func (*Reader) ReadHTTPS(context.Context,provider.DeviceAccess)(provider.InventorySnapshot,error) {return provider.InventorySnapshot{},ErrIncomplete}

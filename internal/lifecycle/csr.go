package lifecycle

import (
	"context"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

type CSRDevice interface {
	Generate(context.Context, csr.Request) (csr.Result, error)
	Inspect(context.Context, csr.Request) error
}
type CSRGate struct {
	journal *journal.Store
	device  CSRDevice
}

// NewIOSXECSRGate wires the concrete opt-in adapter to the real inventory
// semantic verifier. Hosts must not substitute transport success for this check.
func NewIOSXECSRGate(store *journal.Store, client *device.Client, policies map[string]device.CSRPolicy) (*CSRGate, error) {
	adapter, err := device.NewCSRAdapter(client, policies, inventory.VerifyCSRBaseline)
	if err != nil {
		return nil, err
	}
	return NewCSRGate(store, adapter)
}

func NewCSRGate(store *journal.Store, device CSRDevice) (*CSRGate, error) {
	if store == nil || device == nil {
		return nil, journal.ErrStore
	}
	return &CSRGate{journal: store, device: device}, nil
}
func (g *CSRGate) Generate(ctx context.Context, ref journal.Ref, spec csr.Spec) (journal.Record, []byte, error) {
	if g == nil || g.journal == nil || g.device == nil {
		return journal.Record{}, nil, journal.ErrStore
	}
	return g.journal.GenerateCSR(ctx, ref, spec, g.device.Generate)
}

// Reconcile performs read-only observation. A missing/lost CSR cannot be
// recreated by regenerating its key; unresolved ownership deliberately remains.
func (g *CSRGate) Reconcile(ctx context.Context, ref journal.Ref) error {
	if g == nil || g.journal == nil || g.device == nil {
		return journal.ErrStore
	}
	q, err := g.journal.CSRRequest(ctx, ref)
	if err != nil {
		return err
	}
	_ = g.device.Inspect(ctx, q)
	return journal.ErrReconcile
}

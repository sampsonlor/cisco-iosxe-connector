// Package lifecycle contains shared API/worker side-effect gates. The read-only
// Provider does not expose CSR, issuance or the opt-in inactive import adapter.
package lifecycle

import (
	"context"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

type Importer interface {
	Import(context.Context, journal.Record) error
}
type ImportGate struct{ journal *journal.Store }

func NewImportGate(store *journal.Store) (*ImportGate, error) {
	if store == nil {
		return nil, journal.ErrStore
	}
	return &ImportGate{journal: store}, nil
}

// Stage is the digest-only foundation harness. Recorded runtime CSRs require
// StageGate's fresh validation, device/TLS observation and durable artifacts.
func (g *ImportGate) Stage(ctx context.Context, ref journal.Ref, certificateSHA256 string, importer Importer) (journal.Record, error) {
	if g == nil || g.journal == nil || importer == nil {
		return journal.Record{}, journal.ErrStore
	}
	return g.journal.ImportOnce(ctx, ref, certificateSHA256, importer.Import)
}

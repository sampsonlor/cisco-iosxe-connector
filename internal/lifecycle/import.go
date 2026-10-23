// Package lifecycle contains the shared API/worker side-effect gates. Actual
// device CSR, certificate validation and inactive import adapters are separate
// milestones and are not exposed by the read-only Provider.
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

// Stage is an internal entry point for an already validated certificate. The
// production validator and adapter must be wired before advertising SDK push.
func (g *ImportGate) Stage(ctx context.Context, ref journal.Ref, certificateSHA256 string, importer Importer) (journal.Record, error) {
	if g == nil || g.journal == nil || importer == nil {
		return journal.Record{}, journal.ErrStore
	}
	return g.journal.ImportOnce(ctx, ref, certificateSHA256, importer.Import)
}

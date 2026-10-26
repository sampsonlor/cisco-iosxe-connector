package lifecycle

import (
	"context"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

type CertificateGate struct {
	journal   *journal.Store
	validator *certpolicy.Validator
}

func (g *CertificateGate) PolicySHA256() string {
	if g == nil || g.validator == nil {
		return ""
	}
	return g.validator.Digest()
}

func NewCertificateGate(store *journal.Store, validator *certpolicy.Validator) (*CertificateGate, error) {
	if store == nil || validator == nil {
		return nil, journal.ErrStore
	}
	return &CertificateGate{journal: store, validator: validator}, nil
}

// Accept is shared by future native Core and ACME issuance paths. Validation is
// always against the recorded CSR, with fresh time and enrollment evidence even
// on an idempotent retry. No certificate is imported or activated here.
func (g *CertificateGate) Accept(ctx context.Context, ref journal.Ref, leaf []byte, chain [][]byte) (journal.Record, certpolicy.Result, error) {
	if g == nil || g.journal == nil || g.validator == nil {
		return journal.Record{}, certpolicy.Result{}, journal.ErrStore
	}
	r, spec, material, err := g.journal.CertificateMaterial(ctx, ref)
	if err != nil {
		return journal.Record{}, certpolicy.Result{}, err
	}
	if g.validator.Digest() != r.Correlation.PolicySHA256 {
		return journal.Record{}, certpolicy.Result{}, journal.ErrCorrelation
	}
	proof, err := g.validator.Validate(ctx, material, spec, leaf, chain)
	if err != nil {
		return journal.Record{}, certpolicy.Result{}, err
	}
	ready, err := g.journal.CertificateValidated(ctx, ref, r.Revision, proof)
	if err != nil {
		return journal.Record{}, certpolicy.Result{}, err
	}
	return ready, proof, nil
}

package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

func recordedCertificateMaterial(ctx context.Context, q querier, id string) (csr.Spec, csr.Result, error) {
	var raw, label string
	var material csr.Result
	err := q.QueryRowContext(ctx, "SELECT specification,key_label,csr_der,public_key_der FROM csr_operations WHERE operation_id=?", id).Scan(&raw, &label, &material.DER, &material.PublicKeyDER)
	if errors.Is(err, sql.ErrNoRows) {
		return csr.Spec{}, csr.Result{}, ErrState
	}
	if err != nil {
		return csr.Spec{}, csr.Result{}, ErrStore
	}
	var spec csr.Spec
	if json.Unmarshal([]byte(raw), &spec) != nil || label != csr.KeyLabel(id) {
		return csr.Spec{}, csr.Result{}, ErrStore
	}
	spec, err = csr.Normalize(spec)
	encoded, _ := json.Marshal(spec)
	material.NonExportable = true // recorded only after the guarded CSR proof
	if err != nil || raw != string(encoded) || csr.Validate(material, spec) != nil {
		return csr.Spec{}, csr.Result{}, ErrReconcile
	}
	return spec, material, nil
}

// CertificateMaterial reads the authorized, durable CSR and current revision
// from one snapshot. It never trusts CSR bytes supplied by an issuance caller.
func (s *Store) CertificateMaterial(ctx context.Context, ref Ref) (Record, csr.Spec, csr.Result, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, csr.Spec{}, csr.Result{}, ErrStore
	}
	var r Record
	var spec csr.Spec
	var material csr.Result
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		r, err = s.authorized(ctx, tx, ref)
		if err != nil {
			return err
		}
		if r.State != AwaitingIssuance && r.State != CertReady {
			return ErrState
		}
		spec, material, err = recordedCertificateMaterial(ctx, tx, ref.ID)
		return err
	})
	if err != nil {
		return Record{}, csr.Spec{}, csr.Result{}, err
	}
	return r, spec, material, nil
}

// CertificateValidated binds a fresh opaque validator receipt to the saved CSR,
// approved policy, baseline and current revision atomically with its history.
// Receipt bytes remain transient; later import must revalidate its own inputs.
func (s *Store) CertificateValidated(ctx context.Context, ref Ref, revision int64, proof certpolicy.Result) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, ErrStore
	}
	var result Record
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, err := s.authorized(ctx, tx, ref)
		if err != nil {
			return err
		}
		if r.Revision != revision {
			return ErrConflict
		}
		if !proof.ValidAt(time.Now().UTC()) || proof.PolicySHA256() != r.Correlation.PolicySHA256 || proof.CertificateSHA256() == r.Correlation.BaselineSHA256 {
			return ErrCorrelation
		}
		_, material, err := recordedCertificateMaterial(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		if proof.CSRSHA256() != certpolicy.SHA256(material.DER) {
			return ErrCorrelation
		}
		if r.State == CertReady && r.CertificateSHA256 == proof.CertificateSHA256() {
			result = r
			return nil
		}
		if r.State != AwaitingIssuance {
			return ErrState
		}
		result, err = save(ctx, tx, r, CertReady, proof.CertificateSHA256())
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return result, nil
}

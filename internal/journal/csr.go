package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

func csrRequest(r Record, spec csr.Spec) csr.Request {
	spec.DNSNames = slices.Clone(spec.DNSNames)
	c := r.Correlation
	return csr.Request{OperationID: r.ID, DeviceID: c.DeviceID, Target: c.Target, HostKeySHA256: c.HostKeySHA256, PolicySHA256: c.PolicySHA256, ActiveTrustpoint: c.ActiveTrustpoint, BaselineSHA256: c.BaselineSHA256, Trustpoint: c.StagingTrustpoint, Spec: spec}
}

// GenerateCSR commits the complete request and KEY_CREATING intent before any
// generator call. A pending request is never regenerated after an uncertain result.
func (s *Store) GenerateCSR(ctx context.Context, ref Ref, spec csr.Spec, generate func(context.Context, csr.Request) (csr.Result, error)) (Record, []byte, error) {
	spec, err := csr.Normalize(spec)
	if err != nil || generate == nil {
		return Record{}, nil, ErrCorrelation
	}
	encoded, _ := json.Marshal(spec)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, nil, ErrStore
	}
	var r Record
	var cached []byte
	dispatch := false
	err = s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		r, err = s.authorized(ctx, tx, ref)
		if err != nil {
			return err
		}
		var stored, label string
		var der, pub []byte
		err = tx.QueryRowContext(ctx, "SELECT specification,key_label,csr_der,public_key_der FROM csr_operations WHERE operation_id=?", ref.ID).Scan(&stored, &label, &der, &pub)
		if err == nil {
			if stored != string(encoded) || label != csr.KeyLabel(r.ID) {
				return ErrCorrelation
			}
			if r.State == KeyCreating || r.State == Precheck || r.State == FailedNoSwitch || len(der) == 0 {
				return ErrReconcile
			}
			if csr.Validate(csr.Result{DER: der, PublicKeyDER: pub, NonExportable: true}, spec) != nil {
				return ErrStore
			}
			cached = slices.Clone(der)
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return ErrStore
		}
		if r.State != Precheck {
			return ErrReconcile
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO csr_operations(operation_id,specification,key_label,csr_der,public_key_der) VALUES(?,?,?,X'',X'')", r.ID, string(encoded), csr.KeyLabel(r.ID)); err != nil {
			return ErrStore
		}
		r, err = save(ctx, tx, r, KeyCreating, "")
		dispatch = err == nil
		return err
	})
	if err != nil {
		return r, nil, err
	}
	if !dispatch {
		return r, cached, nil
	}
	if ctx.Err() != nil {
		return r, nil, ErrReconcile
	}
	result, err := generate(ctx, csrRequest(r, spec))
	if err != nil || csr.Validate(result, spec) != nil {
		return r, nil, ErrReconcile
	}
	claimed := r
	err = s.transaction(ctx, func(tx *sql.Tx) error {
		current, err := s.authorized(ctx, tx, ref)
		if err != nil {
			return err
		}
		if current.State != KeyCreating || current.Revision != claimed.Revision {
			return ErrConflict
		}
		updated, err := tx.ExecContext(ctx, "UPDATE csr_operations SET csr_der=?,public_key_der=? WHERE operation_id=? AND specification=? AND length(csr_der)=0 AND length(public_key_der)=0", result.DER, result.PublicKeyDER, r.ID, string(encoded))
		if err != nil {
			return ErrStore
		}
		if count, err := updated.RowsAffected(); err != nil || count != 1 {
			return ErrConflict
		}
		r, err = save(ctx, tx, current, CSRReady, "")
		return err
	})
	if err != nil {
		return claimed, nil, err
	}
	return r, slices.Clone(result.DER), nil
}

// CSRRequest supports read-only observation of unfinished work. It is not a
// permission to rerun generation or mark an unknown result successful.
func (s *Store) CSRRequest(ctx context.Context, ref Ref) (csr.Request, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return csr.Request{}, ErrStore
	}
	r, err := s.authorized(ctx, s.db, ref)
	if err != nil {
		return csr.Request{}, err
	}
	var raw, label string
	if err := s.db.QueryRowContext(ctx, "SELECT specification,key_label FROM csr_operations WHERE operation_id=?", ref.ID).Scan(&raw, &label); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return csr.Request{}, ErrReconcile
		}
		return csr.Request{}, ErrStore
	}
	var spec csr.Spec
	if json.Unmarshal([]byte(raw), &spec) != nil || label != csr.KeyLabel(ref.ID) {
		return csr.Request{}, ErrStore
	}
	spec, err = csr.Normalize(spec)
	if err != nil {
		return csr.Request{}, ErrStore
	}
	return csrRequest(r, spec), nil
}

func (s *Store) checkCSRStorage(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT c.operation_id,c.specification,c.key_label,c.csr_der,c.public_key_der,o.state FROM csr_operations c LEFT JOIN operations o ON o.id=c.operation_id")
	if err != nil {
		return ErrStore
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw, label string
		var der, pub []byte
		var state State
		if rows.Scan(&id, &raw, &label, &der, &pub, &state) != nil {
			return ErrStore
		}
		var spec csr.Spec
		if json.Unmarshal([]byte(raw), &spec) != nil {
			return ErrStore
		}
		normalized, err := csr.Normalize(spec)
		encoded, _ := json.Marshal(normalized)
		if err != nil || raw != string(encoded) || label != csr.KeyLabel(id) {
			return ErrStore
		}
		if state == KeyCreating {
			if len(der) != 0 || len(pub) != 0 {
				return ErrStore
			}
		} else if state == Precheck || state == FailedNoSwitch || csr.Validate(csr.Result{DER: der, PublicKeyDER: pub, NonExportable: true}, spec) != nil {
			return ErrStore
		}
	}
	if rows.Err() != nil {
		return ErrStore
	}
	return nil
}

package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

func (s *Store) Begin(ctx context.Context, requestID string, c Correlation) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, ErrStore
	}
	if !canonicalID(requestID) || !s.approved(c) {
		return Record{}, ErrCorrelation
	}
	var result Record
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, err := readRecord(tx.QueryRowContext(ctx, "SELECT "+recordColumns+" FROM operations WHERE request_id=?", requestID))
		if err == nil {
			if r.Correlation != c {
				return ErrCorrelation
			}
			result = r
			return nil
		}
		if !errors.Is(err, ErrCorrelation) {
			return err
		}
		var busy int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE location_id=? AND state<>?", c.LocationID, FailedNoSwitch).Scan(&busy); err != nil {
			return ErrStore
		}
		if busy > 0 {
			return ErrBusy
		}
		id, err := uuid.NewRandom()
		if err != nil {
			return ErrStore
		}
		now := time.Now().UTC().Truncate(time.Millisecond)
		result = Record{ID: id.String(), RequestID: requestID, Correlation: c, State: Precheck, Revision: 1, CreatedAt: now, UpdatedAt: now}
		raw, _ := json.Marshal(c)
		if _, err := tx.ExecContext(ctx, "INSERT INTO operations("+recordColumns+") VALUES(?,?,?,?,?,?,?,?,?)", result.ID, result.RequestID, c.LocationID, string(raw), Precheck, 1, "", now.UnixMilli(), now.UnixMilli()); err != nil {
			return ErrStore
		}
		return appendEvent(ctx, tx, result, "")
	})
	if err != nil {
		return Record{}, err
	}
	return result, nil
}

func appendEvent(ctx context.Context, tx *sql.Tx, r Record, from State) error {
	if _, err := tx.ExecContext(ctx, "INSERT INTO events(operation_id,revision,from_state,to_state,certificate_sha256,at) VALUES(?,?,?,?,?,?)", r.ID, r.Revision, from, r.State, r.CertificateSHA256, r.UpdatedAt.UnixMilli()); err != nil {
		return ErrStore
	}
	return nil
}
func save(ctx context.Context, tx *sql.Tx, r Record, to State, certificate string) (Record, error) {
	previous := r
	now := time.Now().UTC().Truncate(time.Millisecond)
	if now.Before(r.UpdatedAt) {
		now = r.UpdatedAt
	}
	r.State = to
	r.Revision++
	r.CertificateSHA256 = certificate
	r.UpdatedAt = now
	result, err := tx.ExecContext(ctx, "UPDATE operations SET state=?,revision=?,certificate_sha256=?,updated_at=? WHERE id=? AND revision=? AND state=?", to, r.Revision, certificate, now.UnixMilli(), r.ID, previous.Revision, previous.State)
	if err != nil {
		return Record{}, ErrStore
	}
	count, err := result.RowsAffected()
	if err != nil {
		return Record{}, ErrStore
	}
	if count != 1 {
		return Record{}, ErrConflict
	}
	if err := appendEvent(ctx, tx, r, previous.State); err != nil {
		return Record{}, err
	}
	return r, nil
}
func (s *Store) change(ctx context.Context, ref Ref, revision int64, to State, certificate string) (Record, error) {
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
		if to == CertReady {
			// The digest-only foundation path cannot bypass validation once a
			// real CSR request has been recorded. Runtime hosts use the gate.
			var recorded int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM csr_operations WHERE operation_id=?", r.ID).Scan(&recorded); err != nil {
				return ErrStore
			}
			if recorded != 0 {
				return ErrState
			}
		}
		allowed := (r.State == Precheck && (to == KeyCreating || to == FailedNoSwitch)) || (r.State == KeyCreating && to == CSRReady) || (r.State == CSRReady && to == AwaitingIssuance) || (r.State == AwaitingIssuance && to == CertReady && digest.MatchString(certificate) && certificate != r.Correlation.BaselineSHA256)
		if !allowed {
			return ErrState
		}
		result, err = save(ctx, tx, r, to, certificate)
		return err
	})
	if err != nil {
		return Record{}, err
	}
	return result, nil
}
func (s *Store) Progress(ctx context.Context, ref Ref, revision int64, to State) (Record, error) {
	if to != KeyCreating && to != CSRReady && to != AwaitingIssuance {
		return Record{}, ErrState
	}
	return s.change(ctx, ref, revision, to, "")
}

// CertificateReady is the digest-only journal foundation harness. It rejects
// operations with a recorded CSR; runtime flows use CertificateValidated.
func (s *Store) CertificateReady(ctx context.Context, ref Ref, revision int64, certificateSHA256 string) (Record, error) {
	return s.change(ctx, ref, revision, CertReady, certificateSHA256)
}

// Only an operation with no key/issuance/import intent can be safely released
// without device reconciliation. STAGED and uncertain work retain ownership.
func (s *Store) AbortPrecheck(ctx context.Context, ref Ref, revision int64) (Record, error) {
	return s.change(ctx, ref, revision, FailedNoSwitch, "")
}

// ImportOnce commits IMPORTING before dispatch and STAGED only after success.
// A pending intent is never automatically replayed, even after restart. Actual
// certificate/CSR/chain policy validation belongs to the later staging engine.
func (s *Store) ImportOnce(ctx context.Context, ref Ref, certificateSHA256 string, effect func(context.Context, Record) error) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, ErrStore
	}
	if effect == nil || !digest.MatchString(certificateSHA256) {
		return Record{}, ErrCorrelation
	}
	var result Record
	dispatch := false
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, err := s.authorized(ctx, tx, ref)
		if err != nil {
			return err
		}
		if r.CertificateSHA256 != certificateSHA256 {
			return ErrCorrelation
		}
		// The digest-only foundation harness cannot dispatch a recorded runtime
		// CSR. Runtime imports require StageOnce and fresh validator receipts.
		var realCSR int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM csr_operations WHERE operation_id=?", r.ID).Scan(&realCSR); err != nil {
			return ErrStore
		}
		if realCSR != 0 {
			return ErrState
		}
		result = r
		switch r.State {
		case Staged:
			return nil
		case Importing:
			return ErrReconcile
		case CertReady:
			result, err = save(ctx, tx, r, Importing, certificateSHA256)
			dispatch = err == nil
			return err
		default:
			return ErrState
		}
	})
	if err != nil {
		return result, err
	}
	if !dispatch {
		return result, nil
	}
	if ctx.Err() != nil {
		return result, ErrReconcile
	}
	if err = effect(ctx, result); err != nil {
		return result, ErrReconcile
	}
	claimed := result
	err = s.transaction(ctx, func(tx *sql.Tx) error {
		current, err := s.authorized(ctx, tx, ref)
		if err != nil {
			return err
		}
		if current.State != Importing || current.Revision != claimed.Revision {
			return ErrConflict
		}
		result, err = save(ctx, tx, current, Staged, certificateSHA256)
		return err
	})
	if err != nil {
		return claimed, err
	}
	return result, nil
}

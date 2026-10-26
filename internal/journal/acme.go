package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

func readACME(ctx context.Context, q querier, id string) (ACMERecord, error) {
	var raw string
	if err := q.QueryRowContext(ctx, "SELECT record FROM acme_operations WHERE operation_id=?", id).Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ACMERecord{}, ErrState
		}
		return ACMERecord{}, ErrStore
	}
	var r ACMERecord
	if len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &r) != nil || !validACMERecord(r) {
		return ACMERecord{}, ErrStore
	}
	encoded, _ := json.Marshal(r)
	if string(encoded) != raw {
		return ACMERecord{}, ErrStore
	}
	return r, nil
}

// LockACME excludes overlapping workers on this Store. Durable side-effect
// intents remain the recovery boundary across Close, process death and restart.
// No Store lock is held while a protocol request or DNS backend is running.
func (s *Store) LockACME(ctx context.Context, ref Ref) (func(), error) {
	r, err := s.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	if r.Correlation.Owner != ACMEWorker {
		return nil, ErrCorrelation
	}
	s.acmeMu.Lock()
	defer s.acmeMu.Unlock()
	if s.acmeJobs == nil {
		s.acmeJobs = map[string]bool{}
	}
	if s.acmeJobs[ref.ID] {
		return nil, ErrBusy
	}
	s.acmeJobs[ref.ID] = true
	var once sync.Once
	return func() { once.Do(func() { s.acmeMu.Lock(); delete(s.acmeJobs, ref.ID); s.acmeMu.Unlock() }) }, nil
}

// BeginACME binds the external CSR and account configuration before any network
// side effect. It advances CSR_READY once, without creating a replacement CSR.
func (s *Store) BeginACME(ctx context.Context, ref Ref, b ACMEBinding) (Record, csr.Spec, csr.Result, ACMERecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, csr.Spec{}, csr.Result{}, ACMERecord{}, ErrStore
	}
	if !validACMEBinding(b) {
		return Record{}, csr.Spec{}, csr.Result{}, ACMERecord{}, ErrCorrelation
	}
	var r Record
	var spec csr.Spec
	var material csr.Result
	var flow ACMERecord
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		var err error
		r, err = s.authorized(ctx, tx, ref)
		if err != nil {
			return err
		}
		if r.Correlation.Owner != ACMEWorker {
			return ErrCorrelation
		}
		if r.State != CSRReady && r.State != AwaitingIssuance && r.State != CertReady {
			return ErrState
		}
		spec, material, err = recordedCertificateMaterial(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		flow, err = readACME(ctx, tx, ref.ID)
		if err == nil {
			if flow.Binding != b || flow.CSRSHA256 != certpolicy.SHA256(material.DER) {
				return ErrCorrelation
			}
			return nil
		}
		if !errors.Is(err, ErrState) {
			return err
		}
		if r.State != CSRReady {
			return ErrReconcile
		}
		binding, _ := json.Marshal(b)
		if _, err = tx.ExecContext(ctx, "INSERT INTO acme_accounts(binding_id,configuration,account_url) VALUES(?,?,'') ON CONFLICT(binding_id) DO NOTHING", acmeBindingID(b), string(binding)); err != nil {
			return ErrStore
		}
		flow = ACMERecord{Binding: b, Revision: 1, CSRSHA256: certpolicy.SHA256(material.DER), Stage: ACMEPreparing}
		raw, _ := json.Marshal(flow)
		if _, err = tx.ExecContext(ctx, "INSERT INTO acme_operations(operation_id,binding_id,revision,record) VALUES(?,?,?,?)", r.ID, acmeBindingID(b), 1, string(raw)); err != nil {
			return ErrStore
		}
		r, err = save(ctx, tx, r, AwaitingIssuance, "")
		return err
	})
	if err != nil {
		return Record{}, csr.Spec{}, csr.Result{}, ACMERecord{}, err
	}
	return r, spec, material, flow, nil
}

func (s *Store) ACMEStatus(ctx context.Context, ref Ref) (ACMERecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ACMERecord{}, ErrStore
	}
	if _, err := s.authorized(ctx, s.db, ref); err != nil {
		return ACMERecord{}, err
	}
	return readACME(ctx, s.db, ref.ID)
}
func (s *Store) SaveACME(ctx context.Context, ref Ref, revision int64, next ACMERecord) (ACMERecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ACMERecord{}, ErrStore
	}
	var result ACMERecord
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, err := s.authorized(ctx, tx, ref)
		if err != nil {
			return err
		}
		if r.Correlation.Owner != ACMEWorker {
			return ErrCorrelation
		}
		old, err := readACME(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		if old.Revision != revision {
			return ErrConflict
		}
		if !acmeChangeAllowed(old, next) {
			return ErrCorrelation
		}
		next.Revision = revision + 1
		raw, _ := json.Marshal(next)
		res, err := tx.ExecContext(ctx, "UPDATE acme_operations SET revision=?,record=? WHERE operation_id=? AND revision=?", next.Revision, string(raw), ref.ID, revision)
		if err != nil {
			return ErrStore
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			return ErrConflict
		}
		if json.Unmarshal(raw, &result) != nil {
			return ErrStore
		}
		return nil
	})
	if err != nil {
		return ACMERecord{}, err
	}
	return result, nil
}
func (s *Store) ACMEAccount(ctx context.Context, ref Ref) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return "", ErrStore
	}
	if _, err := s.authorized(ctx, s.db, ref); err != nil {
		return "", err
	}
	flow, err := readACME(ctx, s.db, ref.ID)
	if err != nil {
		return "", err
	}
	var uri string
	if err = s.db.QueryRowContext(ctx, "SELECT account_url FROM acme_accounts WHERE binding_id=?", acmeBindingID(flow.Binding)).Scan(&uri); err != nil {
		return "", ErrStore
	}
	return uri, nil
}
func (s *Store) BindACMEAccount(ctx context.Context, ref Ref, uri string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrStore
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		if _, err := s.authorized(ctx, tx, ref); err != nil {
			return err
		}
		flow, err := readACME(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		if !ValidACMEResource(flow.Binding.DirectoryURL, uri) {
			return ErrCorrelation
		}
		var old string
		if err = tx.QueryRowContext(ctx, "SELECT account_url FROM acme_accounts WHERE binding_id=?", acmeBindingID(flow.Binding)).Scan(&old); err != nil {
			return ErrStore
		}
		if old != "" && old != uri {
			return ErrCorrelation
		}
		if _, err = tx.ExecContext(ctx, "UPDATE acme_accounts SET account_url=? WHERE binding_id=?", uri, acmeBindingID(flow.Binding)); err != nil {
			return ErrStore
		}
		return nil
	})
}

func (s *Store) checkACMEStorage(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, "SELECT binding_id,configuration,account_url FROM acme_accounts")
	if err != nil {
		return ErrStore
	}
	bindings := map[string]ACMEBinding{}
	for rows.Next() {
		var id, raw, uri string
		var b ACMEBinding
		if rows.Scan(&id, &raw, &uri) != nil || len(raw) > 8192 || json.Unmarshal([]byte(raw), &b) != nil || !validACMEBinding(b) || id != acmeBindingID(b) || uri != "" && !ValidACMEResource(b.DirectoryURL, uri) {
			rows.Close()
			return ErrStore
		}
		encoded, _ := json.Marshal(b)
		if raw != string(encoded) {
			rows.Close()
			return ErrStore
		}
		bindings[id] = b
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return ErrStore
	}
	rows, err = s.db.QueryContext(ctx, "SELECT a.binding_id,a.revision,a.record,c.csr_der,o.state FROM acme_operations a LEFT JOIN csr_operations c ON a.operation_id=c.operation_id LEFT JOIN operations o ON a.operation_id=o.id")
	if err != nil {
		return ErrStore
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw string
		var rev int64
		var der []byte
		var state State
		var r ACMERecord
		if rows.Scan(&id, &rev, &raw, &der, &state) != nil || len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &r) != nil || !validACMERecord(r) || r.Binding != bindings[id] || r.Revision != rev || r.CSRSHA256 != certpolicy.SHA256(der) || state != AwaitingIssuance && state != CertReady && state != Importing && state != Staged {
			return ErrStore
		}
		encoded, _ := json.Marshal(r)
		if raw != string(encoded) {
			return ErrStore
		}
	}
	if rows.Err() != nil {
		return ErrStore
	}
	return nil
}

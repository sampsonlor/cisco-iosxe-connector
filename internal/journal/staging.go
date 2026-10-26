package journal

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
)

type StageArtifact struct {
	SettingsSHA256, CSRSHA256, OtherStateSHA256 string
	LeafDER                                     []byte
	ChainDER                                    [][]byte
	Revision                                    int64
}
type StageRecheck func(context.Context, certpolicy.Result) error

func stageAllowed(ctx context.Context, q querier, r Record) error {
	if r.State != CertReady && r.State != Importing && r.State != Staged {
		return ErrState
	}
	if r.Correlation.Owner == ACMEWorker {
		flow, err := readACME(ctx, q, r.ID)
		if err != nil {
			return err
		}
		if flow.CancelRequested || flow.Stage != ACMEIssued {
			return ErrState
		}
	}
	return nil
}
func (s *Store) stageMaterial(ctx context.Context, q querier, ref Ref) (Record, staging.Request, error) {
	r, err := s.authorized(ctx, q, ref)
	if err != nil {
		return r, staging.Request{}, err
	}
	if err := stageAllowed(ctx, q, r); err != nil {
		return r, staging.Request{}, err
	}
	spec, material, err := recordedCertificateMaterial(ctx, q, ref.ID)
	if err != nil {
		return r, staging.Request{}, err
	}
	return r, staging.Request{CSR: csrRequest(r, spec), Material: material}, nil
}
func (s *Store) StageMaterial(ctx context.Context, ref Ref) (Record, staging.Request, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, staging.Request{}, ErrStore
	}
	var r Record
	var q staging.Request
	err := s.transaction(ctx, func(tx *sql.Tx) error { var err error; r, q, err = s.stageMaterial(ctx, tx, ref); return err })
	return r, q, err
}
func (s *Store) LockStage(ctx context.Context, ref Ref) (func(), error) {
	r, err := s.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	if r.Correlation.Owner == ACMEWorker {
		return s.LockACME(ctx, ref)
	}
	s.stageMu.Lock()
	defer s.stageMu.Unlock()
	if s.stageJobs == nil {
		s.stageJobs = map[string]bool{}
	}
	if s.stageJobs[r.ID] {
		return nil, ErrBusy
	}
	s.stageJobs[r.ID] = true
	var once sync.Once
	return func() { once.Do(func() { s.stageMu.Lock(); delete(s.stageJobs, r.ID); s.stageMu.Unlock() }) }, nil
}
func stageProof(r Record, q staging.Request, p certpolicy.Result) bool {
	return p.ValidAt(time.Now().UTC()) && p.PolicySHA256() == r.Correlation.PolicySHA256 && p.CSRSHA256() == certpolicy.SHA256(q.Material.DER) && p.CertificateSHA256() == r.CertificateSHA256 && p.CertificateSHA256() != r.Correlation.BaselineSHA256
}
func validStage(a StageArtifact) bool {
	if a.Revision < 1 || !digest.MatchString(a.SettingsSHA256) || !digest.MatchString(a.CSRSHA256) || a.OtherStateSHA256 != "" && !digest.MatchString(a.OtherStateSHA256) || len(a.ChainDER) < 2 || len(a.ChainDER) > 8 || !bytes.Equal(a.LeafDER, a.ChainDER[0]) {
		return false
	}
	for _, der := range a.ChainDER {
		if len(der) == 0 || len(der) > 64<<10 {
			return false
		}
	}
	return true
}
func sameStage(a StageArtifact, p certpolicy.Result, settings string) bool {
	if a.SettingsSHA256 != settings || a.CSRSHA256 != p.CSRSHA256() || !bytes.Equal(a.LeafDER, p.LeafDER()) {
		return false
	}
	chain := p.ChainDER()
	if len(chain) != len(a.ChainDER) {
		return false
	}
	for i, der := range chain {
		if !bytes.Equal(der, a.ChainDER[i]) {
			return false
		}
	}
	return true
}
func readStage(ctx context.Context, q querier, id string) (StageArtifact, error) {
	var raw, settings string
	var rev int64
	if err := q.QueryRowContext(ctx, "SELECT settings_sha256,revision,record FROM staging_operations WHERE operation_id=?", id).Scan(&settings, &rev, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return StageArtifact{}, ErrState
		}
		return StageArtifact{}, ErrStore
	}
	var a StageArtifact
	if len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &a) != nil || !validStage(a) || a.SettingsSHA256 != settings || a.Revision != rev {
		return a, ErrStore
	}
	encoded, _ := json.Marshal(a)
	if raw != string(encoded) {
		return a, ErrStore
	}
	return a, nil
}
func (s *Store) PrepareStage(ctx context.Context, ref Ref, proof certpolicy.Result, settings string) (StageArtifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return StageArtifact{}, ErrStore
	}
	var result StageArtifact
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, q, err := s.stageMaterial(ctx, tx, ref)
		if err != nil {
			return err
		}
		if !digest.MatchString(settings) || !stageProof(r, q, proof) {
			return ErrCorrelation
		}
		q.LeafDER, q.ChainDER = proof.LeafDER(), proof.ChainDER()
		if staging.Validate(q) != nil {
			return ErrCorrelation
		}
		old, err := readStage(ctx, tx, r.ID)
		if err == nil {
			if !sameStage(old, proof, settings) {
				return ErrCorrelation
			}
			result = old
			return nil
		}
		if !errors.Is(err, ErrState) {
			return err
		}
		if r.State != CertReady {
			return ErrReconcile
		}
		result = StageArtifact{SettingsSHA256: settings, CSRSHA256: proof.CSRSHA256(), LeafDER: proof.LeafDER(), ChainDER: proof.ChainDER(), Revision: 1}
		raw, _ := json.Marshal(result)
		if _, err = tx.ExecContext(ctx, "INSERT INTO staging_operations(operation_id,settings_sha256,revision,record) VALUES(?,?,?,?)", r.ID, settings, 1, string(raw)); err != nil {
			return ErrStore
		}
		return nil
	})
	return result, err
}
func (s *Store) BindStageBaseline(ctx context.Context, ref Ref, a StageArtifact, other string) (StageArtifact, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return StageArtifact{}, ErrStore
	}
	if !digest.MatchString(other) {
		return StageArtifact{}, ErrCorrelation
	}
	var result StageArtifact
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, _, err := s.stageMaterial(ctx, tx, ref)
		if err != nil {
			return err
		}
		current, err := readStage(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		if current.Revision != a.Revision || current.SettingsSHA256 != a.SettingsSHA256 {
			return ErrConflict
		}
		if current.OtherStateSHA256 != "" {
			if current.OtherStateSHA256 != other {
				return ErrCorrelation
			}
			result = current
			return nil
		}
		if r.State != CertReady {
			return ErrReconcile
		}
		current.OtherStateSHA256 = other
		current.Revision++
		raw, _ := json.Marshal(current)
		res, err := tx.ExecContext(ctx, "UPDATE staging_operations SET revision=?,record=? WHERE operation_id=? AND revision=?", current.Revision, string(raw), ref.ID, a.Revision)
		if err != nil {
			return ErrStore
		}
		n, err := res.RowsAffected()
		if err != nil || n != 1 {
			return ErrConflict
		}
		result = current
		return nil
	})
	return result, err
}

// StageOnce is the runtime import boundary. The callback runs after durable
// IMPORTING and receives a recheck that does not recursively take Store locks.
// It must invoke recheck with fresh policy evidence immediately before writes.
func (s *Store) StageOnce(ctx context.Context, ref Ref, revision int64, proof certpolicy.Result, settings string, effect func(context.Context, Record, StageRecheck) (certpolicy.Result, error)) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, ErrStore
	}
	if effect == nil {
		return Record{}, ErrCorrelation
	}
	var claimed Record
	check := func(tx *sql.Tx, p certpolicy.Result) (Record, error) {
		r, q, err := s.stageMaterial(ctx, tx, ref)
		if err != nil {
			return r, err
		}
		a, err := readStage(ctx, tx, ref.ID)
		if err != nil {
			return r, err
		}
		if !stageProof(r, q, p) || !sameStage(a, p, settings) || !digest.MatchString(a.OtherStateSHA256) {
			return r, ErrCorrelation
		}
		return r, nil
	}
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, err := check(tx, proof)
		if err != nil {
			return err
		}
		if r.Revision != revision {
			return ErrConflict
		}
		if r.State == Importing {
			return ErrReconcile
		}
		if r.State != CertReady {
			return ErrState
		}
		claimed, err = save(ctx, tx, r, Importing, r.CertificateSHA256)
		return err
	})
	if err != nil {
		return claimed, err
	}
	recheck := func(c context.Context, p certpolicy.Result) error {
		if c.Err() != nil {
			return c.Err()
		}
		return s.transaction(c, func(tx *sql.Tx) error {
			current, err := check(tx, p)
			if err != nil {
				return err
			}
			if current.State != Importing || current.Revision != claimed.Revision {
				return ErrConflict
			}
			return nil
		})
	}
	if ctx.Err() != nil {
		return claimed, ErrReconcile
	}
	final, err := effect(ctx, claimed, recheck)
	if err != nil {
		return claimed, ErrReconcile
	}
	result := claimed
	err = s.transaction(ctx, func(tx *sql.Tx) error {
		current, err := check(tx, final)
		if err != nil {
			return err
		}
		if current.State != Importing || current.Revision != claimed.Revision {
			return ErrConflict
		}
		result, err = save(ctx, tx, current, Staged, current.CertificateSHA256)
		return err
	})
	return result, err
}

// ConfirmStage records only a complete independently observed prior intent.
// It cannot dispatch, reset IMPORTING, release ownership or alter artifacts.
func (s *Store) ConfirmStage(ctx context.Context, ref Ref, revision int64, proof certpolicy.Result, settings, other string) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, ErrStore
	}
	var result Record
	err := s.transaction(ctx, func(tx *sql.Tx) error {
		r, q, err := s.stageMaterial(ctx, tx, ref)
		if err != nil {
			return err
		}
		a, err := readStage(ctx, tx, ref.ID)
		if err != nil {
			return err
		}
		if r.Revision != revision {
			return ErrConflict
		}
		if !stageProof(r, q, proof) || !sameStage(a, proof, settings) || !digest.MatchString(other) || a.OtherStateSHA256 != other {
			return ErrCorrelation
		}
		if r.State == Staged {
			result = r
			return nil
		}
		if r.State != Importing {
			return ErrReconcile
		}
		result, err = save(ctx, tx, r, Staged, r.CertificateSHA256)
		return err
	})
	return result, err
}
func (s *Store) checkStageStorage(ctx context.Context) error {
	var missing int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM operations o JOIN csr_operations c ON c.operation_id=o.id LEFT JOIN staging_operations st ON st.operation_id=o.id WHERE o.state IN ('IMPORTING','STAGED') AND st.operation_id IS NULL").Scan(&missing); err != nil || missing != 0 {
		return ErrStore
	}
	rows, err := s.db.QueryContext(ctx, "SELECT st.operation_id,st.settings_sha256,st.revision,st.record,c.csr_der,o.certificate_sha256,o.state FROM staging_operations st LEFT JOIN csr_operations c ON c.operation_id=st.operation_id LEFT JOIN operations o ON o.id=st.operation_id")
	if err != nil {
		return ErrStore
	}
	defer rows.Close()
	for rows.Next() {
		var id, settings, raw, leafHash string
		var revision int64
		var csrDER []byte
		var state State
		var a StageArtifact
		if rows.Scan(&id, &settings, &revision, &raw, &csrDER, &leafHash, &state) != nil || !canonicalID(id) || len(raw) > 1<<20 || json.Unmarshal([]byte(raw), &a) != nil || !validStage(a) || a.SettingsSHA256 != settings || a.Revision != revision || a.CSRSHA256 != certpolicy.SHA256(csrDER) || certpolicy.SHA256(a.LeafDER) != leafHash || state != CertReady && state != Importing && state != Staged || state != CertReady && !digest.MatchString(a.OtherStateSHA256) {
			return ErrStore
		}
		encoded, _ := json.Marshal(a)
		if string(encoded) != raw {
			return ErrStore
		}
	}
	if rows.Err() != nil {
		return ErrStore
	}
	return nil
}

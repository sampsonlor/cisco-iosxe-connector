package journal

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store is shared by all API and worker entry points in one active process.
// The OS lock is on the database file itself, not a deletable PID/lease file.
type Store struct {
	db        *sql.DB
	file      *os.File
	services  map[string]Service
	mu        sync.RWMutex
	closed    bool
	acmeMu    sync.Mutex
	acmeJobs  map[string]bool
	dnsMu     sync.Mutex
	dnsJobs   map[string]bool
	stageMu   sync.Mutex
	stageJobs map[string]bool
}

func Open(path string, services []Service) (*Store, error) {
	s := &Store{services: map[string]Service{}}
	seenDevices, seenTargets := map[string]bool{}, map[string]bool{}
	for _, p := range services {
		if !validService(p) || s.services[p.LocationID].LocationID != "" || seenDevices[p.DeviceID] || seenTargets[p.Target] {
			return nil, ErrCorrelation
		}
		p.StagingTrustpoints = slices.Clone(p.StagingTrustpoints)
		slices.Sort(p.StagingTrustpoints)
		s.services[p.LocationID] = p
		seenDevices[p.DeviceID] = true
		seenTargets[p.Target] = true
	}
	if len(s.services) == 0 || !filepath.IsAbs(path) || strings.HasPrefix(filepath.ToSlash(path), "//") || strings.ContainsAny(path, "?\x00") {
		return nil, ErrStore
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, ErrStore
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, ErrStore
	}
	path = filepath.Join(parent, filepath.Base(path))
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, ErrStore
	}
	s.file, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, ErrStore
	}
	info, err := s.file.Stat()
	named, namedErr := os.Stat(path)
	if err != nil || namedErr != nil || !info.Mode().IsRegular() || !os.SameFile(info, named) {
		_ = s.file.Close()
		return nil, ErrStore
	}
	if err = lockInstance(s.file); err != nil {
		_ = s.file.Close()
		return nil, err
	}
	fail := func(err error) (*Store, error) {
		if s.db != nil {
			_ = s.db.Close()
		}
		_ = s.file.Close()
		return nil, err
	}
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{}
	for _, pragma := range []string{"synchronous(FULL)", "busy_timeout(100)", "foreign_keys(ON)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	s.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return fail(ErrStore)
	}
	s.db.SetMaxOpenConns(1)
	if err = s.initialize(); err != nil {
		return fail(err)
	}
	return s, nil
}

// Close waits for all dispatched callbacks, including completion recording,
// before releasing instance ownership. It must not be called by a callback.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := s.db.Close(); err != nil {
		return ErrStore
	}
	s.closed = true
	if err := s.file.Close(); err != nil {
		return ErrStore
	}
	return nil
}

func (s *Store) initialize() error {
	ctx := context.Background()
	const applicationID = 0x49584a4c
	var app, version int
	if err := s.db.QueryRow("PRAGMA application_id").Scan(&app); err != nil {
		return ErrStore
	}
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return ErrStore
	}
	if app != applicationID || (version != 1 && version != 2 && version != 3 && version != 4 && version != 5) {
		if app != 0 || version != 0 {
			return ErrStore
		}
		var count int
		if err := s.db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&count); err != nil || count != 0 {
			return ErrStore
		}
		if err := s.transaction(ctx, func(tx *sql.Tx) error {
			for _, statement := range []string{
				"CREATE TABLE services (location_id TEXT PRIMARY KEY, configuration TEXT NOT NULL)",
				"CREATE TABLE operations (id TEXT PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, location_id TEXT NOT NULL REFERENCES services(location_id), correlation TEXT NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), certificate_sha256 TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)",
				"CREATE UNIQUE INDEX one_unfinished_service ON operations(location_id) WHERE state <> 'FAILED_NO_SWITCH'",
				"CREATE TABLE events (operation_id TEXT NOT NULL REFERENCES operations(id), revision INTEGER NOT NULL, from_state TEXT NOT NULL, to_state TEXT NOT NULL, certificate_sha256 TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY(operation_id,revision))",
				fmt.Sprintf("PRAGMA application_id=%d", applicationID), "PRAGMA user_version=1",
			} {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return ErrStore
				}
			}
			return nil
		}); err != nil {
			return err
		}
		version = 1
	}
	if version == 1 {
		if err := s.transaction(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "CREATE TABLE csr_operations (operation_id TEXT PRIMARY KEY REFERENCES operations(id), specification TEXT NOT NULL, key_label TEXT NOT NULL UNIQUE, csr_der BLOB NOT NULL, public_key_der BLOB NOT NULL)"); err != nil {
				return ErrStore
			}
			if _, err := tx.ExecContext(ctx, "PRAGMA user_version=2"); err != nil {
				return ErrStore
			}
			return nil
		}); err != nil {
			return err
		}
		version = 2
	}
	if version == 2 {
		if err := s.transaction(ctx, func(tx *sql.Tx) error {
			for _, statement := range []string{
				"CREATE TABLE acme_accounts (binding_id TEXT PRIMARY KEY, configuration TEXT NOT NULL, account_url TEXT NOT NULL)",
				"CREATE TABLE acme_operations (operation_id TEXT PRIMARY KEY REFERENCES operations(id), binding_id TEXT NOT NULL REFERENCES acme_accounts(binding_id), revision INTEGER NOT NULL CHECK(revision>0), record TEXT NOT NULL)",
				"PRAGMA user_version=3",
			} {
				if _, err := tx.ExecContext(ctx, statement); err != nil {
					return ErrStore
				}
			}
			return nil
		}); err != nil {
			return err
		}
		version = 3
	}
	if version == 3 {
		if err := s.transaction(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "CREATE TABLE dns_claims (claim_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL REFERENCES operations(id), revision INTEGER NOT NULL CHECK(revision>0), state TEXT NOT NULL, record TEXT NOT NULL)"); err != nil {
				return ErrStore
			}
			if _, err := tx.ExecContext(ctx, "PRAGMA user_version=4"); err != nil {
				return ErrStore
			}
			return nil
		}); err != nil {
			return err
		}
		version = 4
	}
	if version == 4 {
		if err := s.transaction(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, "CREATE TABLE staging_operations (operation_id TEXT PRIMARY KEY REFERENCES operations(id), settings_sha256 TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), record TEXT NOT NULL)"); err != nil {
				return ErrStore
			}
			if _, err := tx.ExecContext(ctx, "PRAGMA user_version=5"); err != nil {
				return ErrStore
			}
			return nil
		}); err != nil {
			return err
		}
	}
	var mode, integrity string
	var syncMode int
	if err := s.db.QueryRow("PRAGMA journal_mode=WAL").Scan(&mode); err != nil || mode != "wal" {
		return ErrStore
	}
	if err := s.db.QueryRow("PRAGMA synchronous").Scan(&syncMode); err != nil || syncMode != 2 {
		return ErrStore
	}
	if err := s.db.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil || integrity != "ok" {
		return ErrStore
	}
	var detached int
	if err := s.db.QueryRow(`SELECT count(*) FROM operations o
		WHERE o.revision <> (SELECT count(*) FROM events e WHERE e.operation_id=o.id)
		OR NOT EXISTS (SELECT 1 FROM events e WHERE e.operation_id=o.id
		AND e.revision=o.revision AND e.to_state=o.state
		AND e.certificate_sha256=o.certificate_sha256)
		OR NOT EXISTS (SELECT 1 FROM events e WHERE e.operation_id=o.id
		AND e.revision=1 AND e.from_state='' AND e.to_state='PRECHECK')`).Scan(&detached); err != nil || detached != 0 {
		return ErrStore
	}
	if err := s.checkCSRStorage(ctx); err != nil {
		return err
	}
	if err := s.checkACMEStorage(ctx); err != nil {
		return err
	}
	if err := s.checkDNSStorage(ctx); err != nil {
		return err
	}
	if err := s.checkStageStorage(ctx); err != nil {
		return err
	}
	return s.transaction(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, "SELECT location_id,configuration FROM services")
		if err != nil {
			return ErrStore
		}
		stored := map[string]Service{}
		for rows.Next() {
			var id, raw string
			var p Service
			if err := rows.Scan(&id, &raw); err != nil {
				_ = rows.Close()
				return ErrStore
			}
			if json.Unmarshal([]byte(raw), &p) != nil || !validService(p) || id != p.LocationID {
				_ = rows.Close()
				return ErrStore
			}
			stored[id] = p
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			return ErrStore
		}
		for id, old := range stored {
			var pending int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE location_id=? AND state<>?", id, FailedNoSwitch).Scan(&pending); err != nil {
				return ErrStore
			}
			current, present := s.services[id]
			if !present {
				if pending > 0 {
					return ErrConflict
				}
				continue
			}
			// Policy/owner can change only without unfinished work. Device identity
			// changes need an explicit migration, never an implicit redirect.
			if current.EntityID != old.EntityID || current.DeviceID != old.DeviceID || current.Target != old.Target || current.HostKeySHA256 != old.HostKeySHA256 {
				return ErrConflict
			}
			if pending > 0 && (current.Binding != old.Binding || !slices.Equal(current.StagingTrustpoints, old.StagingTrustpoints)) {
				return ErrConflict
			}
		}
		for id, p := range s.services {
			raw, _ := json.Marshal(p)
			if _, err := tx.ExecContext(ctx, "INSERT INTO services(location_id,configuration) VALUES(?,?) ON CONFLICT(location_id) DO UPDATE SET configuration=excluded.configuration", id, string(raw)); err != nil {
				return ErrStore
			}
		}
		rows, err = tx.QueryContext(ctx, "SELECT "+recordColumns+" FROM operations")
		if err != nil {
			return ErrStore
		}
		defer rows.Close()
		for rows.Next() {
			r, err := readRecord(rows)
			if err != nil {
				return err
			}
			if r.State != FailedNoSwitch && !s.approved(r.Correlation) {
				return ErrConflict
			}
		}
		if rows.Err() != nil {
			return ErrStore
		}
		return nil
	})
}

func (s *Store) transaction(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrStore
	}
	defer tx.Rollback()
	if err = f(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return ErrStore
	}
	return nil
}

const recordColumns = "id,request_id,location_id,correlation,state,revision,certificate_sha256,created_at,updated_at"

type scanner interface{ Scan(...any) error }
type querier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func readRecord(row scanner) (r Record, err error) {
	var location, raw string
	var created, updated int64
	err = row.Scan(&r.ID, &r.RequestID, &location, &raw, &r.State, &r.Revision, &r.CertificateSHA256, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrCorrelation
	}
	if err != nil {
		return r, ErrStore
	}
	if json.Unmarshal([]byte(raw), &r.Correlation) != nil || location != r.Correlation.LocationID || !canonicalID(r.ID) || !canonicalID(r.RequestID) || !validState(r.State) || r.Revision < 1 || created <= 0 || updated < created {
		return Record{}, ErrStore
	}
	if (r.State == CertReady || r.State == Importing || r.State == Staged) && !digest.MatchString(r.CertificateSHA256) {
		return Record{}, ErrStore
	}
	r.CreatedAt = time.UnixMilli(created).UTC()
	r.UpdatedAt = time.UnixMilli(updated).UTC()
	return r, nil
}
func (s *Store) authorized(ctx context.Context, q querier, ref Ref) (Record, error) {
	if !canonicalID(ref.ID) || !s.approved(ref.Correlation) {
		return Record{}, ErrCorrelation
	}
	r, err := readRecord(q.QueryRowContext(ctx, "SELECT "+recordColumns+" FROM operations WHERE id=?", ref.ID))
	if err != nil {
		return Record{}, err
	}
	if r.Correlation != ref.Correlation {
		return Record{}, ErrCorrelation
	}
	return r, nil
}
func (s *Store) Get(ctx context.Context, ref Ref) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, ErrStore
	}
	return s.authorized(ctx, s.db, ref)
}
func (s *Store) Pending(ctx context.Context) ([]Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStore
	}
	rows, err := s.db.QueryContext(ctx, "SELECT "+recordColumns+" FROM operations WHERE state<>? ORDER BY created_at,id", FailedNoSwitch)
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		r, err := readRecord(rows)
		if err != nil {
			return nil, err
		}
		if !s.approved(r.Correlation) {
			return nil, ErrCorrelation
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return out, nil
}
func (s *Store) History(ctx context.Context, ref Ref) ([]Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrStore
	}
	if _, err := s.authorized(ctx, s.db, ref); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, "SELECT revision,from_state,to_state,certificate_sha256,at FROM events WHERE operation_id=? ORDER BY revision", ref.ID)
	if err != nil {
		return nil, ErrStore
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var at int64
		if err := rows.Scan(&e.Revision, &e.From, &e.To, &e.CertificateSHA256, &at); err != nil {
			return nil, ErrStore
		}
		e.At = time.UnixMilli(at).UTC()
		out = append(out, e)
	}
	if rows.Err() != nil {
		return nil, ErrStore
	}
	return out, nil
}

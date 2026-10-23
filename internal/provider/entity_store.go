package provider

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"modernc.org/sqlite"
)

var (
	errEntityMissing  = errors.New("entity not found")
	errEntityConflict = errors.New("entity binding conflict")
)

type entityRecord struct{ ID, Name, DeviceID, Target string }

// EntityStore persists metadata only. Device-operation intent and locks belong
// to the later lifecycle journal, not this table.
type EntityStore struct{ db *sql.DB }

func OpenEntityStore(path string) (*EntityStore, error) {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "?\x00") {
		return nil, errors.New("an absolute local database path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, errors.New("entity database directory unavailable")
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("entity database must be a regular file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, errors.New("entity database file unavailable")
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	p := filepath.ToSlash(path)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u := url.URL{Scheme: "file", Path: p}
	q := url.Values{}
	for _, pragma := range []string{"journal_mode(WAL)", "synchronous(FULL)", "busy_timeout(3000)", "foreign_keys(ON)"} {
		q.Add("_pragma", pragma)
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, errors.New("entity database open failed")
	}
	db.SetMaxOpenConns(1)
	store := &EntityStore{db: db}
	if err := store.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}
func (s *EntityStore) Close() error { return s.db.Close() }
func (s *EntityStore) initialize() error {
	ctx := context.Background()
	var mode string
	var sync, app, version int
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return errors.New("entity database unreadable")
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA synchronous").Scan(&sync); err != nil || mode != "wal" || sync != 2 {
		return errors.New("entity database durability settings unavailable")
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&app); err != nil {
		return err
	}
	if err := s.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	const applicationID = 0x49584543
	if app == applicationID && version == 1 {
		return nil
	}
	if app != 0 || version != 0 {
		return errors.New("unsupported entity database schema")
	}
	var tables int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&tables); err != nil || tables != 0 {
		return errors.New("entity database is not empty")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, statement := range []string{
		"CREATE TABLE entities (uuid TEXT PRIMARY KEY, name TEXT NOT NULL, device_id TEXT NOT NULL UNIQUE, target TEXT NOT NULL UNIQUE)",
		"PRAGMA application_id=1230521667", "PRAGMA user_version=1",
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return errors.New("entity schema initialization failed")
		}
	}
	return tx.Commit()
}
func (s *EntityStore) get(ctx context.Context, id string) (entityRecord, error) {
	var r entityRecord
	err := s.db.QueryRowContext(ctx, "SELECT uuid,name,device_id,target FROM entities WHERE uuid=?", id).Scan(&r.ID, &r.Name, &r.DeviceID, &r.Target)
	if errors.Is(err, sql.ErrNoRows) {
		err = errEntityMissing
	}
	return r, err
}
func (s *EntityStore) list(ctx context.Context) ([]entityRecord, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT uuid,name,device_id,target FROM entities ORDER BY uuid")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]entityRecord, 0)
	for rows.Next() {
		var r entityRecord
		if err := rows.Scan(&r.ID, &r.Name, &r.DeviceID, &r.Target); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (s *EntityStore) create(ctx context.Context, r entityRecord) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO entities(uuid,name,device_id,target) VALUES(?,?,?,?)", r.ID, r.Name, r.DeviceID, r.Target)
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code()&255 == 19 {
		return errEntityConflict
	}
	return err
}
func affected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return errEntityMissing
	}
	return err
}
func (s *EntityStore) rename(ctx context.Context, r entityRecord) error {
	return affected(s.db.ExecContext(ctx, "UPDATE entities SET name=? WHERE uuid=? AND device_id=? AND target=?", r.Name, r.ID, r.DeviceID, r.Target))
}
func (s *EntityStore) remove(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, "DELETE FROM entities WHERE uuid=?", id))
}

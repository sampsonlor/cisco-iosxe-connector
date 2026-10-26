package journal

import (
	"context"
	"database/sql"
	"errors"
)

// NativeBinding validates trusted host configuration against the current service
// registry. Both API and worker entry points must use this one Store instance.
func (s *Store) NativeBinding(ctx context.Context, c Correlation) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return ErrStore
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if c.Owner != ILMCore || !s.approved(c) {
		return ErrCorrelation
	}
	return nil
}

// ResolveNative reads an untrusted UUID only inside a server-selected scope.
// The full correlation is recovered from durable storage and checked against
// current approval; the UUID is never promoted to an authorization capability.
func (s *Store) ResolveNative(ctx context.Context, b Binding, id string) (Record, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, ErrStore
	}
	p, ok := s.services[b.LocationID]
	if b.Owner != ILMCore || !ok || p.Binding != b || !canonicalID(id) {
		return Record{}, ErrCorrelation
	}
	r, err := readRecord(s.db.QueryRowContext(ctx, "SELECT "+recordColumns+" FROM operations WHERE id=?", id))
	if err != nil {
		return Record{}, err
	}
	if r.Correlation.Binding != b || !s.approved(r.Correlation) || r.State == FailedNoSwitch {
		return Record{}, ErrCorrelation
	}
	return r, nil
}

// NativeCertificate preserves Core's per-certificate CSR/push attributes during
// inventory synchronization. It proves association only, never live key presence.
func (s *Store) NativeCertificate(ctx context.Context, b Binding, sha string) (Record, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Record{}, false, ErrStore
	}
	p, ok := s.services[b.LocationID]
	if !ok || p.Binding != b || b.Owner != ILMCore || !digest.MatchString(sha) {
		return Record{}, false, ErrCorrelation
	}
	var id string
	err := s.db.QueryRowContext(ctx, "SELECT id FROM operations WHERE location_id=? AND certificate_sha256=? AND state=?", b.LocationID, sha, Staged).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, ErrStore
	}
	r, err := readRecord(s.db.QueryRowContext(ctx, "SELECT "+recordColumns+" FROM operations WHERE id=?", id))
	if err != nil {
		return Record{}, false, err
	}
	if r.Correlation.Binding != b || !s.approved(r.Correlation) {
		return Record{}, false, ErrCorrelation
	}
	return r, true, nil
}

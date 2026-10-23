package provider

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestEntityStoreDurabilityAndSchema(t *testing.T) {
	foreignPath := filepath.Join(t.TempDir(), "foreign.sqlite")
	foreign, err := sql.Open("sqlite", foreignPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Exec("CREATE TABLE other_application (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	if err := foreign.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(foreignPath)
	if err != nil {
		t.Fatal(err)
	}
	if accepted, err := OpenEntityStore(foreignPath); err == nil {
		_ = accepted.Close()
		t.Fatal("foreign database accepted")
	}
	after, err := os.ReadFile(foreignPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected foreign database was modified")
	}
	path := filepath.Join(t.TempDir(), "entities.sqlite")
	s, err := OpenEntityStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var mode string
	var sync int
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("WAL not active: %q %v", mode, err)
	}
	if err := s.db.QueryRow("PRAGMA synchronous").Scan(&sync); err != nil || sync != 2 {
		t.Fatalf("FULL sync not active: %d %v", sync, err)
	}
	if _, err := s.db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if reopened, err := OpenEntityStore(path); err == nil {
		_ = reopened.Close()
		t.Fatal("future schema was silently accepted")
	}
	if _, err := OpenEntityStore("relative.sqlite"); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestEntityStoreWriteFailureAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entities.sqlite")
	s, err := OpenEntityStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r := entityRecord{ID: "11111111-2222-4333-8444-555555555555", Name: "original", DeviceID: "router-a", Target: "192.0.2.10"}
	if err := s.create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	r.Name = "failed rename"
	if err := s.rename(context.Background(), r); err == nil {
		t.Fatal("write denial was ignored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.remove(ctx, r.ID); err == nil {
		t.Fatal("cancelled delete was accepted")
	}
	_ = s.Close()
	s, err = OpenEntityStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	got, err := s.get(context.Background(), r.ID)
	if err != nil || got.Name != "original" {
		t.Fatalf("failed write corrupted persistent entity: %+v %v", got, err)
	}
}

package journal

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func approved() Service {
	entity := "11111111-2222-4333-8444-555555555555"
	return Service{Binding: Binding{EntityID: entity, LocationID: uuid.NewSHA1(uuid.NameSpaceURL, []byte("iosxe:"+entity+":https")).String(), DeviceID: "router-a", Target: "192.0.2.10", HostKeySHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), PolicySHA256: strings.Repeat("a", 64), Owner: ILMCore}, StagingTrustpoints: []string{"HTTPS-STAGE-A", "HTTPS-STAGE-B"}}
}
func correlation() Correlation {
	return Correlation{Binding: approved().Binding, ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: strings.Repeat("b", 64), StagingTrustpoint: "HTTPS-STAGE-A"}
}
func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journal.sqlite")
	s, err := Open(path, []Service{approved()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}
func begin(t *testing.T, s *Store) Record {
	t.Helper()
	r, err := s.Begin(context.Background(), uuid.NewString(), correlation())
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func ready(t *testing.T, s *Store) Record {
	t.Helper()
	r := begin(t, s)
	for _, state := range []State{KeyCreating, CSRReady, AwaitingIssuance} {
		var err error
		r, err = s.Progress(context.Background(), r.Ref(), r.Revision, state)
		if err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.CertificateReady(context.Background(), r.Ref(), r.Revision, strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServiceLockAndOwnerPolicy(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	c := correlation()
	c.Owner = ACMEWorker
	if _, err := s.Begin(ctx, uuid.NewString(), c); !errors.Is(err, ErrCorrelation) {
		t.Fatal("conflicting renewal owner accepted", err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Begin(ctx, uuid.NewString(), correlation()); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, ErrBusy) {
				t.Errorf("unexpected contender result: %v", err)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("more than one operation acquired HTTPS service", wins.Load())
	}
	pending, err := s.Pending(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatal("pending lock not durable", err)
	}
	r := pending[0]
	if _, err := s.Progress(ctx, r.Ref(), r.Revision, Staged); !errors.Is(err, ErrState) {
		t.Fatal("arbitrary stage completion accepted", err)
	}
	if _, err := s.AbortPrecheck(ctx, r.Ref(), r.Revision+1); !errors.Is(err, ErrConflict) {
		t.Fatal("stale CAS accepted", err)
	}
	if _, err := s.AbortPrecheck(ctx, r.Ref(), r.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Begin(ctx, uuid.NewString(), correlation()); err != nil {
		t.Fatal("safe precheck abort did not release lock", err)
	}
}

func TestDurableCorrelationRejectsReplay(t *testing.T) {
	s, path := openTest(t)
	ctx := context.Background()
	r := begin(t, s)
	again, err := s.Begin(ctx, r.RequestID, correlation())
	if err != nil || again.ID != r.ID {
		t.Fatal("request retry changed operation", err)
	}
	if r.ID == r.RequestID || uuid.MustParse(r.ID).Version() != 4 {
		t.Fatal("operation ID was not server-generated")
	}
	for name, change := range map[string]func(*Ref){
		"fabricated": func(ref *Ref) { ref.ID = uuid.NewString() },
		"location":   func(ref *Ref) { ref.Correlation.LocationID = uuid.NewString() },
		"entity":     func(ref *Ref) { ref.Correlation.EntityID = uuid.NewString() },
		"device":     func(ref *Ref) { ref.Correlation.DeviceID = "router-b" },
		"address":    func(ref *Ref) { ref.Correlation.Target = "192.0.2.11" },
		"host-key": func(ref *Ref) {
			ref.Correlation.HostKeySHA256 = "SHA256:" + base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
		},
		"policy":   func(ref *Ref) { ref.Correlation.PolicySHA256 = strings.Repeat("d", 64) },
		"baseline": func(ref *Ref) { ref.Correlation.BaselineSHA256 = strings.Repeat("d", 64) },
		"owner":    func(ref *Ref) { ref.Correlation.Owner = ACMEWorker },
		"active":   func(ref *Ref) { ref.Correlation.ActiveTrustpoint = "OTHER" },
		"stage":    func(ref *Ref) { ref.Correlation.StagingTrustpoint = "HTTPS-STAGE-B" },
	} {
		t.Run(name, func(t *testing.T) {
			ref := r.Ref()
			change(&ref)
			if _, err := s.Get(ctx, ref); !errors.Is(err, ErrCorrelation) {
				t.Fatal("forged correlation accepted", err)
			}
			var called bool
			_, err := s.ImportOnce(ctx, ref, strings.Repeat("c", 64), func(context.Context, Record) error { called = true; return nil })
			if err == nil || called {
				t.Fatal("forgery reached effect")
			}
		})
	}
	c := correlation()
	c.BaselineSHA256 = strings.Repeat("d", 64)
	if _, err := s.Begin(ctx, r.RequestID, c); !errors.Is(err, ErrCorrelation) {
		t.Fatal("reused request ID changed baseline", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, []Service{approved()})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.Get(ctx, r.Ref())
	if err != nil || got != r {
		t.Fatal("restart lost correlation", err)
	}
	if _, err := reopened.Begin(ctx, uuid.NewString(), correlation()); !errors.Is(err, ErrBusy) {
		t.Fatal("restart expired service lock", err)
	}
	if _, err := reopened.Progress(ctx, r.Ref(), r.Revision, KeyCreating); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Progress(ctx, r.Ref(), r.Revision, KeyCreating); !errors.Is(err, ErrConflict) {
		t.Fatal("stale revision replay accepted", err)
	}
	if _, err := reopened.AbortPrecheck(ctx, r.Ref(), r.Revision+1); !errors.Is(err, ErrState) {
		t.Fatal("in-progress key intent unlocked without reconciliation", err)
	}
}

func TestJournalStorageFailuresBlockEffects(t *testing.T) {
	for _, mode := range []string{"read-only", "disk-full", "writer-lock", "cancelled", "closed"} {
		t.Run(mode, func(t *testing.T) {
			s, path := openTest(t)
			r := ready(t, s)
			ctx := context.Background()
			var external *sql.DB
			var tx *sql.Tx
			switch mode {
			case "read-only":
				if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
					t.Fatal(err)
				}
			case "disk-full":
				for _, statement := range []string{"CREATE TABLE disk_pressure (payload BLOB)", "CREATE TRIGGER import_disk_pressure AFTER UPDATE ON operations WHEN NEW.state='IMPORTING' BEGIN INSERT INTO disk_pressure VALUES(zeroblob(1048576)); END"} {
					if _, err := s.db.Exec(statement); err != nil {
						t.Fatal(err)
					}
				}
				var pages int
				if err := s.db.QueryRow("PRAGMA page_count").Scan(&pages); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); err != nil {
					t.Fatal(err)
				}
			case "writer-lock":
				var err error
				external, err = sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer external.Close()
				tx, err = external.Begin()
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback()
				if _, err = tx.Exec("UPDATE operations SET revision=revision"); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var calls int
			if _, err := s.ImportOnce(ctx, r.Ref(), r.CertificateSHA256, func(context.Context, Record) error { calls++; return nil }); err == nil || calls != 0 {
				t.Fatal("uncommitted intent permitted import", mode, err)
			}
			if tx != nil {
				_ = tx.Rollback()
			}
			if mode != "closed" {
				got, err := s.Get(context.Background(), r.Ref())
				if err != nil || got.State != CertReady || got.Revision != r.Revision {
					t.Fatal("failed intent changed durable state", err)
				}
			}
		})
	}
}

func TestUncertainImportIsNeverRedispatched(t *testing.T) {
	for _, mode := range []string{"device-error", "completion-write-error"} {
		t.Run(mode, func(t *testing.T) {
			s, path := openTest(t)
			r := ready(t, s)
			var calls int
			_, err := s.ImportOnce(context.Background(), r.Ref(), r.CertificateSHA256, func(context.Context, Record) error {
				calls++
				if mode == "device-error" {
					return errors.New("private diagnostic must not leak")
				}
				_, err := s.db.Exec("PRAGMA query_only=ON")
				return err
			})
			if err == nil || strings.Contains(err.Error(), "private diagnostic") || calls != 1 {
				t.Fatal("uncertainty suppressed or leaked", err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path, []Service{approved()})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			got, err := reopened.ImportOnce(context.Background(), r.Ref(), r.CertificateSHA256, func(context.Context, Record) error { calls++; return nil })
			if !errors.Is(err, ErrReconcile) || got.State != Importing || calls != 1 {
				t.Fatal("uncertain import was retried", err, calls)
			}
			if _, err := reopened.Begin(context.Background(), uuid.NewString(), correlation()); !errors.Is(err, ErrBusy) {
				t.Fatal("uncertain operation unlocked", err)
			}
		})
	}
}

func TestSingleInstanceCrashAndWALRecovery(t *testing.T) {
	if os.Getenv("IOSXE_JOURNAL_TEST_CHILD") == "1" {
		s, err := Open(os.Getenv("IOSXE_JOURNAL_TEST_PATH"), []Service{approved()})
		if err != nil {
			t.Fatal(err)
		}
		r := ready(t, s)
		_, _ = s.ImportOnce(context.Background(), r.Ref(), r.CertificateSHA256, func(context.Context, Record) error { fmt.Println("READY"); select {} })
		return
	}
	path := filepath.Join(t.TempDir(), "journal.sqlite")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, exe, "-test.run=^TestSingleInstanceCrashAndWALRecovery$")
	child.Env = append(os.Environ(), "IOSXE_JOURNAL_TEST_CHILD=1", "IOSXE_JOURNAL_TEST_PATH="+path)
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var diagnostic bytes.Buffer
	child.Stderr = &diagnostic
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "READY" {
		t.Fatalf("child did not persist import intent: %v %s %s", err, line, &diagnostic)
	}
	if second, err := Open(path, []Service{approved()}); !errors.Is(err, ErrInstance) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("second active instance admitted", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	s, err := Open(path, []Service{approved()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var mode string
	var syncMode int
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil || mode != "wal" {
		t.Fatal("WAL not active", mode, err)
	}
	if err := s.db.QueryRow("PRAGMA synchronous").Scan(&syncMode); err != nil || syncMode != 2 {
		t.Fatal("FULL sync not active", syncMode, err)
	}
	list, err := s.Pending(context.Background())
	if err != nil || len(list) != 1 || list[0].State != Importing {
		t.Fatal("crash lost unresolved intent", err)
	}
	r := list[0]
	calls := 0
	if _, err := s.ImportOnce(context.Background(), r.Ref(), r.CertificateSHA256, func(context.Context, Record) error { calls++; return nil }); !errors.Is(err, ErrReconcile) || calls != 0 {
		t.Fatal("crash triggered blind import retry", err)
	}
	history, err := s.History(context.Background(), r.Ref())
	if err != nil || len(history) != 6 || history[5].To != Importing {
		t.Fatal("atomic history lost on restart", len(history), err)
	}
}

func TestJournalSchemaPolicyAndInstanceLifetime(t *testing.T) {
	s, path := openTest(t)
	r := begin(t, s)
	for _, change := range []func(*Service){func(p *Service) { p.Owner = ACMEWorker }, func(p *Service) { p.PolicySHA256 = strings.Repeat("d", 64) }, func(p *Service) { p.StagingTrustpoints = []string{"OTHER"} }} {
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		p := approved()
		change(&p)
		if changed, err := Open(path, []Service{p}); !errors.Is(err, ErrConflict) {
			if changed != nil {
				_ = changed.Close()
			}
			t.Fatal("pending policy was replaced", err)
		}
		var err error
		s, err = Open(path, []Service{approved()})
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AbortPrecheck(context.Background(), r.Ref(), r.Revision); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	p := approved()
	p.Owner = ACMEWorker
	p.PolicySHA256 = strings.Repeat("d", 64)
	s, err := Open(path, []Service{p})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Get(context.Background(), r.Ref()); !errors.Is(err, ErrCorrelation) {
		t.Fatal("old owner/policy reference accepted", err)
	}
	if _, err := s.db.Exec("PRAGMA user_version=99"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if future, err := Open(path, []Service{p}); err == nil {
		_ = future.Close()
		t.Fatal("unknown schema accepted")
	}
	foreignPath := filepath.Join(t.TempDir(), "foreign.sqlite")
	foreign, err := sql.Open("sqlite", foreignPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Exec("CREATE TABLE other_application (value TEXT)"); err != nil {
		t.Fatal(err)
	}
	_ = foreign.Close()
	before, _ := os.ReadFile(foreignPath)
	if foreign, err := Open(foreignPath, []Service{approved()}); err == nil {
		_ = foreign.Close()
		t.Fatal("foreign database accepted")
	}
	after, _ := os.ReadFile(foreignPath)
	if !bytes.Equal(before, after) {
		t.Fatal("foreign database modified")
	}
	if relative, err := Open("relative.sqlite", []Service{approved()}); err == nil {
		_ = relative.Close()
		t.Fatal("relative path accepted")
	}
}

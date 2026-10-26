package lifecycle_test

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
	"path/filepath"
	"strings"
	"testing"
)

type unknownCSRDevice struct{ writes, reads int }

func (d *unknownCSRDevice) Generate(context.Context, csr.Request) (csr.Result, error) {
	d.writes++
	return csr.Result{}, context.DeadlineExceeded
}
func (d *unknownCSRDevice) Inspect(context.Context, csr.Request) error { d.reads++; return nil }
func TestUnknownCSRUsesReadOnlyReconciliation(t *testing.T) {
	entity := uuid.NewString()
	b := journal.Binding{EntityID: entity, LocationID: provider.HTTPSLocationID(entity), DeviceID: "router-a", Target: "192.0.2.10", HostKeySHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), PolicySHA256: strings.Repeat("a", 64), Owner: journal.ILMCore}
	s, err := journal.Open(filepath.Join(t.TempDir(), "journal.sqlite"), []journal.Service{{Binding: b, StagingTrustpoints: []string{"HTTPS-STAGE-A"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.Begin(context.Background(), uuid.NewString(), journal.Correlation{Binding: b, ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: strings.Repeat("b", 64), StagingTrustpoint: "HTTPS-STAGE-A"})
	if err != nil {
		t.Fatal(err)
	}
	device := &unknownCSRDevice{}
	gate, err := lifecycle.NewCSRGate(s, device)
	if err != nil {
		t.Fatal(err)
	}
	spec := csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test"}, RSABits: 2048}
	for range 2 {
		if _, _, err := gate.Generate(context.Background(), r.Ref(), spec); !errors.Is(err, journal.ErrReconcile) {
			t.Fatal("unknown generation was not retained", err)
		}
	}
	if err := gate.Reconcile(context.Background(), r.Ref()); !errors.Is(err, journal.ErrReconcile) || device.writes != 1 || device.reads != 1 {
		t.Fatal("reconciliation repeated writes or released uncertainty", err)
	}
}

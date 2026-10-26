package lifecycle_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
)

func stageMust(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type stageBackend struct {
	mu              sync.Mutex
	obs             staging.Observation
	imports, reads  int
	lost, partial   bool
	entered, finish chan struct{}
	before          func()
}

func (b *stageBackend) Inspect(ctx context.Context, _ staging.Request) (staging.Observation, error) {
	if err := ctx.Err(); err != nil {
		return staging.Observation{}, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reads++
	return b.obs, nil
}
func (b *stageBackend) Import(ctx context.Context, q staging.Request, authorize func(context.Context) error) error {
	if b.entered != nil {
		close(b.entered)
		select {
		case <-b.finish:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if b.before != nil {
		b.before()
	}
	if err := authorize(ctx); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.imports++
	b.obs.IssuerDER = bytes.Clone(q.ChainDER[1])
	if !b.partial {
		b.obs.LeafDER = bytes.Clone(q.LeafDER)
	}
	if b.lost {
		return errors.New("synthetic lost import reply")
	}
	return nil
}

type stageFixture struct {
	s                    *journal.Store
	path                 string
	services             []journal.Service
	r                    journal.Record
	v                    *certpolicy.Validator
	material             csr.Result
	spec                 csr.Spec
	leaf, root, baseline []byte
	backend              *stageBackend
	gate                 *lifecycle.StageGate
	denied               bool
	probeFail            bool
	probes               int
}

func newStageFixture(t *testing.T) *stageFixture {
	f := &stageFixture{}
	now := time.Now().UTC().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	stageMust(t, err)
	f.spec = csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test"}, RSABits: 2048}
	f.material.DER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: f.spec.CommonName}, DNSNames: f.spec.DNSNames, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	stageMust(t, err)
	f.material.PublicKeyDER, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	stageMust(t, err)
	f.material.NonExportable = true
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stageMust(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic staging CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(4, 0, 0), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign}
	f.root, err = x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	stageMust(t, err)
	ca, err = x509.ParseCertificate(f.root)
	stageMust(t, err)
	ext, err := asn1.Marshal(asn1.RawValue{Tag: 30, Bytes: []byte{0, 'W', 0, 'e', 0, 'b'}})
	stageMust(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: f.spec.CommonName}, DNSNames: f.spec.DNSNames, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}, Value: ext}}}
	f.leaf, err = x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	stageMust(t, err)
	leaf.SerialNumber = big.NewInt(3)
	f.baseline, err = x509.CreateCertificate(rand.Reader, leaf, ca, &caKey.PublicKey, caKey)
	stageMust(t, err)
	p := certpolicy.Policy{ID: "https-stage", Spec: f.spec, RAProfileID: "ra-a", AuthorityID: "ca-a", PrincipalRef: "principal://issuer/a", EvidenceRef: "evidence://private/a", BundleRef: "bundle://approved/a", Roots: [][]byte{f.root}, IssuerSHA256: []string{certpolicy.SHA256(f.root)}, Template: certpolicy.Template{Kind: certpolicy.V1, Name: "Web"}, KeyUsage: leaf.KeyUsage, MinRemaining: time.Hour, MaxLifetime: 2 * 365 * 24 * time.Hour, MaxBackdate: time.Hour, MaxClockAge: time.Minute, MaxClockError: time.Second, MaxEvidenceAge: time.Hour}
	f.v, err = certpolicy.New(p, validationClock(func(context.Context) (certpolicy.TimeReading, error) {
		n := time.Now().UTC()
		return certpolicy.TimeReading{Now: n, ObservedAt: n, Synchronized: true}, nil
	}), validationEvidence(func(_ context.Context, ref string) (certpolicy.EnrollmentEvidence, error) {
		n := time.Now().UTC()
		return certpolicy.EnrollmentEvidence{Reference: ref, SnapshotSHA256: strings.Repeat("d", 64), PolicySHA256: f.v.Digest(), RAProfileID: p.RAProfileID, AuthorityID: p.AuthorityID, PrincipalRef: p.PrincipalRef, IssuerSHA256: p.IssuerSHA256[0], Template: p.Template, ObservedAt: n, ValidUntil: n.Add(time.Hour), RABindingVerified: true, Published: true, CAReadTemplate: true, CARequestCertificates: true, TemplateRead: true, TemplateEnroll: !f.denied, SubjectSupplyAllowed: true, SANSupplyAllowed: true}, nil
	}))
	stageMust(t, err)
	id := uuid.NewString()
	b := journal.Binding{EntityID: id, LocationID: provider.HTTPSLocationID(id), DeviceID: "router-a", Target: "192.0.2.10", HostKeySHA256: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), PolicySHA256: f.v.Digest(), Owner: journal.ILMCore}
	f.services = []journal.Service{{Binding: b, StagingTrustpoints: []string{"HTTPS-STAGE-A"}}}
	f.path = filepath.Join(t.TempDir(), "journal.sqlite")
	f.s, err = journal.Open(f.path, f.services)
	stageMust(t, err)
	f.r, err = f.s.Begin(context.Background(), uuid.NewString(), journal.Correlation{Binding: b, ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: certpolicy.SHA256(f.baseline), StagingTrustpoint: "HTTPS-STAGE-A"})
	stageMust(t, err)
	f.r, _, err = f.s.GenerateCSR(context.Background(), f.r.Ref(), f.spec, func(context.Context, csr.Request) (csr.Result, error) { return f.material, nil })
	stageMust(t, err)
	f.r, err = f.s.Progress(context.Background(), f.r.Ref(), f.r.Revision, journal.AwaitingIssuance)
	stageMust(t, err)
	cg, err := lifecycle.NewCertificateGate(f.s, f.v)
	stageMust(t, err)
	f.r, _, err = cg.Accept(context.Background(), f.r.Ref(), f.leaf, nil)
	stageMust(t, err)
	f.backend = &stageBackend{obs: staging.Observation{ActiveTrustpoint: "HTTPS-LIVE", ActiveDER: f.baseline, PublicKeyDER: f.material.PublicKeyDER, NonExportable: true, OtherStateSHA256: strings.Repeat("f", 64)}}
	f.rewire(t)
	t.Cleanup(func() { f.s.Close() })
	return f
}
func (f *stageFixture) rewire(t *testing.T) {
	var err error
	f.gate, err = lifecycle.NewStageGate(f.s, f.v, map[string]string{"router-a": strings.Repeat("e", 64)}, f.backend, func(ctx context.Context, q staging.Request, active []byte) error {
		f.probes++
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if f.probeFail || !bytes.Equal(active, f.baseline) || q.CSR.BaselineSHA256 != certpolicy.SHA256(active) {
			return errors.New("synthetic TLS baseline mismatch")
		}
		return nil
	})
	stageMust(t, err)
}
func TestStageOnlyValidatedImportAndFreshWithKey(t *testing.T) {
	f := newStageFixture(t)
	got, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
	stageMust(t, err)
	if got.Operation.State != journal.Staged || !got.WithKey || f.backend.imports != 1 || f.probes < 2 {
		t.Fatal("staging lacked independent evidence")
	}
	stageMust(t, f.s.Close())
	f.s, err = journal.Open(f.path, f.services)
	stageMust(t, err)
	f.rewire(t)
	got, err = f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
	stageMust(t, err)
	if !got.WithKey || f.backend.imports != 1 {
		t.Fatal("restart repeated import")
	}
	f.backend.obs.PublicKeyDER = nil
	got, err = f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
	if err == nil || got.WithKey || f.backend.imports != 1 {
		t.Fatal("cached staged state fabricated withKey")
	}
}
func TestStageUncertainImportOnlyReconcilesAndNeverReplays(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "issuer-only"}[partial], func(t *testing.T) {
			f := newStageFixture(t)
			f.backend.lost = true
			f.backend.partial = partial
			got, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
			if !errors.Is(err, journal.ErrReconcile) || got.WithKey {
				t.Fatal("uncertain import was accepted", err)
			}
			stageMust(t, f.s.Close())
			f.s, err = journal.Open(f.path, f.services)
			stageMust(t, err)
			f.rewire(t)
			got, err = f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
			if partial {
				if !errors.Is(err, journal.ErrReconcile) || got.WithKey {
					t.Fatal("partial import promoted", err)
				}
			} else {
				stageMust(t, err)
				if !got.WithKey || got.Operation.State != journal.Staged {
					t.Fatal("read-only reconciliation failed")
				}
			}
			if f.backend.imports != 1 {
				t.Fatal("uncertain import replayed")
			}
		})
	}
}
func TestStageRejectsScopePolicyBaselineAndPreexistingLeaf(t *testing.T) {
	for _, mode := range []string{"permission", "wrong-leaf", "baseline", "tls", "preexisting", "other-state", "key"} {
		t.Run(mode, func(t *testing.T) {
			f := newStageFixture(t)
			leaf := f.leaf
			switch mode {
			case "permission":
				f.denied = true
			case "wrong-leaf":
				leaf = f.baseline
			case "baseline":
				f.backend.obs.ActiveTrustpoint = "OTHER"
			case "tls":
				f.probeFail = true
			case "preexisting":
				f.backend.obs.LeafDER = f.leaf
				f.backend.obs.IssuerDER = f.root
			case "other-state":
				f.backend.obs.OtherStateSHA256 = "invalid"
			case "key":
				f.backend.obs.NonExportable = false
			}
			got, err := f.gate.Stage(context.Background(), f.r.Ref(), leaf, nil)
			if err == nil || got.WithKey || f.backend.imports != 0 {
				t.Fatal("unsafe staging dispatched", err)
			}
		})
	}
}
func TestStageConcurrentPushAndDispatchPermissionRecheck(t *testing.T) {
	t.Run("overlap", func(t *testing.T) {
		f := newStageFixture(t)
		f.backend.entered = make(chan struct{})
		f.backend.finish = make(chan struct{})
		done := make(chan error, 1)
		go func() { _, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil); done <- err }()
		<-f.backend.entered
		if _, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil); !errors.Is(err, journal.ErrBusy) {
			t.Fatal("overlap admitted", err)
		}
		close(f.backend.finish)
		stageMust(t, <-done)
		if f.backend.imports != 1 {
			t.Fatal("overlap repeated import")
		}
	})
	t.Run("permission-changed-at-dispatch", func(t *testing.T) {
		f := newStageFixture(t)
		f.backend.before = func() { f.denied = true }
		got, err := f.gate.Stage(context.Background(), f.r.Ref(), f.leaf, nil)
		if err == nil || got.WithKey || f.backend.imports != 0 {
			t.Fatal("stale issuance permission authorized import", err)
		}
	})
}

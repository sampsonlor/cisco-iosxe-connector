package journal

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestNativeScopedLookupAndOwnerExclusion(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	r := ready(t, s)
	if err := s.NativeBinding(ctx, r.Correlation); err != nil {
		t.Fatal(err)
	}
	if got, err := s.ResolveNative(ctx, r.Correlation.Binding, r.ID); err != nil || got.Ref() != r.Ref() {
		t.Fatalf("scope lookup: %v", err)
	}
	for _, mutate := range []func(*Binding){func(b *Binding) { b.Owner = ACMEWorker }, func(b *Binding) { b.EntityID = uuid.NewString() }, func(b *Binding) { b.PolicySHA256 = strings.Repeat("f", 64) }, func(b *Binding) { b.LocationID = uuid.NewString() }} {
		b := r.Correlation.Binding
		mutate(&b)
		if _, err := s.ResolveNative(ctx, b, r.ID); !errors.Is(err, ErrCorrelation) {
			t.Fatalf("UUID granted access: %v", err)
		}
		c := r.Correlation
		c.Binding = b
		if err := s.NativeBinding(ctx, c); !errors.Is(err, ErrCorrelation) {
			t.Fatalf("wrong native binding: %v", err)
		}
	}
	if _, found, err := s.NativeCertificate(ctx, r.Correlation.Binding, r.CertificateSHA256); err != nil || found {
		t.Fatal("unstaged cert associated")
	}
	r, err := s.ImportOnce(ctx, r.Ref(), r.CertificateSHA256, func(context.Context, Record) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got, found, err := s.NativeCertificate(ctx, r.Correlation.Binding, r.CertificateSHA256); err != nil || !found || got.ID != r.ID {
		t.Fatalf("staged association: %v", err)
	}
	c := r.Correlation
	c.Owner = ACMEWorker
	if _, err = s.Begin(ctx, uuid.NewString(), c); err == nil {
		t.Fatal("worker claimed Core service")
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ResolveNative(ctx, r.Correlation.Binding, r.ID); !errors.Is(err, ErrStore) {
		t.Fatal("closed database reported operation")
	}
}

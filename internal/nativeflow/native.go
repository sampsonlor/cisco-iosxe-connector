// Package nativeflow connects the pinned Core Entity Provider lifecycle to the
// same CSR, validation and stage-only gates as the ACME worker. It starts no host.
package nativeflow

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/google/uuid"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lifecycle"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

// Service is operator approval, including the observed old HTTPS baseline. Core
// supplies neither the target, issuance policy, owner nor a baseline digest.
type Service struct {
	Correlation journal.Correlation
	Spec        csr.Spec
}
type Engine struct {
	store    *journal.Store
	csr      *lifecycle.CSRGate
	cert     *lifecycle.CertificateGate
	stage    *lifecycle.StageGate
	services map[string]Service
}

func New(s *journal.Store, c *lifecycle.CSRGate, v *lifecycle.CertificateGate, g *lifecycle.StageGate, services []Service) (*Engine, error) {
	if s == nil || c == nil || v == nil || g == nil || len(services) == 0 {
		return nil, provider.ErrNativeUnavailable
	}
	e := &Engine{store: s, csr: c, cert: v, stage: g, services: map[string]Service{}}
	for _, p := range services {
		spec, err := csr.Normalize(p.Spec)
		if err != nil || !v.AllowsCSR(spec) || p.Correlation.PolicySHA256 != v.PolicySHA256() || e.services[p.Correlation.EntityID].Correlation.EntityID != "" {
			return nil, provider.ErrNativeScope
		}
		if err = s.NativeBinding(context.Background(), p.Correlation); err != nil {
			return nil, flowError(err)
		}
		p.Spec = spec
		e.services[p.Correlation.EntityID] = p
	}
	return e, nil
}
func flowError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, journal.ErrStore), errors.Is(err, journal.ErrInstance):
		return errors.Join(provider.ErrNativeUnavailable, err)
	case errors.Is(err, journal.ErrCorrelation):
		return errors.Join(provider.ErrNativeScope, err)
	case errors.Is(err, journal.ErrBusy), errors.Is(err, journal.ErrConflict), errors.Is(err, journal.ErrState), errors.Is(err, journal.ErrReconcile):
		return errors.Join(provider.ErrNativeConflict, err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return errors.Join(provider.ErrNativeRejected, err)
	}
}
func (e *Engine) service(ctx context.Context, t provider.NativeTarget) (Service, error) {
	if e == nil || e.store == nil {
		return Service{}, provider.ErrNativeUnavailable
	}
	p, ok := e.services[t.EntityID]
	b := p.Correlation.Binding
	if !ok || b.EntityID != t.EntityID || b.LocationID != t.LocationID || b.DeviceID != t.DeviceID || b.Target != t.Target || b.Owner != journal.ILMCore {
		return Service{}, provider.ErrNativeScope
	}
	if err := e.store.NativeBinding(ctx, p.Correlation); err != nil {
		return Service{}, flowError(err)
	}
	return p, nil
}
func (e *Engine) Enabled(ctx context.Context, t provider.NativeTarget) error {
	_, err := e.service(ctx, t)
	return err
}

func (e *Engine) Association(ctx context.Context, t provider.NativeTarget, leaf []byte) (provider.NativeAssociation, error) {
	p, err := e.service(ctx, t)
	if err != nil {
		return provider.NativeAssociation{}, err
	}
	r, found, err := e.store.NativeCertificate(ctx, p.Correlation.Binding, certpolicy.SHA256(leaf))
	if err != nil {
		return provider.NativeAssociation{}, flowError(err)
	}
	if !found {
		return provider.NativeAssociation{}, nil
	}
	if r.Correlation != p.Correlation || (r.RequestID != requestID(p, true) && r.RequestID != requestID(p, false)) {
		return provider.NativeAssociation{}, provider.ErrNativeScope
	}
	return provider.NativeAssociation{OperationID: r.ID, StagingTrustpoint: r.Correlation.StagingTrustpoint}, nil
}

// Core has no CSR request-id field. Derive one from the complete trusted intent
// and renewal flag, then rely on Begin's durable request-id and one-service
// uniqueness. Retries/restarts reuse the CSR; a changed intent cannot claim it.
func requestID(p Service, renewal bool) string {
	raw, _ := json.Marshal(struct {
		Service Service
		Renewal bool
	}{p, renewal})
	return uuid.NewSHA1(uuid.NameSpaceOID, append([]byte("iosxe-native-v1:"), raw...)).String()
}
func (e *Engine) CSR(ctx context.Context, t provider.NativeTarget, slot string, renewal bool) (provider.NativeCSR, error) {
	p, err := e.service(ctx, t)
	if err != nil {
		return provider.NativeCSR{}, err
	}
	if slot != p.Correlation.StagingTrustpoint {
		return provider.NativeCSR{}, provider.ErrNativeScope
	}
	r, err := e.store.Begin(ctx, requestID(p, renewal), p.Correlation)
	if err != nil {
		return provider.NativeCSR{}, flowError(err)
	}
	if r.State != journal.Precheck && r.State != journal.KeyCreating && r.State != journal.CSRReady && r.State != journal.AwaitingIssuance {
		return provider.NativeCSR{}, provider.ErrNativeConflict
	}
	r, der, err := e.csr.Generate(ctx, r.Ref(), p.Spec)
	if err != nil {
		return provider.NativeCSR{}, flowError(err)
	}
	if r.State == journal.CSRReady {
		r, err = e.store.Progress(ctx, r.Ref(), r.Revision, journal.AwaitingIssuance)
		if err != nil {
			return provider.NativeCSR{}, flowError(err)
		}
	}
	if r.State != journal.AwaitingIssuance {
		return provider.NativeCSR{}, provider.ErrNativeConflict
	}
	return provider.NativeCSR{DER: slices.Clone(der), OperationID: r.ID, State: string(r.State)}, nil
}
func (e *Engine) Push(ctx context.Context, t provider.NativeTarget, id string, leaf []byte) (provider.NativePush, error) {
	p, err := e.service(ctx, t)
	if err != nil {
		return provider.NativePush{}, err
	}
	r, err := e.store.ResolveNative(ctx, p.Correlation.Binding, id)
	if err != nil {
		return provider.NativePush{}, flowError(err)
	}
	if r.Correlation != p.Correlation || (r.RequestID != requestID(p, true) && r.RequestID != requestID(p, false)) {
		return provider.NativePush{}, provider.ErrNativeScope
	}
	if len(leaf) == 0 || len(leaf) > 1<<20 {
		return provider.NativePush{}, provider.ErrNativeRejected
	}
	switch r.State {
	case journal.AwaitingIssuance, journal.CertReady:
		r, _, err = e.cert.Accept(ctx, r.Ref(), leaf, nil)
		if err != nil {
			return provider.NativePush{}, flowError(err)
		}
	case journal.Importing, journal.Staged:
		if r.CertificateSHA256 != certpolicy.SHA256(leaf) {
			return provider.NativePush{}, provider.ErrNativeScope
		}
	default:
		return provider.NativePush{}, provider.ErrNativeConflict
	}
	// Core 2.19.0 carries no chain. The validator resolves only the public bundle
	// approved by the server policy, never an attacker-supplied URL or extra field.
	staged, err := e.stage.Stage(ctx, r.Ref(), leaf, nil)
	if err != nil {
		return provider.NativePush{}, flowError(err)
	}
	if staged.Operation.State != journal.Staged || !staged.WithKey {
		return provider.NativePush{}, provider.ErrNativeConflict
	}
	return provider.NativePush{OperationID: staged.Operation.ID, State: string(staged.Operation.State), WithKey: staged.WithKey}, nil
}

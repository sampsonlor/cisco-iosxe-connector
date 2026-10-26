package lifecycle

import (
	"context"
	"regexp"
	"slices"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
)

type StageDevice interface {
	Inspect(context.Context, staging.Request) (staging.Observation, error)
	Import(context.Context, staging.Request, func(context.Context) error) error
}
type StageProbe func(context.Context, staging.Request, []byte) error
type StageGate struct {
	store     *journal.Store
	validator *certpolicy.Validator
	settings  map[string]string
	device    StageDevice
	probe     StageProbe
}
type StageResult struct {
	Operation journal.Record
	WithKey   bool
}

// NewStageGate accepts trusted host adapters. NewIOSXEStageGate binds the real
// inventory verifier, pinned SSH importer and independent baseline TLS probe.
func NewStageGate(s *journal.Store, v *certpolicy.Validator, settings map[string]string, d StageDevice, p StageProbe) (*StageGate, error) {
	if s == nil || v == nil || d == nil || p == nil || len(settings) == 0 {
		return nil, journal.ErrCorrelation
	}
	copySettings := map[string]string{}
	for id, h := range settings {
		if id == "" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(h) {
			return nil, journal.ErrCorrelation
		}
		copySettings[id] = h
	}
	return &StageGate{store: s, validator: v, settings: copySettings, device: d, probe: p}, nil
}
func (g *StageGate) observe(ctx context.Context, q staging.Request, other string) (staging.Observation, error) {
	o, err := g.device.Inspect(ctx, q)
	if err != nil {
		return o, err
	}
	if err = o.Check(q, other); err != nil {
		return o, err
	}
	if err = g.probe(ctx, q, slices.Clone(o.ActiveDER)); err != nil {
		return o, err
	}
	return o, nil
}
func (g *StageGate) proof(ctx context.Context, q staging.Request) (certpolicy.Result, error) {
	return g.validator.Validate(ctx, q.Material, q.CSR.Spec, q.LeafDER, q.ChainDER[1:])
}

// Stage revalidates even committed retries. IMPORTING only takes the read-only
// reconciliation path; partial/absent results never authorize a second import.
func (g *StageGate) Stage(ctx context.Context, ref journal.Ref, leaf []byte, chain [][]byte) (result StageResult, err error) {
	if g == nil || g.store == nil {
		return result, journal.ErrStore
	}
	release, err := g.store.LockStage(ctx, ref)
	if err != nil {
		return result, err
	}
	defer release()
	r, q, err := g.store.StageMaterial(ctx, ref)
	result.Operation = r
	if err != nil {
		return result, err
	}
	settings := g.settings[q.CSR.DeviceID]
	if settings == "" || r.Correlation.PolicySHA256 != g.validator.Digest() || r.CertificateSHA256 != certpolicy.SHA256(leaf) {
		return result, journal.ErrCorrelation
	}
	p, err := g.validator.Validate(ctx, q.Material, q.CSR.Spec, leaf, chain)
	if err != nil {
		return result, err
	}
	a, err := g.store.PrepareStage(ctx, ref, p, settings)
	if err != nil {
		return result, err
	}
	q.LeafDER, q.ChainDER = slices.Clone(a.LeafDER), a.ChainDER
	o, err := g.observe(ctx, q, a.OtherStateSHA256)
	if err != nil {
		return result, err
	}
	if r.State != journal.CertReady {
		if !o.Complete(q) {
			return result, journal.ErrReconcile
		}
		p, err = g.proof(ctx, q)
		if err != nil {
			return result, err
		}
		result.Operation, err = g.store.ConfirmStage(ctx, ref, r.Revision, p, settings, o.OtherStateSHA256)
		result.WithKey = err == nil
		return result, err
	}
	if len(o.LeafDER) != 0 || len(o.IssuerDER) != 0 {
		return result, journal.ErrReconcile
	}
	a, err = g.store.BindStageBaseline(ctx, ref, a, o.OtherStateSHA256)
	if err != nil {
		return result, err
	}
	p, err = g.proof(ctx, q)
	if err != nil {
		return result, err
	}
	result.Operation, err = g.store.StageOnce(ctx, ref, r.Revision, p, settings, func(c context.Context, _ journal.Record, recheck journal.StageRecheck) (certpolicy.Result, error) {
		before, err := g.observe(c, q, a.OtherStateSHA256)
		if err != nil {
			return certpolicy.Result{}, err
		}
		if len(before.LeafDER) != 0 || len(before.IssuerDER) != 0 {
			return certpolicy.Result{}, journal.ErrReconcile
		}
		authorize := func(c context.Context) error {
			fresh, err := g.proof(c, q)
			if err != nil {
				return err
			}
			return recheck(c, fresh)
		}
		if err := authorize(c); err != nil {
			return certpolicy.Result{}, err
		}
		if err := g.device.Import(c, q, authorize); err != nil {
			// A lost/cancelled import reply does not prove the old HTTPS binding.
			// Probe independently using the already pinned pre-dispatch DER; the
			// import intent remains unresolved regardless of this read result.
			check, stop := context.WithTimeout(context.WithoutCancel(c), 10*time.Second)
			defer stop()
			_ = g.probe(check, q, slices.Clone(before.ActiveDER))
			return certpolicy.Result{}, err
		}
		after, err := g.observe(c, q, a.OtherStateSHA256)
		if err != nil {
			return certpolicy.Result{}, err
		}
		if !after.Complete(q) {
			return certpolicy.Result{}, journal.ErrReconcile
		}
		return g.proof(c, q)
	})
	result.WithKey = err == nil && result.Operation.State == journal.Staged
	return result, err
}

package acmeflow

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"slices"
	"strings"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"golang.org/x/crypto/acme"
)

type run struct {
	e        *Engine
	ctx      context.Context
	ref      journal.Ref
	spec     csr.Spec
	material csr.Result
	flow     journal.ACMERecord
	client   *acme.Client
	guard    *guard
}

func (r *run) save() error {
	next, err := r.e.store.SaveACME(r.ctx, r.ref, r.flow.Revision, r.flow)
	if err == nil {
		r.flow = next
	}
	return err
}
func (r *run) pending() error {
	r.flow.Attempts++
	d := r.e.config.MinBackoff
	for i := 1; i < r.flow.Attempts && d < r.e.config.MaxBackoff; i++ {
		d = min(d*2, r.e.config.MaxBackoff)
	}
	r.flow.NextAttemptAt = r.e.config.Now().Add(d).UTC()
	if r.guard != nil && r.guard.retryAt.After(r.flow.NextAttemptAt) {
		r.flow.NextAttemptAt = r.guard.retryAt.UTC()
	}
	// Network timeouts do not prevent recording recovery with the caller context.
	if err := r.save(); err != nil {
		return err
	}
	if r.flow.Attempts >= r.e.config.MaxAttempts {
		return ErrExhausted
	}
	return ErrPending
}

func (r *run) protocolError(err error) error {
	var problem *acme.Error
	if errors.As(err, &problem) && problem.ProblemType == "urn:ietf:params:acme:error:badNonce" {
		// The bounded same-nonce retry has ended. Stop rather than discarding
		// its required response nonce and silently retrying with a different one.
		r.flow.Attempts = r.e.config.MaxAttempts
		if err := r.save(); err != nil {
			return err
		}
		return ErrExhausted
	}
	return r.pending()
}

// Run advances one bounded attempt. Pending work is resumed explicitly after
// NextAttemptAt; no scheduler, detached goroutine or unbounded polling is added.
func (e *Engine) Run(ctx context.Context, ref journal.Ref) (journal.Record, error) {
	if e == nil || e.store == nil {
		return journal.Record{}, ErrPolicy
	}
	if err := ctx.Err(); err != nil {
		return journal.Record{}, err
	}
	release, err := e.store.LockACME(ctx, ref)
	if err != nil {
		return journal.Record{}, err
	}
	defer release()
	op, spec, material, flow, err := e.store.BeginACME(ctx, ref, e.binding)
	if err != nil {
		return journal.Record{}, err
	}
	currentKey, keyErr := x509.MarshalPKIXPublicKey(e.key.Public())
	if keyErr != nil || !bytes.Equal(currentKey, e.publicDER) || op.Correlation.PolicySHA256 != e.config.PolicySHA256 || bytes.Equal(e.publicDER, material.PublicKeyDER) {
		return op, ErrPolicy
	}
	if flow.Stage == journal.ACMEInvalid {
		return op, ErrProtocol
	}
	if flow.Stage == journal.ACMECreating && flow.OrderURL == "" {
		return op, ErrReconcile
	}
	if flow.Attempts >= e.config.MaxAttempts {
		return op, ErrExhausted
	}
	if flow.NextAttemptAt.After(e.config.Now()) {
		return op, ErrPending
	}
	client, g := e.client()
	r := &run{e: e, ctx: ctx, ref: ref, spec: spec, material: material, flow: flow, client: client, guard: g}
	network, cancel := context.WithTimeout(ctx, e.config.RunTimeout)
	defer cancel()
	err = r.advance(network)
	if current, readErr := e.store.Get(ctx, ref); readErr == nil {
		op = current
	}
	return op, err
}
func (r *run) account(ctx context.Context, d acme.Directory) error {
	for _, uri := range []string{d.NonceURL, d.RegURL, d.OrderURL} {
		if !journal.ValidACMEResource(r.e.config.DirectoryURL, uri) {
			return ErrProtocol
		}
	}
	if d.Terms != "" && d.Terms != r.e.config.TermsURL {
		return ErrPolicy
	}
	saved, err := r.e.store.ACMEAccount(r.ctx, r.ref)
	if err != nil {
		return err
	}
	a, err := r.client.GetReg(ctx, "")
	if errors.Is(err, acme.ErrNoAccount) {
		if saved != "" {
			return ErrReconcile
		}
		if d.ExternalAccountRequired {
			return ErrPolicy
		}
		a, err = r.client.Register(ctx, &acme.Account{}, func(uri string) bool { return uri == r.e.config.TermsURL })
		if errors.Is(err, acme.ErrAccountAlreadyExists) {
			a, err = r.client.GetReg(ctx, "")
		}
	}
	if err != nil {
		return r.protocolError(err)
	}
	if a == nil || a.Status != acme.StatusValid || !journal.ValidACMEResource(r.e.config.DirectoryURL, a.URI) || saved != "" && saved != a.URI {
		return ErrProtocol
	}
	if err = r.e.store.BindACMEAccount(r.ctx, r.ref, a.URI); err != nil {
		return err
	}
	r.client.KID = acme.KeyID(a.URI)
	return nil
}
func (r *run) validOrder(o *acme.Order) bool {
	if o == nil || !journal.ValidACMEResource(r.e.config.DirectoryURL, o.URI) || !journal.ValidACMEResource(r.e.config.DirectoryURL, o.FinalizeURL) || o.Expires.IsZero() || len(o.Identifiers) != len(r.spec.DNSNames) || len(o.AuthzURLs) == 0 || len(o.AuthzURLs) > 16 || o.Profile != "" {
		return false
	}
	names := make([]string, 0, len(o.Identifiers))
	for _, id := range o.Identifiers {
		if id.Type != "dns" {
			return false
		}
		names = append(names, strings.ToLower(id.Value))
	}
	slices.Sort(names)
	if !slices.Equal(names, r.spec.DNSNames) {
		return false
	}
	seen := map[string]bool{}
	for _, uri := range o.AuthzURLs {
		if !journal.ValidACMEResource(r.e.config.DirectoryURL, uri) || seen[uri] {
			return false
		}
		seen[uri] = true
	}
	slices.Sort(o.AuthzURLs)
	if r.flow.OrderURL != "" && (o.URI != r.flow.OrderURL || o.FinalizeURL != r.flow.FinalizeURL || !slices.Equal(o.AuthzURLs, r.flow.AuthorizationURLs)) {
		return false
	}
	if o.CertURL != "" && !journal.ValidACMEResource(r.e.config.DirectoryURL, o.CertURL) {
		return false
	}
	return o.Status == acme.StatusPending || o.Status == acme.StatusReady || o.Status == acme.StatusProcessing || o.Status == acme.StatusValid || o.Status == acme.StatusInvalid
}
func (r *run) advance(ctx context.Context) error {
	d, err := r.client.Discover(ctx)
	if err != nil {
		return r.pending()
	}
	if err = r.account(ctx, d); err != nil {
		return err
	}
	var order *acme.Order
	if r.flow.Stage == journal.ACMEPreparing {
		r.flow.Stage = journal.ACMECreating
		if err = r.save(); err != nil {
			return err
		}
		r.guard.mutationURL = d.OrderURL
		r.guard.mutationAccepted = false
		order, err = r.client.AuthorizeOrder(ctx, acme.DomainIDs(r.spec.DNSNames...))
		if err != nil {
			if explicitRejection(err, r.guard) {
				r.flow.Stage = journal.ACMEPreparing
				return r.protocolError(err)
			}
			return ErrReconcile
		}
		if !r.validOrder(order) {
			return ErrReconcile
		}
		r.flow.Stage = journal.ACMEBound
		r.flow.OrderURL = order.URI
		r.flow.FinalizeURL = order.FinalizeURL
		r.flow.AuthorizationURLs = slices.Clone(order.AuthzURLs)
		if err = r.save(); err != nil {
			return err
		}
	} else {
		order, err = r.client.GetOrder(ctx, r.flow.OrderURL)
		if err != nil {
			return r.protocolError(err)
		}
		if !r.validOrder(order) {
			return ErrProtocol
		}
	}
	if order.Status == acme.StatusInvalid || !order.Expires.After(r.e.config.Now()) {
		if err := r.cleanup(ctx); err != nil {
			return err
		}
		r.flow.Stage = journal.ACMEInvalid
		if err := r.save(); err != nil {
			return err
		}
		return ErrProtocol
	}
	pending, err := r.authorizations(ctx)
	if err != nil {
		return err
	}
	if pending || order.Status == acme.StatusPending {
		return r.pending()
	}
	switch order.Status {
	case acme.StatusReady:
		if r.flow.Stage != journal.ACMEBound {
			return ErrReconcile
		}
		r.flow.Stage = journal.ACMEFinalizing
		if err := r.save(); err != nil {
			return err
		}
		r.guard.mutationURL = order.FinalizeURL
		r.guard.mutationAccepted = false
		_, _, err := r.client.CreateCertFromOrder(ctx, order, r.material.DER, true)
		if err != nil && explicitRejection(err, r.guard) {
			r.flow.Stage = journal.ACMEBound
		}
		// Verify the original order again next time, even if the combined
		// finalize/poll/download call returned successfully.
		if err != nil {
			return r.protocolError(err)
		}
		return r.pending()
	case acme.StatusProcessing:
		if r.flow.Stage != journal.ACMEFinalizing {
			return ErrProtocol
		}
		return r.pending()
	case acme.StatusValid:
		if r.flow.Stage != journal.ACMEFinalizing && r.flow.Stage != journal.ACMEIssued || order.CertURL == "" {
			return ErrProtocol
		}
		if r.flow.CertificateURL != "" && r.flow.CertificateURL != order.CertURL {
			return ErrProtocol
		}
		if r.flow.CertificateURL == "" {
			r.flow.CertificateURL = order.CertURL
			if err := r.save(); err != nil {
				return err
			}
		}
		chain, err := r.client.FetchCert(ctx, order.CertURL, true)
		if err != nil {
			return r.protocolError(err)
		}
		if len(chain) == 0 {
			return ErrProtocol
		}
		if _, _, err = r.e.gate.Accept(r.ctx, r.ref, chain[0], chain[1:]); err != nil {
			return err
		}
		if r.flow.Stage != journal.ACMEIssued {
			r.flow.Stage = journal.ACMEIssued
			if err := r.save(); err != nil {
				return err
			}
		}
		return nil
	}
	return ErrProtocol
}
func (r *run) cleanup(ctx context.Context) error {
	for i, c := range r.flow.Challenges {
		if c.Cleaned {
			continue
		}
		q := Challenge{OperationID: r.ref.ID, Identifier: c.Identifier, AuthorizationURL: c.AuthorizationURL, URL: c.ChallengeURL, TokenSHA256: c.TokenSHA256, TXTValueSHA256: c.TXTValueSHA256}
		if err := r.e.solver.Cleanup(ctx, q); err != nil {
			return r.pending()
		}
		r.flow.Challenges[i].Cleaned = true
		if err := r.save(); err != nil {
			return err
		}
	}
	return nil
}
func (r *run) authorizations(ctx context.Context) (bool, error) {
	covered := map[string]bool{}
	pending := false
	// Check the complete authorization set before any DNS backend call.
	type authorization struct {
		uri       string
		a         *acme.Authorization
		challenge *acme.Challenge
	}
	items := []authorization{}
	for _, uri := range r.flow.AuthorizationURLs {
		a, err := r.client.GetAuthorization(ctx, uri)
		if err != nil {
			return false, r.protocolError(err)
		}
		name := strings.ToLower(a.Identifier.Value)
		if a.URI != uri || a.Identifier.Type != "dns" || a.Wildcard || !slices.Contains(r.spec.DNSNames, name) || covered[name] || a.Expires.IsZero() {
			return false, ErrProtocol
		}
		if !a.Expires.After(r.e.config.Now()) {
			if err := r.cleanup(ctx); err != nil {
				return false, err
			}
			r.flow.Stage = journal.ACMEInvalid
			if err := r.save(); err != nil {
				return false, err
			}
			return false, ErrProtocol
		}
		covered[name] = true
		item := authorization{uri: uri, a: a}
		switch a.Status {
		case acme.StatusValid:
		case acme.StatusPending:
			if r.flow.Stage != journal.ACMEBound {
				return false, ErrReconcile
			}
			for _, c := range a.Challenges {
				if c.Type == "dns-01" {
					if item.challenge != nil || !journal.ValidACMEResource(r.e.config.DirectoryURL, c.URI) || !tokenPattern.MatchString(c.Token) {
						return false, ErrProtocol
					}
					item.challenge = c
				}
			}
			if item.challenge == nil {
				return false, ErrProtocol
			}
		default:
			if err := r.cleanup(ctx); err != nil {
				return false, err
			}
			r.flow.Stage = journal.ACMEInvalid
			if err := r.save(); err != nil {
				return false, err
			}
			return false, ErrProtocol
		}
		items = append(items, item)
	}
	if len(covered) != len(r.spec.DNSNames) {
		return false, ErrProtocol
	}
	for _, item := range items {
		i := slices.IndexFunc(r.flow.Challenges, func(c journal.ACMEChallenge) bool { return c.AuthorizationURL == item.uri })
		if item.a.Status == acme.StatusValid {
			if i >= 0 && !r.flow.Challenges[i].Cleaned {
				c := r.flow.Challenges[i]
				q := Challenge{OperationID: r.ref.ID, Identifier: c.Identifier, AuthorizationURL: c.AuthorizationURL, URL: c.ChallengeURL, TokenSHA256: c.TokenSHA256, TXTValueSHA256: c.TXTValueSHA256}
				if err := r.e.solver.Cleanup(ctx, q); err != nil {
					return false, r.pending()
				}
				r.flow.Challenges[i].Cleaned = true
				if err := r.save(); err != nil {
					return false, err
				}
			}
			continue
		}
		pending = true
		c := item.challenge
		value, err := r.client.DNS01ChallengeRecord(c.Token)
		if err != nil {
			return false, ErrProtocol
		}
		q := Challenge{OperationID: r.ref.ID, Identifier: strings.ToLower(item.a.Identifier.Value), AuthorizationURL: item.uri, URL: c.URI, Token: c.Token, TXTValue: value, TokenSHA256: certpolicy.SHA256([]byte(c.Token)), TXTValueSHA256: certpolicy.SHA256([]byte(value))}
		if i < 0 {
			r.flow.Challenges = append(r.flow.Challenges, journal.ACMEChallenge{AuthorizationURL: q.AuthorizationURL, Identifier: q.Identifier, ChallengeURL: q.URL, TokenSHA256: q.TokenSHA256, TXTValueSHA256: q.TXTValueSHA256})
			i = len(r.flow.Challenges) - 1
			if err := r.save(); err != nil {
				return false, err
			}
		}
		stored := r.flow.Challenges[i]
		if stored.Identifier != q.Identifier || stored.ChallengeURL != q.URL || stored.TokenSHA256 != q.TokenSHA256 || stored.TXTValueSHA256 != q.TXTValueSHA256 || stored.Cleaned {
			return false, ErrProtocol
		}
		if !stored.Presented {
			if err := r.e.solver.Present(ctx, q); err != nil {
				return false, r.pending()
			}
			r.flow.Challenges[i].Presented = true
			if err := r.save(); err != nil {
				return false, err
			}
		}
		if !stored.Notified {
			accepted, err := r.client.Accept(ctx, c)
			if err != nil {
				return false, r.protocolError(err)
			}
			if accepted.URI != c.URI || accepted.Type != c.Type || accepted.Token != c.Token {
				return false, ErrProtocol
			}
			r.flow.Challenges[i].Notified = true
			if err := r.save(); err != nil {
				return false, err
			}
		}
	}
	return pending, nil
}

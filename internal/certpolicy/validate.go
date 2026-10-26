package certpolicy

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"slices"
	"strings"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

func sameSpec(a, b csr.Spec) bool {
	return a.CommonName == b.CommonName && a.Organization == b.Organization && a.OrganizationalUnit == b.OrganizationalUnit && a.RSABits == b.RSABits && slices.Equal(a.DNSNames, b.DNSNames)
}

func checkSubject(n pkix.Name, s csr.Spec) bool {
	want := map[string]string{"2.5.4.3": s.CommonName}
	if s.Organization != "" {
		want["2.5.4.10"] = s.Organization
	}
	if s.OrganizationalUnit != "" {
		want["2.5.4.11"] = s.OrganizationalUnit
	}
	if len(n.Names) != len(want) {
		return false
	}
	for _, at := range n.Names {
		value, ok := at.Value.(string)
		expected, exists := want[at.Type.String()]
		if !ok || !exists || value != expected {
			return false
		}
		delete(want, at.Type.String())
	}
	return len(want) == 0
}

func checkSAN(c *x509.Certificate, s csr.Spec) bool {
	for _, ext := range c.Extensions {
		if ext.Id.String() != "2.5.29.17" {
			continue
		}
		r, err := rawValue(ext.Value, 16, true)
		if err != nil {
			return false
		}
		names := []string{}
		for body := r.Bytes; len(body) > 0; {
			var item asn1.RawValue
			body, err = asn1.Unmarshal(body, &item)
			if err != nil || item.Class != 2 || item.Tag != 2 || item.IsCompound || len(names) >= 16 {
				return false
			}
			names = append(names, strings.ToLower(string(item.Bytes)))
		}
		slices.Sort(names)
		return slices.Equal(names, s.DNSNames)
	}
	return false
}

func (v *Validator) current(ctx context.Context) (TimeReading, error) {
	r, err := v.clock.Read(ctx)
	if err != nil || !r.Synchronized || r.Now.IsZero() || r.ObservedAt.IsZero() || r.Uncertainty < 0 || r.Uncertainty > v.p.MaxClockError || r.ObservedAt.After(r.Now.Add(r.Uncertainty)) || r.Now.Add(r.Uncertainty).Sub(r.ObservedAt) >= v.p.MaxClockAge {
		return TimeReading{}, ErrClock
	}
	return r, nil
}

func (v *Validator) enrollment(ctx context.Context, clock TimeReading) (EnrollmentEvidence, error) {
	e, err := v.evidence.Read(ctx, v.p.EvidenceRef)
	if err != nil || e.Reference != v.p.EvidenceRef || !hashPattern.MatchString(e.SnapshotSHA256) || e.PolicySHA256 != v.digest || e.RAProfileID != v.p.RAProfileID || e.AuthorityID != v.p.AuthorityID || e.PrincipalRef != v.p.PrincipalRef || !slices.Contains(v.p.IssuerSHA256, e.IssuerSHA256) || !sameTemplate(e.Template, v.p.Template) || !e.RABindingVerified || !e.Published || !e.CAReadTemplate || !e.CARequestCertificates || !e.TemplateRead || !e.TemplateEnroll || !e.SubjectSupplyAllowed || !e.SANSupplyAllowed || e.ObservedAt.IsZero() || e.ValidUntil.IsZero() || e.ObservedAt.After(clock.Now.Add(clock.Uncertainty)) || clock.Now.Add(clock.Uncertainty).Sub(e.ObservedAt) >= v.p.MaxEvidenceAge || !e.ValidUntil.After(clock.Now.Add(clock.Uncertainty)) || !e.ValidUntil.After(e.ObservedAt) {
		return EnrollmentEvidence{}, ErrEvidence
	}
	return e, nil
}

func (v *Validator) chain(leaf *x509.Certificate, returned [][]byte, clock TimeReading, evidence EnrollmentEvidence) ([]*x509.Certificate, error) {
	if len(returned) > 16 {
		return nil, ErrChain
	}
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	approvedRoots := map[string]bool{}
	for _, c := range v.roots {
		roots.AddCert(c)
		approvedRoots[SHA256(c.Raw)] = true
	}
	for _, c := range v.issuers {
		intermediates.AddCert(c)
	}
	provided := map[string]bool{}
	for _, der := range returned {
		c, err := parseCA(bytes.Clone(der))
		if err != nil {
			return nil, ErrChain
		}
		h := SHA256(c.Raw)
		if provided[h] {
			return nil, ErrChain
		}
		provided[h] = true
		if bytes.Equal(c.RawSubject, c.RawIssuer) {
			if !approvedRoots[h] || c.CheckSignatureFrom(c) != nil {
				return nil, ErrChain
			}
		} else {
			intermediates.AddCert(c)
		}
	}
	paths, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: clock.Now, DNSName: v.p.Spec.CommonName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil {
		return nil, ErrChain
	}
	for _, path := range paths {
		if len(path) < 2 || SHA256(path[1].Raw) != evidence.IssuerSHA256 || !slices.Contains(v.p.IssuerSHA256, SHA256(path[1].Raw)) {
			continue
		}
		used := map[string]bool{}
		valid := true
		for _, c := range path {
			used[SHA256(c.Raw)] = true
			if c.NotBefore.After(clock.Now.Add(-clock.Uncertainty)) || !c.NotAfter.After(clock.Now.Add(clock.Uncertainty)) {
				valid = false
			}
		}
		for h := range provided {
			if !used[h] {
				valid = false
			}
		}
		if valid {
			return path, nil
		}
	}
	return nil, ErrChain
}

// AllowsCSR rejects host configuration drift before device key generation.
func (v *Validator) AllowsCSR(spec csr.Spec) bool {
	if v == nil {
		return false
	}
	normalized, err := csr.Normalize(spec)
	return err == nil && sameSpec(normalized, v.p.Spec)
}

// Validate performs no I/O beyond the trusted clock/evidence providers. It
// rechecks both on every call, including retries for a previously seen leaf.
func (v *Validator) Validate(ctx context.Context, material csr.Result, spec csr.Spec, leafDER []byte, returnedChain [][]byte) (Result, error) {
	if v == nil || v.clock == nil || v.evidence == nil {
		return Result{}, ErrPolicy
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	spec, err := csr.Normalize(spec)
	if err != nil || !sameSpec(spec, v.p.Spec) || csr.Validate(material, spec) != nil {
		return Result{}, ErrCSR
	}
	clock, err := v.current(ctx)
	if err != nil {
		return Result{}, err
	}
	evidence, err := v.enrollment(ctx, clock)
	if err != nil {
		return Result{}, err
	}
	if len(leafDER) == 0 || len(leafDER) > 64<<10 {
		return Result{}, ErrLeaf
	}
	leaf, err := x509.ParseCertificate(bytes.Clone(leafDER))
	if err != nil {
		return Result{}, ErrLeaf
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, material.PublicKeyDER) || !checkSubject(leaf.Subject, spec) || !checkSAN(leaf, spec) {
		return Result{}, ErrLeaf
	}
	if !modernSignature(leaf.SignatureAlgorithm) || leaf.IsCA || leaf.KeyUsage != v.p.KeyUsage || len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 {
		return Result{}, ErrLeaf
	}
	earliest, latest := clock.Now.Add(-clock.Uncertainty), clock.Now.Add(clock.Uncertainty)
	if !leaf.NotAfter.After(leaf.NotBefore) || leaf.NotAfter.Sub(leaf.NotBefore) > v.p.MaxLifetime || leaf.NotBefore.After(earliest) || leaf.NotBefore.Before(latest.Add(-v.p.MaxBackdate)) || !leaf.NotAfter.After(latest.Add(v.p.MinRemaining)) {
		return Result{}, ErrLeaf
	}
	if err := checkTemplate(leaf, v.p.Template); err != nil {
		return Result{}, err
	}
	if err := checkApplicationPolicies(leaf); err != nil {
		return Result{}, err
	}
	path, err := v.chain(leaf, returnedChain, clock, evidence)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	// The receipt expires when any input evidence becomes stale, with a maximum
	// one-minute handoff window. Import must independently revalidate later.
	until := clock.Now.Add(time.Minute)
	for _, bound := range []time.Time{clock.ObservedAt.Add(v.p.MaxClockAge).Add(-clock.Uncertainty), evidence.ObservedAt.Add(v.p.MaxEvidenceAge).Add(-clock.Uncertainty), evidence.ValidUntil.Add(-clock.Uncertainty), leaf.NotAfter.Add(-v.p.MinRemaining).Add(-clock.Uncertainty), leaf.NotBefore.Add(v.p.MaxBackdate).Add(-clock.Uncertainty)} {
		if bound.Before(until) {
			until = bound
		}
	}
	for _, c := range path[1:] {
		if bound := c.NotAfter.Add(-clock.Uncertainty); bound.Before(until) {
			until = bound
		}
	}
	if !until.After(clock.Now) {
		return Result{}, ErrClock
	}
	chainDER := make([][]byte, len(path))
	for i, c := range path {
		chainDER[i] = bytes.Clone(c.Raw)
	}
	return Result{leaf: SHA256(leaf.Raw), csr: SHA256(material.DER), policy: v.digest, source: evidence.Reference, snapshot: evidence.SnapshotSHA256, der: bytes.Clone(leaf.Raw), chain: chainDER, at: clock.Now, until: until}, nil
}

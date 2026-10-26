package certpolicy

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"sync"
	"testing"
	"time"
)

func sequence(t *testing.T, body []byte) []byte {
	t.Helper()
	raw, err := asn1.Marshal(asn1.RawValue{Tag: 16, IsCompound: true, Bytes: body})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTemplateDERAndApplicationPolicyBoundaries(t *testing.T) {
	f := newFixture(t)
	v := f.validator(t, f.p, nil, nil)
	oid, _ := parseOID(f.p.Template.OID)
	body, _ := asn1.Marshal(oid)
	negative, _ := asn1.Marshal(int64(-1))
	oversized, _ := asn1.Marshal(int64(1 << 32))
	valid := templateDER(t, f.p.Template)
	raw, err := rawValue(valid, 16, true)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string][]byte{
		"negative-version": sequence(t, append(bytes.Clone(body), negative...)),
		"large-version":    sequence(t, append(bytes.Clone(body), oversized...)),
		"third-version":    sequence(t, append(bytes.Clone(raw.Bytes), 2, 1, 0)),
		"trailing-DER":     append(bytes.Clone(valid), 5, 0),
		"not-sequence":     {5, 0},
	} {
		t.Run(name, func(t *testing.T) {
			leaf := f.leaf(t, func(c *x509.Certificate) { c.ExtraExtensions[0].Value = value })
			if _, err := v.Validate(context.Background(), f.material, f.spec, leaf, nil); !errors.Is(err, ErrTemplate) {
				t.Fatal("malformed template accepted", err)
			}
		})
	}
	for name, change := range map[string]func(*x509.Certificate){
		"missing-template":  func(c *x509.Certificate) { c.ExtraExtensions = nil },
		"critical-template": func(c *x509.Certificate) { c.ExtraExtensions[0].Critical = true },
		"conflicting-legacy-name": func(c *x509.Certificate) {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2}, Value: templateDER(t, Template{Kind: V1, Name: "DifferentTechnicalName"})})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.Validate(context.Background(), f.material, f.spec, f.leaf(t, change), nil); !errors.Is(err, ErrTemplate) {
				t.Fatal("missing or conflicting template accepted", err)
			}
		})
	}
	for _, versions := range [][2]*uint32{{nil, nil}, {u32(0), nil}, {u32(0), u32(0)}, {u32(1<<32 - 1), u32(1<<32 - 1)}} {
		f.p.Template.Major, f.p.Template.Minor = versions[0], versions[1]
		if _, err := f.validator(t, f.p, nil, nil).Validate(context.Background(), f.material, f.spec, f.leaf(t, nil), nil); err != nil {
			t.Fatal("valid explicit version presence rejected", err)
		}
	}
	legacy := Template{Kind: V1, Name: "TechnicalWeb"}
	utf8, err := asn1.Marshal(asn1.RawValue{Tag: 12, Bytes: []byte(legacy.Name)})
	if err != nil {
		t.Fatal(err)
	}
	for _, der := range [][]byte{templateDER(t, legacy), sequence(t, utf8)} {
		if name, err := v1Name(der); err != nil || name != legacy.Name {
			t.Fatal("supported technical name encoding rejected", err)
		}
	}
	for _, der := range [][]byte{sequence(t, append(bytes.Clone(utf8), 5, 0)), {0x1e, 2, 0xd8, 0}, {0x1e, 2, 0, 0}, sequence(t, []byte{12, 1, 0xff})} {
		if _, err := v1Name(der); err == nil {
			t.Fatal("invalid technical name encoding accepted")
		}
	}
	appOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 21, 10}
	serverOID, _ := parseOID(serverAuthOID)
	server, _ := asn1.Marshal(serverOID)
	clientOID, _ := parseOID("1.3.6.1.5.5.7.3.2")
	client, _ := asn1.Marshal(clientOID)
	for name, tc := range map[string]struct {
		der     []byte
		allowed bool
	}{
		"server":         {sequence(t, sequence(t, server)), true},
		"client":         {sequence(t, sequence(t, client)), false},
		"qualifier":      {sequence(t, sequence(t, append(bytes.Clone(server), 0x30, 0))), false},
		"extra-policy":   {sequence(t, append(sequence(t, server), sequence(t, client)...)), false},
		"empty":          {sequence(t, nil), false},
		"trailing-field": {sequence(t, sequence(t, append(bytes.Clone(server), 5, 0, 5, 0))), false},
	} {
		t.Run("application-"+name, func(t *testing.T) {
			leaf := f.leaf(t, func(c *x509.Certificate) {
				c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: appOID, Value: tc.der})
			})
			_, err := f.validator(t, f.p, nil, nil).Validate(context.Background(), f.material, f.spec, leaf, nil)
			if (err == nil) != tc.allowed {
				t.Fatal("application purpose check incorrect", err)
			}
		})
	}
}

func TestReceiptExpiryCSRAndConcurrentValidation(t *testing.T) {
	f := newFixture(t)
	v := f.validator(t, f.p, nil, nil)
	leaf := f.leaf(t, nil)
	proof, err := v.Validate(context.Background(), f.material, f.spec, leaf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if (Result{}).ValidAt(f.now) || proof.ValidAt(f.now.Add(-time.Second)) || proof.ValidAt(proof.ValidUntil()) || proof.ValidAt(f.now.Add(2*time.Minute)) {
		t.Fatal("receipt lifetime or zero value accepted")
	}
	copyChain := proof.ChainDER()
	copyChain[0][0] ^= 1
	if bytes.Equal(copyChain[0], proof.ChainDER()[0]) || proof.EvidenceRef() != f.p.EvidenceRef || proof.EvidenceSHA256() == "" {
		t.Fatal("receipt provenance or defensive copy missing")
	}
	nearBackdate := f.leaf(t, func(c *x509.Certificate) { c.NotBefore = f.now.Add(-f.p.MaxBackdate).Add(3 * time.Second) })
	shortProof, err := v.Validate(context.Background(), f.material, f.spec, nearBackdate, nil)
	if err != nil || shortProof.ValidAt(f.now.Add(3*time.Second)) {
		t.Fatal("receipt outlived approved backdating window", err)
	}
	bad := f.material
	bad.NonExportable = false
	if _, err := v.Validate(context.Background(), bad, f.spec, leaf, nil); !errors.Is(err, ErrCSR) {
		t.Fatal("missing device key proof accepted", err)
	}
	bad = f.material
	bad.DER = bytes.Clone(f.material.DER)
	bad.DER[len(bad.DER)-1] ^= 1
	if _, err := v.Validate(context.Background(), bad, f.spec, leaf, nil); !errors.Is(err, ErrCSR) {
		t.Fatal("bad recorded CSR signature accepted", err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Validate(context.Background(), f.material, f.spec, leaf, nil); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestChainConstraintsAndTimeCannotBeBypassed(t *testing.T) {
	for name, change := range map[string]func(*x509.Certificate){
		"expired-issuer": func(c *x509.Certificate) { c.NotAfter = time.Now().Add(-time.Hour) },
		"future-issuer":  func(c *x509.Certificate) { c.NotBefore = time.Now().Add(time.Hour) },
		"name-constraint": func(c *x509.Certificate) {
			c.PermittedDNSDomainsCritical = true
			c.PermittedDNSDomains = []string{"other.example.test"}
		},
		"CA-purpose": func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c := *f.issuer
			change(&c)
			der, err := x509.CreateCertificate(rand.Reader, &c, f.root, &f.issuerKey.PublicKey, f.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			f.issuer, err = x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			f.p.Intermediates = [][]byte{der}
			f.p.IssuerSHA256 = []string{SHA256(der)}
			if _, err := f.validator(t, f.p, nil, nil).Validate(context.Background(), f.material, f.spec, f.leaf(t, nil), nil); !errors.Is(err, ErrChain) {
				t.Fatal("invalid issuer accepted", err)
			}
		})
	}
}

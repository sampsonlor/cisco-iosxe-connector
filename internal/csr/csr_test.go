package csr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net"
	"testing"
)

func spec() Spec {
	return Spec{CommonName: "router.example.test", Organization: "Example", OrganizationalUnit: "Infrastructure", DNSNames: []string{"router.example.test", "router"}, RSABits: 2048}
}

func TestCSRRejectsUnrequestedExtensionsAndSignaturePolicy(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	for name, change := range map[string]func(*x509.CertificateRequest){
		"CA-extension": func(q *x509.CertificateRequest) {
			q.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: []byte{0x30, 0}}}
		},
		"IP-SAN":              func(q *x509.CertificateRequest) { q.IPAddresses = []net.IP{net.ParseIP("192.0.2.10")} },
		"signature-algorithm": func(q *x509.CertificateRequest) { q.SignatureAlgorithm = x509.SHA384WithRSA },
	} {
		t.Run(name, func(t *testing.T) {
			q := &x509.CertificateRequest{Subject: pkix.Name{CommonName: spec().CommonName, Organization: []string{"Example"}, OrganizationalUnit: []string{"Infrastructure"}}, DNSNames: spec().DNSNames, SignatureAlgorithm: x509.SHA256WithRSA}
			change(q)
			der, err := x509.CreateCertificateRequest(rand.Reader, q, key)
			if err != nil {
				t.Fatal(err)
			}
			if Validate(Result{DER: der, PublicKeyDER: pub, NonExportable: true}, spec()) == nil {
				t.Fatal("unrequested CSR content accepted")
			}
		})
	}
}
func TestCSRSignatureNamesAndDeviceKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	makeRequest := func(cn string, names []string) []byte {
		raw, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn, Organization: []string{"Example"}, OrganizationalUnit: []string{"Infrastructure"}}, DNSNames: names, SignatureAlgorithm: x509.SHA256WithRSA}, key)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	r := Result{DER: makeRequest(spec().CommonName, spec().DNSNames), PublicKeyDER: pub, NonExportable: true}
	if err := Validate(r, spec()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Result){"bad-signature": func(r *Result) { r.DER = append([]byte(nil), r.DER...); r.DER[len(r.DER)-1] ^= 1 }, "extra-san": func(r *Result) { r.DER = makeRequest(spec().CommonName, append(spec().DNSNames, "other.example.test")) }, "subject": func(r *Result) { r.DER = makeRequest("other.example.test", spec().DNSNames) }, "key": func(r *Result) { r.PublicKeyDER = nil }, "exportable": func(r *Result) { r.NonExportable = false }} {
		t.Run(name, func(t *testing.T) {
			bad := r
			change(&bad)
			if Validate(bad, spec()) == nil {
				t.Fatal("invalid CSR accepted")
			}
		})
	}
	bad := spec()
	bad.RSABits = 3072
	if Validate(r, bad) == nil {
		t.Fatal("wrong key size accepted")
	}
	for _, cn := range []string{"router;end", "router\nend", "*.example.test", "router,OU=Injected"} {
		bad := spec()
		bad.CommonName = cn
		if _, err := Normalize(bad); err == nil {
			t.Fatal("unsafe CN accepted")
		}
	}
	bad = spec()
	bad.Organization = "Example,OU=Injected"
	if _, err := Normalize(bad); err == nil {
		t.Fatal("DN injection accepted")
	}
	bad = spec()
	bad.DNSNames = []string{"router.example.test", "ROUTER.EXAMPLE.TEST"}
	if _, err := Normalize(bad); err == nil {
		t.Fatal("duplicate SAN accepted")
	}
	if KeyLabel("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee") != "ILM-K-aaaaaaaabbbb4ccc8dddeeeeeeeeeeee" || KeyLabel("bad") != "" {
		t.Fatal("key labels not bound to operation")
	}
}

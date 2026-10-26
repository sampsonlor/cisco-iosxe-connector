package lifecycle_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
)

func stageEvidence(q staging.Request, baseline, root []byte, complete, parent bool) device.Evidence {
	e := device.Evidence{Complete: true, Raw: map[device.Operation][]byte{}, Capabilities: map[device.Operation]device.Capability{}}
	var names, pems strings.Builder
	add := func(name string, ca, leaf []byte) {
		fmt.Fprintf(&names, "Trustpoint %s:\n    Subject Name:\n    cn=Synthetic\n", name)
		fmt.Fprintf(&pems, "------Trustpoint: %s------\n", name)
		if len(ca) == 0 && len(leaf) == 0 {
			fmt.Fprintf(&pems, "%% The specified trustpoint is not enrolled (%s).\n", name)
			return
		}
		names.WriteString("    Certificate configured.\n")
		if len(ca) != 0 {
			pems.WriteString("% CA certificate:\n")
			pems.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca}))
		}
		if len(leaf) != 0 {
			pems.WriteString("% General Purpose Certificate:\n")
			pems.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}))
		}
	}
	add(q.CSR.ActiveTrustpoint, root, baseline)
	if complete {
		add(q.CSR.Trustpoint, q.ChainDER[1], q.LeafDER)
	} else {
		add(q.CSR.Trustpoint, nil, nil)
	}
	if parent {
		add("ROOT-PREPROVISIONED", root, nil)
	}
	e.Raw[device.ReadVersion] = []byte("Cisco IOS XE Software, Version 26.01.02\n")
	e.Raw[device.ReadPKI] = []byte(names.String())
	e.Raw[device.ReadCertificates] = []byte(pems.String())
	e.Raw[device.ReadBinding] = []byte("ip http secure-trustpoint " + q.CSR.ActiveTrustpoint + "\n")
	e.Raw[device.ReadHTTPSStatus] = []byte("HTTP secure server status: Enabled\nHTTP secure server port: 443\nHTTP secure server trustpoint: " + q.CSR.ActiveTrustpoint + "\n")
	for op := range e.Raw {
		e.Capabilities[op] = device.Capability{Available: true, Transport: "ssh"}
	}
	return e
}
func TestStageInventoryKeepsBaselineSeparateFromCandidateAndAncestors(t *testing.T) {
	f := newStageFixture(t)
	csrRequest, err := f.s.CSRRequest(context.Background(), f.r.Ref())
	stageMust(t, err)
	q := staging.Request{CSR: csrRequest, Material: f.material, LeafDER: f.leaf, ChainDER: [][]byte{f.leaf, f.root}}
	before := stageEvidence(q, f.baseline, f.root, false, false)
	first, err := inventory.VerifyStageInventory(before, q, nil)
	stageMust(t, err)
	after := stageEvidence(q, f.baseline, f.root, true, false)
	last, err := inventory.VerifyStageInventory(after, q, nil)
	stageMust(t, err)
	if first.OtherStateSHA256 != last.OtherStateSHA256 || !bytes.Equal(last.ActiveDER, f.baseline) || !bytes.Equal(last.LeafDER, f.leaf) || !bytes.Equal(last.IssuerDER, f.root) || last.NonExportable || len(last.PublicKeyDER) != 0 {
		t.Fatal("inventory conflated active/staged or fabricated device key proof")
	}
	after.Raw[device.ReadBinding] = []byte("ip http secure-trustpoint " + q.CSR.Trustpoint + "\n")
	if _, err := inventory.VerifyStageInventory(after, q, nil); err == nil {
		t.Fatal("binding drift was accepted")
	}
	root, err := x509.ParseCertificate(f.root)
	stageMust(t, err)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	stageMust(t, err)
	inter := &x509.Certificate{SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "Synthetic intermediate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(2, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	interDER, err := x509.CreateCertificate(rand.Reader, inter, root, &interKey.PublicKey, f.baselineTLS.PrivateKey)
	stageMust(t, err)
	inter, err = x509.ParseCertificate(interDER)
	stageMust(t, err)
	leaf, err := x509.ParseCertificate(f.leaf)
	stageMust(t, err)
	q.LeafDER, err = x509.CreateCertificate(rand.Reader, leaf, inter, leaf.PublicKey, interKey)
	stageMust(t, err)
	q.ChainDER = [][]byte{q.LeafDER, interDER, f.root}
	e := stageEvidence(q, f.baseline, f.root, true, true)
	if _, err := inventory.VerifyStageInventory(e, q, nil); err == nil {
		t.Fatal("implicit parent CA lookup adopted")
	}
	ancestors := map[string]string{certpolicy.SHA256(f.root): "ROOT-PREPROVISIONED"}
	if _, err := inventory.VerifyStageInventory(e, q, ancestors); err != nil {
		t.Fatal("explicit unchanged ancestor unavailable", err)
	}
	ancestors[certpolicy.SHA256(f.root)] = "MISSING"
	if _, err := inventory.VerifyStageInventory(e, q, ancestors); err == nil {
		t.Fatal("missing ancestor accepted")
	}
}

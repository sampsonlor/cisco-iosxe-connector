package device

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
	"golang.org/x/crypto/ssh"
)

func stageWire(t *testing.T, mode string) (*fixture, *StageAdapter, staging.Request, *atomic.Int32) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	spec := csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test"}, RSABits: 2048}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: spec.CommonName}, DNSNames: spec.DNSNames, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	if err != nil {
		t.Fatal(err)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Synthetic staging root"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0)}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ = x509.ParseCertificate(caDER)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: spec.CommonName}, DNSNames: spec.DNSNames, KeyUsage: x509.KeyUsageDigitalSignature, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf.SerialNumber = big.NewInt(3)
	baseline, err := x509.CreateCertificate(rand.Reader, leaf, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	q := staging.Request{CSR: csr.Request{OperationID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", DeviceID: "router-a", Target: "192.0.2.10", PolicySHA256: strings.Repeat("a", 64), ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: certpolicy.SHA256(baseline), Trustpoint: "HTTPS-STAGE-A", Spec: spec}, Material: csr.Result{DER: request, PublicKeyDER: pub, NonExportable: true}, LeafDER: leafDER, ChainDER: [][]byte{leafDER, caDER}}
	var stateMu sync.Mutex
	var installedCA, installedLeaf []byte
	count := &atomic.Int32{}
	f := &fixture{}
	config := "crypto pki trustpoint HTTPS-LIVE\n rsakeypair LIVE-KEY\n!\ncrypto pki trustpoint HTTPS-STAGE-A\n enrollment terminal pem\n serial-number none\n fqdn none\n ip-address none\n subject-name CN=router.example.test\n subject-alt-name router.example.test\n rsakeypair " + q.CSR.KeyLabel() + "\n hash sha256\n!\n"
	f.commandOutput = func(command string) string {
		switch command {
		case "show version":
			return "Cisco IOS XE Software, Version 26.01.02\n"
		case "show ntp status":
			if mode == "ntp" {
				return "%NTP is not enabled.\n"
			}
			return "Clock is synchronized, stratum 2\n"
		case "show running-config | section ^crypto pki trustpoint":
			if mode == "wrong-key-binding" {
				return strings.ReplaceAll(config, "rsakeypair "+q.CSR.KeyLabel(), "rsakeypair OTHER")
			}
			return config
		case "show crypto key mypubkey rsa":
			flag := "not exportable"
			if mode == "exportable" {
				flag = "exportable"
			}
			return "Key name: " + q.CSR.KeyLabel() + "\nKey type: RSA KEYS 2048 bits\nKey is " + flag + ".\nKey Data:\n" + strings.ToUpper(hex.EncodeToString(pub)) + "\n"
		case "show crypto key mypubkey ec":
			return "\n"
		default:
			return "synthetic operational reply\n"
		}
	}
	f.csrShell = func(ch ssh.Channel) {
		_, _ = io.WriteString(ch, "Router#")
		r := bufio.NewReader(ch)
		prompt := "Router#"
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			cmd := strings.TrimSpace(line)
			f.record("cli:" + cmd)
			switch cmd {
			case "configure terminal":
				prompt = "Router(config)#"
			case "end":
				prompt = "Router#"
			case "crypto pki authenticate HTTPS-STAGE-A", "crypto pki import HTTPS-STAGE-A certificate":
				if mode == "denied" {
					_, _ = io.WriteString(ch, "% Authorization failed\n"+prompt)
					continue
				}
				if mode == "overwrite" {
					_, _ = io.WriteString(ch, "Do you want to overwrite the existing certificate? [yes/no]:")
					_, _ = io.Copy(io.Discard, ch)
					return
				}
				isCA := strings.Contains(cmd, "authenticate")
				description := ""
				if isCA {
					description = "CA "
				}
				_, _ = io.WriteString(ch, "Enter the base 64 encoded "+description+"certificate.\nEnd with a blank line or the word \"quit\" on a line by itself\n")
				var b strings.Builder
				for {
					line, err = r.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimSpace(line) == "quit" {
						break
					}
					b.WriteString(line)
				}
				block, rest := pem.Decode([]byte(b.String()))
				want := q.LeafDER
				if isCA {
					want = q.ChainDER[1]
				}
				if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, want) {
					t.Error("incorrect public certificate payload")
					return
				}
				if isCA {
					h := sha1.Sum(want)
					display := strings.ToUpper(hex.EncodeToString(h[:]))
					if mode == "fingerprint" {
						display = strings.Repeat("0", 40)
					}
					strong := ""
					if mode == "malformed-strong-fingerprint" {
						strong = "Fingerprint SHA256: invalid-diagnostic\n"
					}
					_, _ = io.WriteString(ch, "Certificate has the following attributes:\nFingerprint SHA1: "+display+"\n"+strong+"% Do you accept this certificate? [yes/no]: ")
					answer, err := r.ReadString('\n')
					if err != nil {
						return
					}
					f.record("answer:" + strings.TrimSpace(answer))
					if strings.TrimSpace(answer) != "yes" {
						return
					}
					stateMu.Lock()
					installedCA = bytes.Clone(want)
					stateMu.Unlock()
					count.Add(1)
					_, _ = io.WriteString(ch, "Trustpoint CA certificate accepted.\n% Certificate successfully imported\n")
				} else {
					stateMu.Lock()
					installedLeaf = bytes.Clone(want)
					stateMu.Unlock()
					count.Add(1)
					if mode == "lost-leaf-reply" {
						return
					}
					if mode == "stderr" {
						_, _ = io.WriteString(ch.Stderr(), "synthetic private diagnostic")
						_, _ = io.Copy(io.Discard, ch)
						return
					}
					_, _ = io.WriteString(ch, "% Router Certificate successfully imported\n")
				}
			default:
				t.Error("forbidden interactive command", cmd)
				return
			}
			_, _ = io.WriteString(ch, prompt)
		}
	}
	f = startFixture(t, f)
	c := testClient(t, f, true, true)
	q.CSR.HostKeySHA256 = ssh.FingerprintSHA256(f.signer.PublicKey())
	policy := StagePolicy{CSRPolicy: CSRPolicy{AllowWrites: true, Version: "26.01.02", PolicySHA256: q.CSR.PolicySHA256, Spec: spec, StagingTrustpoints: []string{"HTTPS-STAGE-A"}, ProtectedNames: []string{"HTTPS-LIVE", "LIVE-KEY"}}}
	a, err := NewStageAdapter(c, map[string]StagePolicy{"router-a": policy}, func(e Evidence, _ staging.Request, _ map[string]string) (staging.Observation, error) {
		if !e.Complete {
			return staging.Observation{}, ErrPolicy
		}
		stateMu.Lock()
		defer stateMu.Unlock()
		return staging.Observation{ActiveTrustpoint: q.CSR.ActiveTrustpoint, ActiveDER: baseline, IssuerDER: bytes.Clone(installedCA), LeafDER: bytes.Clone(installedLeaf), OtherStateSHA256: strings.Repeat("b", 64)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, a, q, count
}
func TestStageSSHImportsOnlyPublicCertificatesIntoReservedSlot(t *testing.T) {
	f, a, q, count := stageWire(t, "")
	var authorizations int
	err := a.Import(context.Background(), q, func(context.Context) error { authorizations++; return nil })
	if err != nil {
		t.Fatal(err, f.logs())
	}
	if count.Load() != 2 || authorizations < 2 {
		t.Fatal("missing CA/leaf scope or dispatch rechecks")
	}
	o, err := a.Inspect(context.Background(), q)
	if err != nil || o.Check(q, "") != nil || !o.Complete(q) {
		t.Fatal("independent key/readback proof missing", err)
	}
	assertNoStageActivation(t, f.logs())
}
func assertNoStageActivation(t *testing.T, logs []string) {
	t.Helper()
	for _, line := range logs {
		for _, bad := range []string{"secure-trustpoint ", "write memory", "copy running", "key generate", "zeroize", "no crypto", "revocation-check", "pkcs12", "exportable", "rpc:"} {
			if strings.Contains(line, bad) {
				t.Fatal("forbidden staging side effect", line)
			}
		}
	}
}
func TestStageSSHRejectsUnsafeEvidenceAndNeverAnswersOverwrite(t *testing.T) {
	for _, mode := range []string{"ntp", "wrong-key-binding", "exportable", "denied", "overwrite", "fingerprint", "malformed-strong-fingerprint", "lost-leaf-reply", "stderr"} {
		t.Run(mode, func(t *testing.T) {
			f, a, q, count := stageWire(t, mode)
			err := a.Import(context.Background(), q, func(context.Context) error { return nil })
			if err == nil || strings.Contains(err.Error(), "private diagnostic") {
				t.Fatal("unsafe import accepted or diagnostic leaked", err)
			}
			if mode == "overwrite" || mode == "fingerprint" || mode == "malformed-strong-fingerprint" {
				for _, line := range f.logs() {
					if line == "answer:yes" {
						t.Fatal("unverified acceptance prompt answered")
					}
				}
			}
			if mode == "ntp" || mode == "wrong-key-binding" || mode == "exportable" {
				if count.Load() != 0 {
					t.Fatal("unsafe preflight imported certificate")
				}
			}
			assertNoStageActivation(t, f.logs())
		})
	}
}
func TestStageSSHDispatchAuthorizationStopsBeforeWrites(t *testing.T) {
	f, a, q, count := stageWire(t, "")
	err := a.Import(context.Background(), q, func(context.Context) error { return errors.New("synthetic policy denial") })
	if err == nil || count.Load() != 0 {
		t.Fatal("denied dispatch mutated device", err)
	}
	assertNoStageActivation(t, f.logs())
}

func TestStageSSHIdentityScopeAndExplicitWritePolicy(t *testing.T) {
	for _, mode := range []string{"target", "host-key", "trustpoint-injection", "policy", "wrong-leaf"} {
		t.Run(mode, func(t *testing.T) {
			f, a, q, count := stageWire(t, "")
			switch mode {
			case "target":
				q.CSR.Target = "192.0.2.11"
			case "host-key":
				q.CSR.HostKeySHA256 = "SHA256:unapproved"
			case "trustpoint-injection":
				q.CSR.Trustpoint = "HTTPS-STAGE-A;write memory"
			case "policy":
				q.CSR.PolicySHA256 = strings.Repeat("b", 64)
			case "wrong-leaf":
				q.LeafDER = q.ChainDER[1]
			}
			if err := a.Import(context.Background(), q, func(context.Context) error { return nil }); err == nil || f.auth.Load() != 0 || count.Load() != 0 {
				t.Fatal("unsafe target reached authentication or write", err)
			}
		})
	}
	f, a, q, _ := stageWire(t, "")
	p := a.policies[q.CSR.DeviceID]
	p.AllowWrites = false
	if _, err := NewStageAdapter(a.client, map[string]StagePolicy{q.CSR.DeviceID: p}, a.verify); err == nil {
		t.Fatal("default-disabled writes enabled")
	}
	p.AllowWrites = true
	p.Ancestors = map[string]string{strings.Repeat("a", 64): "UNAPPROVED-ROOT"}
	if _, err := NewStageAdapter(a.client, map[string]StagePolicy{q.CSR.DeviceID: p}, a.verify); err == nil {
		t.Fatal("unprotected ancestor accepted")
	}
	if f.auth.Load() != 0 {
		t.Fatal("constructor validation authenticated")
	}
}

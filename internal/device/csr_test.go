package device

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
	"golang.org/x/crypto/ssh"
)

func csrWire(t *testing.T, mode string) (*fixture, *CSRAdapter, csr.Request, *atomic.Int32) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oldPub, _ := x509.MarshalPKIXPublicKey(&oldKey.PublicKey)
	if mode == "reused-key" {
		oldPub = pub
	}
	var configMu sync.Mutex
	var stageLines []string
	spec := csr.Spec{CommonName: "router.example.test", DNSNames: []string{"router.example.test"}, RSABits: 2048}
	names := spec.DNSNames
	if mode == "wrong-san" {
		names = []string{"other.example.test"}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: spec.CommonName}, DNSNames: names, SignatureAlgorithm: x509.SHA256WithRSA}, key)
	if err != nil {
		t.Fatal(err)
	}
	var generated, configured atomic.Bool
	count := &atomic.Int32{}
	q := csr.Request{OperationID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", DeviceID: "router-a", Target: "192.0.2.10", PolicySHA256: strings.Repeat("a", 64), ActiveTrustpoint: "HTTPS-LIVE", BaselineSHA256: strings.Repeat("b", 64), Trustpoint: "HTTPS-STAGE-A", Spec: spec}
	keyText := func(name string) string {
		der := pub
		if name == "LIVE-KEY" || name == "OLD-KEY" {
			der = oldPub
		}
		return "% Key pair was generated at: 12:00:00 UTC Oct 23 2026\nKey name: " + name + "\nKey type: RSA KEYS 2048 bits\n Usage: General Purpose Key\n Key is not exportable.\n Key Data:\n  " + strings.ToUpper(hex.EncodeToString(der)) + "\n"
	}
	f := &fixture{}
	f.commandOutput = func(command string) string {
		switch command {
		case "show version":
			if mode == "wrong-version" {
				return "Cisco IOS XE Software, Version 0.0.0\n"
			}
			return "Cisco IOS XE Software, Version 26.01.02\n"
		case "show ntp status":
			if mode == "ntp-disabled" {
				return "%NTP is not enabled."
			}
			return "Clock is synchronized, stratum 2\n"
		case "show running-config | section ^crypto pki trustpoint":
			out := "crypto pki trustpoint HTTPS-LIVE\n rsakeypair LIVE-KEY\n!\ncrypto pki trustpoint HTTPS-OLD\n rsakeypair OLD-KEY\n!\n"
			if mode == "occupied-tp" || configured.Load() {
				configMu.Lock()
				out += "crypto pki trustpoint HTTPS-STAGE-A\n " + strings.Join(stageLines, "\n ") + "\n!\n"
				configMu.Unlock()
			}
			return out
		case "show crypto key mypubkey rsa":
			out := keyText("LIVE-KEY") + keyText("OLD-KEY")
			if generated.Load() || mode == "occupied-key" {
				out += keyText(q.KeyLabel())
			}
			return out
		case "show crypto key mypubkey ec":
			return "\n"
		default:
			if command == "show crypto key mypubkey rsa "+q.KeyLabel() {
				if mode == "exportable" {
					return strings.ReplaceAll(keyText(q.KeyLabel()), "not exportable", "exportable")
				}
				return keyText(q.KeyLabel())
			}
			return "synthetic successful read\n"
		}
	}
	f.csrShell = func(ch ssh.Channel) {
		_, _ = io.WriteString(ch, "Router#")
		reader := bufio.NewReader(ch)
		prompt := "Router#"
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.TrimSpace(line)
			f.record("cli:" + command)
			switch {
			case strings.HasPrefix(command, "show "):
				_, _ = io.WriteString(ch, f.commandOutput(command))
			case command == "configure terminal":
				prompt = "Router(config)#"
			case command == "end":
				prompt = "Router#"
			case command == "exit":
				prompt = "Router(config)#"
			case strings.HasPrefix(command, "crypto key generate rsa "):
				count.Add(1)
				if mode == "stderr" {
					_, _ = io.WriteString(ch.Stderr(), "private device diagnostic")
					_, _ = io.Copy(io.Discard, ch)
					return
				}
				if mode == "replace" {
					_, _ = io.WriteString(ch, "Do you really want to replace them? [yes/no]: ")
					_, _ = io.Copy(io.Discard, ch)
					return
				}
				if mode == "key-timeout" {
					_, _ = io.Copy(io.Discard, ch)
					return
				}
				if mode == "denied" {
					_, _ = io.WriteString(ch, "% Authorization failed\n"+prompt)
					continue
				}
				generated.Store(true)
				_, _ = io.WriteString(ch, "% Generating 2048 bit RSA keys, keys will be non-exportable...\n[OK]\n")
			case strings.HasPrefix(command, "crypto pki trustpoint "):
				configured.Store(true)
				prompt = "Router(ca-trustpoint)#"
			case strings.HasPrefix(command, "crypto pki enroll "):
				if mode == "unknown-prompt" {
					_, _ = io.WriteString(ch, "Enter challenge password: ")
					_, _ = io.Copy(io.Discard, ch)
					return
				}
				_, _ = io.WriteString(ch, "% Start certificate enrollment ..\nDisplay Certificate Request to terminal? [yes/no]: ")
				answer, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				f.record("answer:" + strings.TrimSpace(answer))
				if strings.TrimSpace(answer) != "yes" {
					return
				}
				_, _ = io.WriteString(ch, "Certificate Request follows:\n"+string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))+"---End - This line not part of the certificate request---\nRedisplay enrollment request? [yes/no]: ")
				answer, err = reader.ReadString('\n')
				if err != nil {
					return
				}
				f.record("answer:" + strings.TrimSpace(answer))
				if strings.TrimSpace(answer) != "no" {
					return
				}
			default:
				if prompt == "Router(ca-trustpoint)#" {
					configMu.Lock()
					stageLines = append(stageLines, command)
					configMu.Unlock()
				}
			}
			_, _ = io.WriteString(ch, prompt)
		}
	}
	f = startFixture(t, f)
	client := testClient(t, f, false, true)
	if mode == "key-timeout" {
		client.timeout = 2 * time.Second
	}
	q.HostKeySHA256 = ssh.FingerprintSHA256(f.signer.PublicKey())
	policy := CSRPolicy{AllowWrites: true, Version: "26.01.02", PolicySHA256: q.PolicySHA256, Spec: spec, StagingTrustpoints: []string{"HTTPS-STAGE-A"}, ProtectedNames: []string{"HTTPS-LIVE", "HTTPS-OLD", "LIVE-KEY", "OLD-KEY"}}
	adapter, err := NewCSRAdapter(client, map[string]CSRPolicy{"router-a": policy}, func(e Evidence, r csr.Request) error {
		if !e.Complete || r.BaselineSHA256 != q.BaselineSHA256 {
			return ErrPolicy
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return f, adapter, q, count
}

func TestCSRFixedCLIAndNonExportableProof(t *testing.T) {
	f, a, q, count := csrWire(t, "")
	result, err := a.Generate(context.Background(), q)
	if err != nil {
		t.Fatal(err, f.logs())
	}
	if count.Load() != 1 || csr.Validate(result, q.Spec) != nil {
		t.Fatal("CSR/public key/non-exportability not verified")
	}
	logs := f.logs()
	if !slices.Contains(logs, "cli:crypto key generate rsa general-keys modulus 2048 label "+q.KeyLabel()) {
		t.Fatal("unlabelled or wrong key command")
	}
	for _, line := range logs {
		for _, forbidden := range []string{"exportable", "zeroize", "no crypto", "secure-trustpoint", "write memory", "copy running", "enable"} {
			if strings.HasPrefix(line, "cli:") && strings.Contains(line, forbidden) {
				t.Fatal("forbidden mutation", line)
			}
		}
	}
	if !slices.Contains(logs, "answer:yes") || !slices.Contains(logs, "answer:no") {
		t.Fatal("expected bounded enrollment dialogue missing")
	}
}
func TestCSRRejectsOccupiedAndUnverifiedTargets(t *testing.T) {
	for _, mode := range []string{"occupied-tp", "occupied-key", "wrong-version", "ntp-disabled"} {
		t.Run(mode, func(t *testing.T) {
			f, a, q, count := csrWire(t, mode)
			if _, err := a.Generate(context.Background(), q); err == nil || count.Load() != 0 || slices.Contains(f.logs(), "shell") {
				t.Fatal("unsafe preflight reached writes", err)
			}
		})
	}
}
func TestCSRStopsUnexpectedPromptsAndUnknownWrites(t *testing.T) {
	for _, mode := range []string{"replace", "key-timeout", "denied", "unknown-prompt", "wrong-san", "exportable", "reused-key", "stderr"} {
		t.Run(mode, func(t *testing.T) {
			f, a, q, count := csrWire(t, mode)
			result, err := a.Generate(context.Background(), q)
			if err == nil || len(result.DER) != 0 || count.Load() != 1 {
				t.Fatal("failed mutation exposed CSR or retried key generation", err)
			}
			if mode == "replace" && slices.Contains(f.logs(), "answer:yes") {
				t.Fatal("replacement prompt answered")
			}
			if errors.Is(err, ErrAuthentication) {
				t.Fatal("prompt error misclassified as authentication")
			}
		})
	}
}

func TestCSRAdapterRequiresExplicitWritePolicy(t *testing.T) {
	f, a, q, _ := csrWire(t, "")
	p := a.policies[q.DeviceID]
	p.AllowWrites = false
	if _, err := NewCSRAdapter(a.client, map[string]CSRPolicy{q.DeviceID: p}, a.verify); err == nil {
		t.Fatal("default-disabled writes enabled")
	}
	p.AllowWrites = true
	p.Spec.RSABits = 1024
	if _, err := NewCSRAdapter(a.client, map[string]CSRPolicy{q.DeviceID: p}, a.verify); err == nil {
		t.Fatal("weak key policy accepted")
	}
	if f.auth.Load() != 0 {
		t.Fatal("invalid write policy authenticated")
	}
}
func TestCSRIdentityAndInjectionFailBeforeAuth(t *testing.T) {
	f, a, q, count := csrWire(t, "")
	for _, change := range []func(*csr.Request){func(q *csr.Request) { q.HostKeySHA256 = "SHA256:wrong" }, func(q *csr.Request) { q.Trustpoint = "HTTPS-OLD" }, func(q *csr.Request) { q.Spec.CommonName = "bad\nend" }, func(q *csr.Request) { q.Target = "192.0.2.11" }} {
		bad := q
		change(&bad)
		if _, err := a.Generate(context.Background(), bad); err == nil || count.Load() != 0 {
			t.Fatal("unapproved request reached mutation")
		}
	}
	if f.auth.Load() != 0 {
		t.Fatal("policy/identity failure authenticated")
	}
}

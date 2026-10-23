package device

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const baseNS = "urn:ietf:params:xml:ns:netconf:base:1.0"
const pkiNS = "http://cisco.com/ns/yang/Cisco-IOS-XE-crypto-pki-oper"
const nativeNS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
const httpNS = "http://cisco.com/ns/yang/Cisco-IOS-XE-http"

type fixture struct {
	signer          ssh.Signer
	listener        net.Listener
	wg              sync.WaitGroup
	mu              sync.Mutex
	log             []string
	auth            atomic.Int32
	connections     []net.Conn
	acceptDone      chan struct{}
	modules         []string
	chunked         bool
	subsystemReject bool
	rpcError        string
	wrongID         bool
	cliOutput       string
	stall           bool
	malformed       string
	clientKey       ssh.PublicKey
	oneSession      bool
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func (f *fixture) record(s string) { f.mu.Lock(); defer f.mu.Unlock(); f.log = append(f.log, s) }
func (f *fixture) logs() []string  { f.mu.Lock(); defer f.mu.Unlock(); return slices.Clone(f.log) }
func startFixture(t *testing.T, f *fixture) *fixture {
	t.Helper()
	f.signer = newSigner(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.listener = ln
	f.acceptDone = make(chan struct{})
	cfg := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, b []byte) (*ssh.Permissions, error) {
		f.auth.Add(1)
		if string(b) != "synthetic-test-password" {
			return nil, errors.New("denied")
		}
		return nil, nil
	}}
	cfg.AddHostKey(f.signer)
	cfg.PublicKeyCallback = func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		f.auth.Add(1)
		if f.clientKey != nil && bytes.Equal(key.Marshal(), f.clientKey.Marshal()) {
			return nil, nil
		}
		return nil, errors.New("denied")
	}
	f.wg.Go(func() {
		defer close(f.acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.connections = append(f.connections, conn)
			f.mu.Unlock()
			f.wg.Go(func() {
				defer conn.Close()
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				sessionCount := 0
				for nc := range chans {
					if nc.ChannelType() != "session" {
						_ = nc.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					if f.oneSession && sessionCount > 0 {
						_ = nc.Reject(ssh.ResourceShortage, "one execution per connection")
						continue
					}
					sessionCount++
					ch, requests, err := nc.Accept()
					if err != nil {
						return
					}
					f.wg.Go(func() {
						defer ch.Close()
						for req := range requests {
							switch req.Type {
							case "subsystem":
								var m struct{ Name string }
								_ = ssh.Unmarshal(req.Payload, &m)
								f.record("subsystem:" + m.Name)
								_ = req.Reply(!f.subsystemReject, nil)
								if f.subsystemReject {
									return
								}
								if f.stall {
									_, _ = io.Copy(io.Discard, ch)
									return
								}
								f.netconf(ch)
								return
							case "exec":
								var m struct{ Command string }
								_ = ssh.Unmarshal(req.Payload, &m)
								f.record("exec:" + m.Command)
								_ = req.Reply(true, nil)
								out := f.cliOutput
								if out == "" {
									out = "synthetic successful read\n"
								}
								_, _ = io.WriteString(ch, out)
								_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
								return
							default:
								f.record("unexpected:" + req.Type)
								_ = req.Reply(false, nil)
							}
						}
					})
				}
			})
		}
	})
	t.Cleanup(func() {
		_ = ln.Close()
		<-f.acceptDone
		f.mu.Lock()
		for _, c := range f.connections {
			_ = c.Close()
		}
		f.mu.Unlock()
		f.wg.Wait()
	})
	return f
}
func readEOM(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		b.WriteByte(c)
		if strings.HasSuffix(b.String(), "]]>]]>") {
			s := b.String()
			return strings.TrimSuffix(s, "]]>]]>"), nil
		}
	}
}
func (f *fixture) netconf(ch ssh.Channel) {
	r := bufio.NewReader(ch)
	caps := `<capability>urn:ietf:params:netconf:base:1.0</capability>`
	if f.chunked {
		caps += `<capability>urn:ietf:params:netconf:base:1.1</capability>`
	}
	for _, m := range f.modules {
		caps += `<capability>` + m + `?module=` + strings.TrimPrefix(m, "http://cisco.com/ns/yang/") + `&amp;revision=2026-02-01</capability>`
	}
	_, _ = io.WriteString(ch, `<hello xmlns="`+baseNS+`"><capabilities>`+caps+`</capabilities><session-id>7</session-id></hello>]]>]]>`)
	if _, err := readEOM(r); err != nil {
		return
	}
	for {
		var raw string
		var err error
		if f.chunked {
			raw, err = fixtureChunkRead(r)
		} else {
			raw, err = readEOM(r)
		}
		if err != nil {
			return
		}
		f.record("rpc:" + raw)
		var v struct {
			ID string `xml:"message-id,attr"`
		}
		_ = xml.Unmarshal([]byte(raw), &v)
		if f.wrongID {
			v.ID = "wrong"
		}
		data := `<data><crypto-pki-oper-data xmlns="` + pkiNS + `"/></data>`
		if strings.Contains(raw, "<native ") {
			data = `<data><native xmlns="` + nativeNS + `"><ip><http xmlns="` + httpNS + `"><secure-trustpoint>HTTPS-ACTIVE</secure-trustpoint></http></ip></native></data>`
		}
		if f.rpcError != "" {
			data = `<rpc-error><error-type>protocol</error-type><error-tag>` + f.rpcError + `</error-tag><error-severity>error</error-severity></rpc-error>`
		}
		out := `<rpc-reply xmlns="` + baseNS + `" message-id="` + v.ID + `">` + data + `</rpc-reply>`
		if f.malformed != "" {
			out = f.malformed
		}
		if f.chunked {
			_, _ = fmt.Fprintf(ch, "\n#%d\n%s\n##\n", len(out), out)
		} else {
			_, _ = io.WriteString(ch, out+"]]>]]>")
		}
	}
}
func fixtureChunkRead(r *bufio.Reader) (string, error) {
	var out strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if line != "\n" {
			return "", errors.New("bad framing")
		}
		head, err := r.ReadString('\n')
		if err != nil {
			return "", err
		}
		if head == "##\n" {
			return out.String(), nil
		}
		var size int
		if _, err := fmt.Sscanf(head, "#%d\n", &size); err != nil || size <= 0 {
			return "", errors.New("bad chunk")
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		out.Write(b)
	}
}

type testResolver struct {
	key      ssh.PublicKey
	password string
}

func (r testResolver) Credentials(context.Context, string) (Credentials, error) {
	return Credentials{Username: "readonly-test", Password: r.password}, nil
}
func (r testResolver) HostKey(context.Context, string) (ssh.PublicKey, error) { return r.key, nil }
func testClient(t *testing.T, f *fixture, netconf, cli bool) *Client {
	t.Helper()
	target := Target{Address: netip.MustParseAddr("192.0.2.10")}
	if netconf {
		target.NETCONF = Endpoint{830, "secret://test/reader", "hostkey://test/netconf"}
	}
	if cli {
		target.CLI = &Endpoint{22, "secret://test/reader", "hostkey://test/ssh"}
	}
	c, err := NewClient(map[string]Target{"router-a": target}, testResolver{f.signer.PublicKey(), "synthetic-test-password"}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.dial = func(ctx context.Context, address string) (net.Conn, error) {
		if address != "192.0.2.10:830" && address != "192.0.2.10:22" {
			t.Fatalf("unapproved address: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", f.listener.Addr().String())
	}
	return c
}
func TestReadCapabilitiesAndNETCONFPreference(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint(chunked), func(t *testing.T) {
			f := startFixture(t, &fixture{modules: []string{pkiNS, nativeNS, httpNS}, chunked: chunked})
			c := testClient(t, f, true, true)
			e, err := c.Collect(context.Background(), "router-a")
			if err != nil {
				t.Fatal(err)
			}
			if !e.Complete || e.Capabilities[ReadPKI].Transport != "netconf" || e.Capabilities[ReadBinding].Transport != "netconf" || e.Capabilities[ReadCertificates].Transport != "ssh" {
				t.Fatalf("capabilities: %+v", e.Capabilities)
			}
			for _, op := range []Operation{CSR, Import, Switch, Save} {
				if e.Capabilities[op].Available {
					t.Fatalf("write operation enabled: %s", op)
				}
			}
			for _, line := range f.logs() {
				if strings.HasPrefix(line, "exec:") && (strings.Contains(line, "trustpoints") || strings.Contains(line, "running-config")) {
					t.Fatalf("NETCONF read unnecessarily replaced: %s", line)
				}
			}
		})
	}
	f := startFixture(t, &fixture{modules: []string{pkiNS}})
	e, err := testClient(t, f, true, false).Collect(context.Background(), "router-a")
	if err != nil || e.Complete || !e.Capabilities[ReadPKI].Available || e.Capabilities[ReadBinding].Available || e.Capabilities[ReadCertificates].Available {
		t.Fatalf("partial models fabricated support: %+v %v", e, err)
	}
}
func TestReadOnlyAuditAndRepeatedDiscovery(t *testing.T) {
	f := startFixture(t, &fixture{modules: []string{pkiNS, nativeNS, httpNS}})
	c := testClient(t, f, true, true)
	for i := 0; i < 3; i++ {
		e, err := c.Collect(context.Background(), "router-a")
		if err != nil || !e.Complete || len(e.Audit) == 0 {
			t.Fatalf("discovery: %+v %v", e, err)
		}
	}
	assertReadOnlyAudit(t, f.logs())
	f2 := startFixture(t, &fixture{})
	e, err := testClient(t, f2, false, true).Collect(context.Background(), "router-a")
	if err != nil || !e.Complete {
		t.Fatalf("explicit CLI mode: %+v %v", e, err)
	}
	assertReadOnlyAudit(t, f2.logs())
}
func assertReadOnlyAudit(t *testing.T, lines []string) {
	t.Helper()
	if len(lines) == 0 {
		t.Fatal("no server-side audit")
	}
	allowed := []string{"show version", "show crypto pki trustpoints", "show crypto pki certificates pem", "show ip http server status", "show running-config | include ^ip http secure-trustpoint"}
	for _, line := range lines {
		switch {
		case line == "subsystem:netconf":
		case strings.HasPrefix(line, "exec:"):
			if !slices.Contains(allowed, strings.TrimPrefix(line, "exec:")) {
				t.Errorf("unapproved CLI: %s", line)
			}
		case strings.HasPrefix(line, "rpc:"):
			var root struct {
				XMLName xml.Name
				Get     *struct{} `xml:"get"`
			}
			if err := xml.Unmarshal([]byte(strings.TrimPrefix(line, "rpc:")), &root); err != nil || root.XMLName.Local != "rpc" || root.Get == nil {
				t.Errorf("non-read RPC: %s", line)
			}
		default:
			t.Errorf("unexpected request: %s", line)
		}
	}
}
func TestHostKeyFailsBeforeAuthentication(t *testing.T) {
	f := startFixture(t, &fixture{})
	c := testClient(t, f, true, true)
	c.resolver = testResolver{newSigner(t).PublicKey(), "synthetic-test-password"}
	_, err := c.Collect(context.Background(), "router-a")
	if !errors.Is(err, ErrHostKey) || f.auth.Load() != 0 || len(f.logs()) != 0 {
		t.Fatalf("host mismatch continued: auth=%d log=%v err=%v", f.auth.Load(), f.logs(), err)
	}
}
func TestAAADenialDoesNotFallback(t *testing.T) {
	f := startFixture(t, &fixture{modules: []string{pkiNS}, rpcError: "access-denied"})
	_, err := testClient(t, f, true, true).Collect(context.Background(), "router-a")
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("NETCONF denial: %v", err)
	}
	for _, l := range f.logs() {
		if strings.HasPrefix(l, "exec:") {
			t.Fatal("authorization denial caused CLI fallback")
		}
	}
	assertReadOnlyAudit(t, f.logs())
	f2 := startFixture(t, &fixture{cliOutput: "% Authorization failed: private transcript\n"})
	_, err = testClient(t, f2, false, true).Collect(context.Background(), "router-a")
	if !errors.Is(err, ErrPermission) || strings.Contains(err.Error(), "private transcript") {
		t.Fatalf("CLI denial leaked/ignored: %v", err)
	}
	if len(f2.logs()) != 1 {
		t.Fatalf("commands continued: %v", f2.logs())
	}
	f3 := startFixture(t, &fixture{subsystemReject: true})
	_, err = testClient(t, f3, true, true).Collect(context.Background(), "router-a")
	if !errors.Is(err, ErrSessionRejected) || len(f3.logs()) != 1 {
		t.Fatalf("ambiguous subsystem rejection downgraded: %v %v", err, f3.logs())
	}
}
func TestDeviceProtocolFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		f    *fixture
		want error
	}{
		{"wrong ID", &fixture{modules: []string{pkiNS}, wrongID: true}, ErrProtocol},
		{"DTD", &fixture{modules: []string{pkiNS}, malformed: `<!DOCTYPE x><rpc-reply/>`}, ErrProtocol},
		{"trailing XML", &fixture{modules: []string{pkiNS}, malformed: `<rpc-reply/><extra/>`}, ErrProtocol},
		{"paging", &fixture{cliOutput: "--More--"}, ErrRead},
		{"limit", &fixture{cliOutput: strings.Repeat("x", 8192)}, ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := startFixture(t, tc.f)
			c := testClient(t, f, len(f.modules) > 0, true)
			c.limit = 4096
			e, err := c.Collect(context.Background(), "router-a")
			if !errors.Is(err, tc.want) || e.Complete || len(e.Raw) > 0 {
				t.Fatalf("invalid response accepted: complete=%v err=%v", e.Complete, err)
			}
			assertReadOnlyAudit(t, f.logs())
		})
	}
	f := startFixture(t, &fixture{stall: true})
	c := testClient(t, f, true, true)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := c.Collect(ctx, "router-a")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline ignored: %v", err)
	}
}
func TestDevicePolicyAndAuthentication(t *testing.T) {
	f := startFixture(t, &fixture{})
	c := testClient(t, f, false, true)
	if _, err := c.Collect(context.Background(), "unapproved;reload"); !errors.Is(err, ErrPolicy) {
		t.Fatalf("unknown target accepted: %v", err)
	}
	c.resolver = testResolver{f.signer.PublicKey(), "wrong-test-password"}
	_, err := c.Collect(context.Background(), "router-a")
	if !errors.Is(err, ErrAuthentication) || len(f.logs()) != 0 {
		t.Fatalf("auth failure fallback: %v %v", err, f.logs())
	}
	bad := map[string]Target{"router-a": {Address: netip.MustParseAddr("192.0.2.10"), NETCONF: Endpoint{830, "secret://test/read", "hostkey://test/nc"}, CLI: &Endpoint{2222, "secret://test/recovery", "hostkey://test/cli"}}}
	if _, err := NewClient(bad, testResolver{}, time.Second); err == nil {
		t.Fatal("different fallback identity accepted")
	}
}

type keyResolver struct {
	testResolver
	signer ssh.Signer
}

func (r keyResolver) Credentials(context.Context, string) (Credentials, error) {
	return Credentials{Username: "readonly-test", Signers: []ssh.Signer{r.signer}}, nil
}
func TestDevicePublicKeyAuthentication(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, signer := range []ssh.Signer{newSigner(t), rsaSigner} {
		f := startFixture(t, &fixture{clientKey: signer.PublicKey()})
		c := testClient(t, f, false, true)
		c.resolver = keyResolver{testResolver: testResolver{key: f.signer.PublicKey()}, signer: signer}
		e, err := c.Collect(context.Background(), "router-a")
		if err != nil || !e.Complete {
			t.Fatalf("public key authentication: %v", err)
		}
		assertReadOnlyAudit(t, f.logs())
	}
}

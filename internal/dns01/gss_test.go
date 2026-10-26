package dns01

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	gssflags "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/miekg/dns"
)

const testKrbConfig = `[libdefaults]
 default_realm = EXAMPLE.TEST
 dns_lookup_kdc = false
 dns_lookup_realm = false
 allow_weak_crypto = false
 default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
[realms]
 EXAMPLE.TEST = {
  kdc = 192.0.2.88:88
 }
`

func TestADCredentialsRequireExplicitPinnedAESKerberosAndRedact(t *testing.T) {
	valid := Credentials{Realm: "EXAMPLE.TEST", Username: "dns-solver", Password: "synthetic-password", KerberosConfig: testKrbConfig}
	if !validCredentials(valid) {
		t.Fatal("explicit AES configuration refused")
	}
	for _, mutate := range []func(*Credentials){
		func(c *Credentials) { c.KerberosConfig = "" },
		func(c *Credentials) { c.Realm = "example.test" },
		func(c *Credentials) { c.Realm = "" },
		func(c *Credentials) { c.Username = "domain\\user" },
		func(c *Credentials) { c.Password = "" },
		func(c *Credentials) {
			c.KerberosConfig = strings.ReplaceAll(c.KerberosConfig, "192.0.2.88:88", "kdc.example.test:88")
		},
		func(c *Credentials) {
			c.KerberosConfig = strings.ReplaceAll(c.KerberosConfig, "dns_lookup_kdc = false", "dns_lookup_kdc = true")
		},
		func(c *Credentials) {
			c.KerberosConfig = strings.ReplaceAll(c.KerberosConfig, "allow_weak_crypto = false", "allow_weak_crypto = true")
		},
		func(c *Credentials) {
			c.KerberosConfig = strings.ReplaceAll(c.KerberosConfig, "aes128-cts-hmac-sha1-96", "rc4-hmac")
		},
	} {
		bad := valid
		mutate(&bad)
		if validCredentials(bad) {
			t.Fatal("unsafe Kerberos configuration accepted")
		}
		if _, err := negotiateGSS(context.Background(), Config{}, bad); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
	}
	raw, err := json.Marshal(valid)
	must(t, err)
	for _, out := range []string{fmt.Sprint(valid), fmt.Sprintf("%#v", valid), string(raw)} {
		if strings.Contains(out, valid.Password) || strings.Contains(out, valid.Username) || strings.Contains(out, "[libdefaults]") {
			t.Fatal("credential diagnostic leaked")
		}
	}
}

type testInitiator struct {
	t *testing.T
	testMIC
	calls                     int
	badMutual, oversize, loop bool
	name                      string
}

func (i *testInitiator) Initiate(spn string, flags int, input []byte) ([]byte, bool, error) {
	if spn != "DNS/dns.example.test" || flags&(gssflags.ContextFlagMutual|gssflags.ContextFlagInteg|gssflags.ContextFlagReplay) != (gssflags.ContextFlagMutual|gssflags.ContextFlagInteg|gssflags.ContextFlagReplay) {
		i.t.Error("wrong SPN or missing mutual/integrity/replay flags")
	}
	i.calls++
	if i.calls == 1 {
		if len(input) != 0 {
			i.t.Error("unexpected initial input")
		}
		if i.oversize {
			return bytes.Repeat([]byte{1}, 65536), true, nil
		}
		return []byte("synthetic-AP-REQ"), true, nil
	}
	if !bytes.Equal(input, []byte("synthetic-AP-REP")) || i.badMutual {
		return nil, false, ErrAuthentication
	}
	if i.loop {
		return []byte("synthetic-AP-REQ"), true, nil
	}
	return nil, false, nil
}

func TestGSSTKEYRequiresMutualContextAndSignedFinalPacket(t *testing.T) {
	for _, mode := range []string{"success", "unsigned-final", "tampered-final", "bad-mutual", "oversize-token", "bounded-rounds", "wrong-algorithm"} {
		t.Run(mode, func(t *testing.T) {
			initiator := &testInitiator{t: t, badMutual: mode == "bad-mutual", oversize: mode == "oversize-token", loop: mode == "bounded-rounds"}
			// TKEY replies are signed with the context established by the AP-REP.
			// A test MIC validates our packet orchestration independently of AD.
			dynamic := &dynamicTsig{mic: &testMIC{}}
			requests := make(chan struct{}, 10)
			address := startDNS(t, dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
				requests <- struct{}{}
				if len(req.Question) != 1 || req.Question[0].Qtype != dns.TypeTKEY || req.Question[0].Qclass != dns.ClassANY || len(req.Extra) != 1 {
					t.Error("unexpected TKEY framing")
					return
				}
				tkey, ok := req.Extra[0].(*dns.TKEY)
				if !ok || tkey.Mode != 3 || tkey.Algorithm != gssAlgorithm || tkey.Key != hex.EncodeToString([]byte("synthetic-AP-REQ")) {
					t.Error("unexpected TKEY token")
					return
				}
				res := new(dns.Msg)
				res.SetReply(req)
				answer := *tkey
				answer.Key = hex.EncodeToString([]byte("synthetic-AP-REP"))
				answer.KeySize = uint16(len("synthetic-AP-REP"))
				if mode == "wrong-algorithm" {
					answer.Algorithm = "hmac-sha256."
				}
				res.Answer = []dns.RR{&answer}
				if mode != "unsigned-final" {
					res.SetTsig(tkey.Hdr.Name, gssAlgorithm, 300, time.Now().Unix())
				}
				if mode == "tampered-final" {
					wire, _, err := dns.TsigGenerateWithProvider(res, dynamic, "", false)
					must(t, err)
					// Preserve parsability while changing a signed byte (AA flag).
					wire[2] ^= 4
					_, err = w.Write(wire)
					must(t, err)
				} else {
					must(t, w.WriteMsg(res))
				}
			}), dynamic)
			cfg := Config{ServerName: "dns.example.test.", ServerAddress: address, Timeout: time.Second}
			a, err := establishGSS(context.Background(), cfg, initiator)
			if mode == "success" {
				must(t, err)
				defer a.close()
				if initiator.calls != 2 || len(requests) != 1 {
					t.Fatal("unexpected handshake rounds")
				}
			} else if !errors.Is(err, ErrAuthentication) {
				t.Fatal("untrusted TKEY/context accepted", err)
			}
			if mode == "oversize-token" && len(requests) != 0 {
				t.Fatal("oversized token sent")
			}
			if mode == "bounded-rounds" && len(requests) != 4 {
				t.Fatal("continuation budget not enforced", len(requests))
			}
		})
	}
}

type dynamicTsig struct{ mic *testMIC }

func (p *dynamicTsig) Generate(b []byte, _ *dns.TSIG) ([]byte, error) { return p.mic.MakeSignature(b) }
func (p *dynamicTsig) Verify(b []byte, t *dns.TSIG) error {
	sig, err := hex.DecodeString(t.MAC)
	if err != nil {
		return err
	}
	return p.mic.VerifySignature(b, sig)
}

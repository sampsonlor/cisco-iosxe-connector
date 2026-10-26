package dns01

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"regexp"
	"strings"
	"time"

	kerberos "github.com/bodgit/gssapi"
	krbconfig "github.com/jcmturner/gokrb5/v8/config"
	gssflags "github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/miekg/dns"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

var username = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

func validCredentials(c Credentials) bool {
	if !username.MatchString(c.Username) || c.Password == "" || len(c.Password) > 2048 || strings.ContainsRune(c.Password, 0) || !journal.DNSIdentifier(strings.ToLower(c.Realm)) || c.Realm != strings.ToUpper(c.Realm) || len(c.KerberosConfig) == 0 || len(c.KerberosConfig) > 64<<10 {
		return false
	}
	k, err := krbconfig.NewFromString(c.KerberosConfig)
	if err != nil || k.LibDefaults.DefaultRealm != c.Realm || k.LibDefaults.DNSLookupKDC || k.LibDefaults.DNSLookupRealm || k.LibDefaults.AllowWeakCrypto || len(k.Realms) != 1 || k.Realms[0].Realm != c.Realm || len(k.Realms[0].KDC) == 0 || len(k.Realms[0].KDC) > 4 {
		return false
	}
	for _, address := range k.Realms[0].KDC {
		a, err := netip.ParseAddrPort(address)
		if err != nil || a.Port() != 88 || a.Addr().IsUnspecified() || a.Addr().IsMulticast() || a.Addr().Is4In6() || a.String() != address {
			return false
		}
	}
	for _, ids := range [][]int32{k.LibDefaults.DefaultTktEnctypeIDs, k.LibDefaults.DefaultTGSEnctypeIDs, k.LibDefaults.PermittedEnctypeIDs} {
		if len(ids) == 0 {
			return false
		}
		for _, id := range ids {
			if id != 17 && id != 18 {
				return false
			}
		}
	}
	return true
}
func negotiateGSS(ctx context.Context, cfg Config, credentials Credentials) (authContext, error) {
	if !validCredentials(credentials) {
		return nil, ErrAuthentication
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Explicit configuration and password prevent environment credential/cache
	// fallback. The third-party KDC login API has no context parameter; check
	// cancellation after it and before every TKEY exchange or mutation.
	initiator, err := kerberos.NewInitiator(kerberos.WithConfig[kerberos.Initiator](credentials.KerberosConfig), kerberos.WithDomain[kerberos.Initiator](credentials.Realm), kerberos.WithUsername[kerberos.Initiator](credentials.Username), kerberos.WithPassword[kerberos.Initiator](credentials.Password))
	if err != nil {
		return nil, ErrAuthentication
	}
	return establishGSS(ctx, cfg, initiator)
}

type initiatorContext interface {
	gssContext
	Initiate(string, int, []byte) ([]byte, bool, error)
}

func establishGSS(ctx context.Context, cfg Config, initiator initiatorContext) (authContext, error) {
	keep := false
	defer func() {
		if !keep {
			initiator.Close()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrAuthentication
	}
	provider := &gssProvider{context: initiator, name: "ilm-" + hex.EncodeToString(nonce) + "." + cfg.ServerName}
	spn := "DNS/" + strings.TrimSuffix(cfg.ServerName, ".")
	flags := gssflags.ContextFlagMutual | gssflags.ContextFlagReplay | gssflags.ContextFlagInteg
	output, cont, err := initiator.Initiate(spn, flags, nil)
	if err != nil {
		return nil, ErrAuthentication
	}
	for round := 0; round < 4; round++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(output) > 32<<10 || len(output) == 0 && !cont {
			return nil, ErrAuthentication
		}
		msg := new(dns.Msg)
		msg.SetQuestion(provider.name, dns.TypeTKEY)
		msg.Question[0].Qclass = dns.ClassANY
		msg.RecursionDesired = false
		now := uint32(time.Now().Unix())
		msg.Extra = []dns.RR{&dns.TKEY{Hdr: dns.RR_Header{Name: provider.name, Rrtype: dns.TypeTKEY, Class: dns.ClassANY}, Algorithm: gssAlgorithm, Inception: now, Expiration: now + 3600, Mode: 3, KeySize: uint16(len(output)), Key: hex.EncodeToString(output)}}
		res, raw, err := exchangeTKEY(ctx, cfg, msg)
		if err != nil {
			return nil, err
		}
		var tkey *dns.TKEY
		for _, r := range res.Answer {
			if t, ok := r.(*dns.TKEY); ok {
				if tkey != nil {
					return nil, ErrAuthentication
				}
				tkey = t
			} else {
				return nil, ErrAuthentication
			}
		}
		if tkey == nil || dns.CanonicalName(tkey.Hdr.Name) != provider.name || dns.CanonicalName(tkey.Algorithm) != gssAlgorithm || tkey.Mode != 3 || tkey.Error != 0 || len(tkey.Key) > 64<<10 {
			return nil, ErrAuthentication
		}
		input, err := hex.DecodeString(tkey.Key)
		if err != nil || len(input) != int(tkey.KeySize) {
			return nil, ErrAuthentication
		}
		output, cont, err = initiator.Initiate(spn, flags, input)
		if err != nil {
			return nil, ErrAuthentication
		}
		if !cont && len(output) == 0 {
			if !signedResponse(msg, res, provider.name) || dns.TsigVerifyWithProvider(raw, provider, "", false) != nil {
				return nil, ErrAuthentication
			}
			keep = true
			return provider, nil
		}
	}
	return nil, ErrAuthentication
}
func exchangeTKEY(ctx context.Context, cfg Config, msg *dns.Msg) (*dns.Msg, []byte, error) {
	client := &dns.Client{Net: "tcp", Timeout: cfg.Timeout}
	conn, err := client.DialContext(ctx, cfg.ServerAddress)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline := time.Now().Add(cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, nil, ErrUnavailable
	}
	if err = conn.WriteMsg(msg); err != nil {
		return nil, nil, ErrUnavailable
	}
	// Keep the original packet for final-context TSIG verification; repacking
	// DNS compression would not reproduce the signed bytes.
	raw, err := conn.ReadMsgHeader(nil)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	res := new(dns.Msg)
	if res.Unpack(raw) != nil || !res.Response || res.Id != msg.Id || res.Opcode != dns.OpcodeQuery || res.Rcode != dns.RcodeSuccess || res.Truncated || len(res.Question) != 1 || res.Question[0] != msg.Question[0] {
		return nil, nil, ErrAuthentication
	}
	return res, raw, nil
}

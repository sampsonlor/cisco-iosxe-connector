// Package device provides a fixed, read-only IOS XE discovery channel.
package device

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var (
	ErrPolicy          = errors.New("device policy rejected")
	ErrHostKey         = errors.New("SSH host identity rejected")
	ErrAuthentication  = errors.New("SSH authentication rejected")
	ErrPermission      = errors.New("device authorization denied")
	ErrSessionRejected = errors.New("SSH session or subsystem rejected")
	ErrUnsupported     = errors.New("operation explicitly unsupported")
	ErrProtocol        = errors.New("invalid device protocol response")
	ErrTransport       = errors.New("device transport failed")
	ErrLimit           = errors.New("device response exceeds limit")
	ErrRead            = errors.New("device read failed or incomplete")
)

type Endpoint struct {
	Port                      uint16
	CredentialRef, HostKeyRef string
}
type Target struct {
	Address netip.Addr
	NETCONF Endpoint
	CLI     *Endpoint
}
type Credentials struct {
	Username, Password string
	Signers            []ssh.Signer
}
type Resolver interface {
	Credentials(context.Context, string) (Credentials, error)
	HostKey(context.Context, string) (ssh.PublicKey, error)
}
type Operation string

const (
	ReadVersion      Operation = "read-version"
	ReadPKI          Operation = "read-pki"
	ReadBinding      Operation = "read-https-binding"
	ReadCertificates Operation = "read-certificates"
	ReadHTTPSStatus  Operation = "read-https-status"
	CSR              Operation = "csr"
	Import           Operation = "import"
	Switch           Operation = "switch"
	Save             Operation = "save"
)

type Capability struct {
	Available bool
	Transport string
	Reason    string
}
type Event struct {
	Transport string
	Operation Operation
	Outcome   string
}

// Evidence contains bounded raw reads, never deployment authorization or a
// parsed certificate inventory. The inventory layer must interpret it next.
type Evidence struct {
	Complete     bool
	Raw          map[Operation][]byte
	Capabilities map[Operation]Capability
	Audit        []Event
}
type Client struct {
	targets  map[string]Target
	resolver Resolver
	timeout  time.Duration
	limit    int
	dial     func(context.Context, string) (net.Conn, error)
}

func NewClient(targets map[string]Target, resolver Resolver, timeout time.Duration) (*Client, error) {
	if resolver == nil || len(targets) == 0 {
		return nil, ErrPolicy
	}
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	if timeout < time.Millisecond || timeout > time.Minute {
		return nil, ErrPolicy
	}
	out := make(map[string]Target, len(targets))
	seen := map[netip.Addr]bool{}
	for id, t := range targets {
		if !deviceID.MatchString(id) || !t.Address.IsGlobalUnicast() || t.Address.IsLoopback() || t.Address.Is4In6() || t.Address.Zone() != "" || seen[t.Address] {
			return nil, ErrPolicy
		}
		seen[t.Address] = true
		if t.NETCONF.Port == 0 && t.CLI == nil {
			return nil, ErrPolicy
		}
		if t.NETCONF.Port != 0 && !validEndpoint(t.NETCONF) {
			return nil, ErrPolicy
		}
		if t.CLI != nil {
			ep := *t.CLI
			if !validEndpoint(ep) || (t.NETCONF.Port != 0 && ep.CredentialRef != t.NETCONF.CredentialRef) {
				return nil, ErrPolicy
			}
			t.CLI = &ep
		}
		out[id] = t
	}
	dialer := &net.Dialer{}
	return &Client{targets: out, resolver: resolver, timeout: timeout, limit: 4 << 20, dial: func(ctx context.Context, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp", address)
	}}, nil
}

var deviceID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var reference = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}://[A-Za-z0-9][A-Za-z0-9/_.-]{0,127}$`)

func validEndpoint(e Endpoint) bool {
	return e.Port != 0 && reference.MatchString(e.CredentialRef) && reference.MatchString(e.HostKeyRef)
}

func (c *Client) Collect(ctx context.Context, id string) (e Evidence, err error) {
	t, ok := c.targets[id]
	if !ok {
		return e, ErrPolicy
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	e.Raw = map[Operation][]byte{}
	e.Capabilities = map[Operation]Capability{}
	for _, op := range []Operation{ReadVersion, ReadPKI, ReadBinding, ReadCertificates, ReadHTTPSStatus, CSR, Import, Switch, Save} {
		e.Capabilities[op] = Capability{Reason: "not verified"}
	}
	for _, op := range []Operation{CSR, Import, Switch, Save} {
		e.Capabilities[op] = Capability{Reason: "write operation not implemented or authorized"}
	}
	// Failure results retain only safe audit/capability fields, never a partial
	// transcript that a caller might mistake for complete inventory.
	defer func() {
		if err != nil {
			e.Complete = false
			e.Raw = nil
		}
		if ctx.Err() != nil {
			err = ctx.Err()
			e.Complete = false
			e.Raw = nil
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			err = context.DeadlineExceeded
			e.Complete = false
			e.Raw = nil
		}
	}()
	if t.NETCONF.Port != 0 {
		err = c.readNETCONF(ctx, t, &e)
		if err != nil && !errors.Is(err, ErrUnsupported) {
			return e, err
		}
		if err != nil && t.CLI == nil {
			return e, err
		}
	}
	if t.CLI != nil {
		if err = c.readCLI(ctx, t, &e); err != nil {
			return e, err
		}
	}
	for _, op := range []Operation{ReadVersion, ReadPKI, ReadBinding, ReadCertificates, ReadHTTPSStatus} {
		if !e.Capabilities[op].Available {
			return e, nil
		}
	}
	e.Complete = true
	return e, nil
}
func (e *Evidence) record(transport string, op Operation, raw []byte, err error) {
	outcome := "success"
	if err != nil {
		outcome = "failed"
	}
	e.Audit = append(e.Audit, Event{Transport: transport, Operation: op, Outcome: outcome})
	if err == nil {
		e.Raw[op] = slices.Clone(raw)
		e.Capabilities[op] = Capability{Available: true, Transport: transport, Reason: "read completed; semantic parsing pending"}
	}
}
func address(t Target, e Endpoint) string {
	return net.JoinHostPort(t.Address.String(), strconv.Itoa(int(e.Port)))
}
func transportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return context.DeadlineExceeded
	}
	return ErrTransport
}
func safeCredentials(in Credentials) ([]ssh.AuthMethod, error) {
	if in.Username == "" || len(in.Username) > 128 || strings.TrimSpace(in.Username) != in.Username || strings.ContainsAny(in.Username, "\x00\r\n") || (in.Password == "") == (len(in.Signers) == 0) {
		return nil, ErrPolicy
	}
	if in.Password != "" {
		return []ssh.AuthMethod{ssh.Password(in.Password)}, nil
	}
	signers := make([]ssh.Signer, 0, len(in.Signers))
	for _, s := range in.Signers {
		if s == nil {
			return nil, ErrPolicy
		}
		switch s.PublicKey().Type() {
		case ssh.KeyAlgoRSA:
			as, ok := s.(ssh.AlgorithmSigner)
			if !ok {
				return nil, ErrPolicy
			}
			wrapped, err := ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256})
			if err != nil {
				return nil, ErrPolicy
			}
			s = wrapped
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		default:
			return nil, ErrPolicy
		}
		signers = append(signers, s)
	}
	return []ssh.AuthMethod{ssh.PublicKeys(signers...)}, nil
}

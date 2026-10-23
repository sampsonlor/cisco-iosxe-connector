// Package device provides a fixed, read-only IOS XE discovery channel.
package device

import (
	"context"
	"errors"
	"net"
	"net/netip"
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
	return &Client{}, nil
}
func (c *Client) Collect(ctx context.Context, id string) (Evidence, error) { return Evidence{}, nil }

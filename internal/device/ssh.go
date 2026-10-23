package device

import (
	"bytes"
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

var unenrolledNotice = regexp.MustCompile(`^% the specified trustpoint is not enrolled \([a-z0-9][a-z0-9_.-]{0,63}\)\.$`)

func (c *Client) connect(ctx context.Context, t Target, ep Endpoint) (*ssh.Client, func(), error) {
	key, err := c.resolver.HostKey(ctx, ep.HostKeyRef)
	if err != nil || key == nil {
		return nil, nil, ErrPolicy
	}
	credentials, err := c.resolver.Credentials(ctx, ep.CredentialRef)
	if err != nil {
		return nil, nil, ErrPolicy
	}
	auth, err := safeCredentials(credentials)
	if err != nil {
		return nil, nil, err
	}
	conn, err := c.dial(ctx, address(t, ep))
	if err != nil {
		return nil, nil, transportError(ctx, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			_ = conn.Close()
			return nil, nil, ErrTransport
		}
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	cleanup := func() { stop(); _ = conn.Close() }
	var rejected atomic.Bool
	pin := ssh.FixedHostKey(key)
	alg := ssh.SupportedAlgorithms()
	config := &ssh.ClientConfig{User: credentials.Username, Auth: auth, HostKeyAlgorithms: alg.HostKeys, Config: ssh.Config{KeyExchanges: alg.KeyExchanges, Ciphers: alg.Ciphers, MACs: alg.MACs}, HostKeyCallback: func(host string, remote net.Addr, actual ssh.PublicKey) error {
		err := pin(host, remote, actual)
		if err != nil {
			rejected.Store(true)
		}
		return err
	}}
	sc, chans, reqs, err := ssh.NewClientConn(conn, address(t, ep), config)
	if err != nil {
		cleanup()
		if rejected.Load() {
			return nil, nil, ErrHostKey
		}
		if strings.Contains(err.Error(), "unable to authenticate") {
			return nil, nil, ErrAuthentication
		}
		return nil, nil, transportError(ctx, err)
	}
	return ssh.NewClient(sc, chans, reqs), cleanup, nil
}

var readCommands = map[Operation]string{
	ReadVersion:      "show version",
	ReadPKI:          "show crypto pki trustpoints",
	ReadBinding:      "show running-config | include ^ip http secure-trustpoint",
	ReadCertificates: "show crypto pki certificates pem",
	ReadHTTPSStatus:  "show ip http server status",
}

type boundedOutput struct {
	mu       sync.Mutex
	b        bytes.Buffer
	limit    int
	overflow bool
	close    func()
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.b.Len()+len(p) > b.limit {
		b.overflow = true
		b.close()
		return 0, ErrLimit
	}
	return b.b.Write(p)
}
func (b *boundedOutput) snapshot() ([]byte, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.b.Bytes()), b.overflow
}

func (c *Client) readCLI(ctx context.Context, t Target, e *Evidence) error {
	client, cleanup, err := c.connect(ctx, t, *t.CLI)
	if err != nil {
		return err
	}
	defer cleanup()
	defer client.Close()
	for _, op := range []Operation{ReadVersion, ReadPKI, ReadBinding, ReadCertificates, ReadHTTPSStatus} {
		if e.Capabilities[op].Available {
			continue
		}
		session, err := client.NewSession()
		if err != nil {
			return ErrSessionRejected
		}
		output := &boundedOutput{limit: c.limit, close: func() { _ = client.Close() }}
		session.Stdout = output
		session.Stderr = output
		runErr := session.Run(readCommands[op])
		_ = session.Close()
		raw, overflow := output.snapshot()
		err = classifyCLI(raw, runErr, overflow)
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		e.record("ssh", op, raw, err)
		if err != nil {
			return err
		}
	}
	return nil
}
func classifyCLI(raw []byte, runErr error, overflow bool) error {
	if overflow {
		return ErrLimit
	}
	s := strings.ToLower(string(raw))
	for _, denied := range []string{"authorization failed", "authorization denied", "access denied", "not authorized", "permission denied", "command authorization failed"} {
		if strings.Contains(s, denied) {
			return ErrPermission
		}
	}
	if strings.Contains(s, "--more--") || strings.Contains(s, "<--- more --->") {
		return ErrRead
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "% invalid input") || strings.HasPrefix(line, "% unrecognized command") {
			return ErrUnsupported
		}
		if strings.HasPrefix(line, "%") && line != "% general purpose certificate:" && line != "% ca certificate:" && line != "% only export the ca certificate in pem format." && !unenrolledNotice.MatchString(line) {
			return ErrRead
		}
	}
	if runErr != nil {
		var exit *ssh.ExitError
		if errors.As(runErr, &exit) {
			return ErrRead
		}
		return ErrSessionRejected
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return ErrRead
	}
	return nil
}

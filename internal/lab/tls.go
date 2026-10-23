package lab

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"time"
)

type TLSResult struct {
	MatchesInventory, HostnameValid, ChainTrusted bool
	SHA256, SourceAddress                         string
	Certificates                                  [][]byte
}

func ProbeTLS(ctx context.Context, address, hostname string, expectedDER []byte, roots *x509.CertPool) (result TLSResult, err error) {
	expected, err := x509.ParseCertificate(expectedDER)
	if err != nil || hostname == "" {
		return result, errors.New("invalid TLS baseline policy")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Chain trust is evaluated separately. This handshake authenticates the
	// peer using exact public DER obtained through pinned SSH plus its hostname.
	// No HTTP request, cookie or management credential is transmitted.
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: hostname, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("TLS peer certificate unavailable")
		}
		leaf := state.PeerCertificates[0]
		for _, c := range state.PeerCertificates {
			result.Certificates = append(result.Certificates, bytes.Clone(c.Raw))
		}
		h := sha256.Sum256(leaf.Raw)
		result.SHA256 = hex.EncodeToString(h[:])
		result.MatchesInventory = bytes.Equal(leaf.Raw, expected.Raw)
		result.HostnameValid = leaf.VerifyHostname(hostname) == nil
		intermediates := x509.NewCertPool()
		for _, c := range state.PeerCertificates[1:] {
			intermediates.AddCert(c)
		}
		_, verifyErr := leaf.Verify(x509.VerifyOptions{DNSName: hostname, Roots: roots, Intermediates: intermediates})
		result.ChainTrusted = verifyErr == nil
		if !result.MatchesInventory || !result.HostnameValid {
			return errors.New("TLS certificate differs from approved SSH inventory or hostname")
		}
		return nil
	}}
	dialer := tls.Dialer{NetDialer: &net.Dialer{}, Config: config}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return result, errors.New("TLS baseline handshake failed")
	}
	result.SourceAddress = conn.LocalAddr().String()
	_ = conn.Close()
	return result, nil
}

package lab

import (
	"context"
	"crypto/x509"
	"errors"
)

type TLSResult struct {
	MatchesInventory, HostnameValid, ChainTrusted bool
	SHA256, SourceAddress                         string
	Certificates                                  [][]byte
}

func ProbeTLS(context.Context, string, string, []byte, *x509.CertPool) (TLSResult, error) {
	return TLSResult{}, errors.New("TLS baseline unavailable")
}

package lab

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

func tlsFixture(t *testing.T) (string, []byte, *tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "router.example.test"}, DNSNames: []string{"router.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer conn.Close()
				_ = conn.(*tls.Conn).Handshake()
				_ = conn.SetReadDeadline(time.Now().Add(time.Second))
				var b [1]byte
				n, _ := conn.Read(b[:])
				if n != 0 {
					t.Error("TLS probe sent application payload")
				}
			})
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; wg.Wait() })
	return listener.Addr().String(), der, cert
}

func TestPinnedTLSBaselineAndMismatch(t *testing.T) {
	address, der, _ := tlsFixture(t)
	result, err := ProbeTLS(context.Background(), address, "router.example.test", der, nil)
	if err != nil || !result.MatchesInventory || !result.HostnameValid || result.ChainTrusted || len(result.Certificates) != 1 {
		t.Fatalf("pinned TLS result=%+v err=%v", result, err)
	}
	if _, err := ProbeTLS(context.Background(), address, "router.example.test", []byte("wrong inventory certificate"), nil); err == nil {
		t.Fatal("TLS inventory mismatch accepted")
	}
	if _, err := ProbeTLS(context.Background(), address, "wrong.example.test", der, nil); err == nil {
		t.Fatal("wrong hostname accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ProbeTLS(ctx, address, "router.example.test", der, nil); err == nil {
		t.Fatal("cancel ignored")
	}
	_ = net.IPv4len
}

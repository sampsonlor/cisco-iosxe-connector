package device

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

func TestNETCONFFramingAndEnvelopes(t *testing.T) {
	for _, s := range []string{"\n#0\n\n##\n", "\n#01\nx\n##\n", "\n#-1\nx\n##\n", "\n#99999999999\n", "\n##\n", "\n#4\nx", "\n#100\n"} {
		if _, err := readFrame(bufio.NewReader(strings.NewReader(s)), true, 64); err == nil {
			t.Errorf("invalid chunk accepted: %q", s)
		}
	}
	want := "<x>λ</x>"
	s := "\n#3\n<x>\n#6\nλ</x>\n##\n"
	got, err := readFrame(bufio.NewReader(strings.NewReader(s)), true, 64)
	if err != nil || string(got) != want {
		t.Fatalf("multiple byte-counted chunks: %q %v", got, err)
	}
	if _, err := readFrame(bufio.NewReader(strings.NewReader(strings.Repeat("x", 100))), false, 64); !errors.Is(err, ErrLimit) {
		t.Fatalf("EOM limit ignored: %v", err)
	}
	for _, raw := range []string{
		`<rpc-reply xmlns="` + baseNS + `" message-id="1"><data/><rpc-error xmlns="urn:wrong"><error-tag>access-denied</error-tag></rpc-error></rpc-reply>`,
		`<rpc-reply xmlns="` + baseNS + `" message-id="1"><data/><data/></rpc-reply>`,
		`<rpc-reply xmlns="` + baseNS + `" message-id="1"><ok/><data/></rpc-reply>`,
	} {
		if err := parseReply([]byte(raw), "1"); !errors.Is(err, ErrProtocol) {
			t.Errorf("ambiguous reply accepted: %v", err)
		}
	}
	for _, raw := range []string{
		`<hello xmlns="` + baseNS + `"><capabilities xmlns="urn:wrong"><capability>` + base10 + `</capability></capabilities><session-id>7</session-id></hello>`,
		`<hello xmlns="` + baseNS + `"><capabilities><capability>` + base10 + `</capability></capabilities><session-id>7</session-id><session-id>8</session-id></hello>`,
	} {
		if _, _, err := parseHello([]byte(raw)); !errors.Is(err, ErrProtocol) {
			t.Errorf("ambiguous hello accepted: %v", err)
		}
	}
	for _, s := range []string{`<a x="1" x="2"/>`, `<a/><b/>`, `<!DOCTYPE a><a/>`, `<a>&external;</a>`, strings.Repeat("<a>", 65) + strings.Repeat("</a>", 65)} {
		if validXML([]byte(s)) {
			t.Errorf("unsafe XML accepted")
		}
	}
}

func TestExplicitUnsupportedAndTransportFailure(t *testing.T) {
	f := startFixture(t, &fixture{modules: []string{pkiNS}, rpcError: "operation-not-supported"})
	e, err := testClient(t, f, true, true).Collect(context.Background(), "router-a")
	if err != nil || !e.Complete || e.Capabilities[ReadPKI].Transport != "ssh" {
		t.Fatalf("explicit read fallback failed: %+v %v", e, err)
	}
	assertReadOnlyAudit(t, f.logs())
	c := testClient(t, f, true, true)
	calls := 0
	c.dial = func(context.Context, string) (net.Conn, error) { calls++; return nil, io.EOF }
	_, err = c.Collect(context.Background(), "router-a")
	if !errors.Is(err, ErrTransport) || calls != 1 {
		t.Fatalf("network error caused fallback/retry: %v %d", err, calls)
	}
}

func TestConcurrentReadCollection(t *testing.T) {
	f := startFixture(t, &fixture{modules: []string{pkiNS, nativeNS, httpNS}, chunked: true})
	c := testClient(t, f, true, true)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Go(func() {
			e, err := c.Collect(context.Background(), "router-a")
			if err != nil || !e.Complete {
				t.Errorf("concurrent read: %v", err)
			}
		})
	}
	wg.Wait()
	assertReadOnlyAudit(t, f.logs())
}

func FuzzNETCONFFraming(f *testing.F) {
	for _, b := range [][]byte{[]byte("\n#1\nx\n##\n"), []byte("\n#0\n"), []byte("<a/>]]>]]>")} {
		f.Add(b, true)
	}
	f.Fuzz(func(t *testing.T, b []byte, chunked bool) {
		if len(b) > 8192 {
			return
		}
		r := bufio.NewReader(bytes.NewReader(b))
		out, err := readFrame(r, chunked, 4096)
		if err == nil && len(out) > 4096 {
			t.Fatal("frame exceeded limit")
		}
	})
}

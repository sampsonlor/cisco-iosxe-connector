package device

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"strconv"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

const netconfNS = "urn:ietf:params:xml:ns:netconf:base:1.0"
const pkiNamespace = "http://cisco.com/ns/yang/Cisco-IOS-XE-crypto-pki-oper"
const nativeNamespace = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
const httpNamespace = "http://cisco.com/ns/yang/Cisco-IOS-XE-http"
const base10 = "urn:ietf:params:netconf:base:1.0"
const base11 = "urn:ietf:params:netconf:base:1.1"

var readFilters = map[Operation]string{
	ReadPKI:     `<crypto-pki-oper-data xmlns="` + pkiNamespace + `"><crypto-pki-bundle/></crypto-pki-oper-data>`,
	ReadBinding: `<native xmlns="` + nativeNamespace + `"><ip><http xmlns="` + httpNamespace + `"><secure-trustpoint/></http></ip></native>`,
}

func (c *Client) readNETCONF(ctx context.Context, t Target, e *Evidence) (err error) {
	client, cleanup, err := c.connect(ctx, t, t.NETCONF)
	if err != nil {
		return err
	}
	defer cleanup()
	if e.LocalAddresses == nil {
		e.LocalAddresses = map[string]string{}
	}
	e.LocalAddresses["netconf"] = client.LocalAddr().String()
	ch, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		_ = client.Close()
		return ErrSessionRejected
	}
	go ssh.DiscardRequests(requests)
	var stderr atomic.Int64
	done := make(chan struct{})
	go func() {
		n, _ := io.Copy(io.Discard, io.LimitReader(ch.Stderr(), int64(c.limit)+1))
		stderr.Store(n)
		if n > int64(c.limit) {
			_ = client.Close()
		}
		close(done)
	}()
	defer func() {
		_ = client.Close()
		<-done
		if err == nil && stderr.Load() > 0 {
			err = ErrProtocol
		}
	}()
	ok, err := ch.SendRequest("subsystem", true, ssh.Marshal(struct{ Name string }{"netconf"}))
	if err != nil || !ok {
		return ErrSessionRejected
	}
	hello := []byte(`<hello xmlns="` + netconfNS + `"><capabilities><capability>` + base10 + `</capability><capability>` + base11 + `</capability></capabilities></hello>`)
	if err := writeFrame(ch, hello, false); err != nil {
		return err
	}
	r := bufio.NewReader(ch)
	raw, err := readFrame(r, false, 64<<10)
	if err != nil {
		return err
	}
	chunked, modules, err := parseHello(raw)
	if err != nil {
		return err
	}
	e.NETCONFHello = append([]byte(nil), raw...)
	for i, op := range []Operation{ReadPKI, ReadBinding} {
		available := modules[pkiNamespace]
		if op == ReadBinding {
			available = modules[nativeNamespace] && modules[httpNamespace]
		}
		if !available {
			continue
		}
		id := strconv.Itoa(i + 1)
		rpc := []byte(`<rpc xmlns="` + netconfNS + `" message-id="` + id + `"><get><filter type="subtree">` + readFilters[op] + `</filter></get></rpc>`)
		if err := writeFrame(ch, rpc, chunked); err != nil {
			e.record("netconf", op, nil, err)
			return err
		}
		reply, readErr := readFrame(r, chunked, c.limit)
		if readErr == nil {
			readErr = parseReply(reply, id)
		}
		e.record("netconf", op, reply, readErr)
		if readErr != nil && !errors.Is(readErr, ErrUnsupported) {
			return readErr
		}
	}
	return nil
}
func parseHello(raw []byte) (bool, map[string]bool, error) {
	if !validXML(raw) || !validEnvelope(raw, "hello") {
		return false, nil, ErrProtocol
	}
	var h struct {
		XMLName      xml.Name
		Capabilities struct {
			Items []string `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 capability"`
		} `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 capabilities"`
		SessionID uint32 `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 session-id"`
	}
	if xml.Unmarshal(raw, &h) != nil || h.XMLName != (xml.Name{Space: netconfNS, Local: "hello"}) || h.SessionID == 0 || len(h.Capabilities.Items) > 1024 {
		return false, nil, ErrProtocol
	}
	modules := map[string]bool{}
	has10, has11 := false, false
	for _, cap := range h.Capabilities.Items {
		if cap == base10 {
			has10 = true
		}
		if cap == base11 {
			has11 = true
		}
		u, err := url.Parse(cap)
		if err != nil {
			continue
		}
		for _, ns := range []string{pkiNamespace, nativeNamespace, httpNamespace} {
			v, _ := url.Parse(ns)
			if u.Scheme == v.Scheme && u.Host == v.Host && u.Path == v.Path && u.Query().Get("module") == u.Path[len("/ns/yang/"):] {
				modules[ns] = true
			}
		}
	}
	if !has10 && !has11 {
		return false, nil, ErrUnsupported
	}
	return has11, modules, nil
}
func parseReply(raw []byte, id string) error {
	if !validXML(raw) || !validEnvelope(raw, "rpc-reply") {
		return ErrProtocol
	}
	var reply struct {
		XMLName xml.Name
		ID      string `xml:"message-id,attr"`
		Data    *struct {
			Inner string `xml:",innerxml"`
		} `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 data"`
		Errors []struct {
			Tag string `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 error-tag"`
		} `xml:"urn:ietf:params:xml:ns:netconf:base:1.0 rpc-error"`
	}
	if xml.Unmarshal(raw, &reply) != nil || reply.XMLName != (xml.Name{Space: netconfNS, Local: "rpc-reply"}) || reply.ID != id {
		return ErrProtocol
	}
	unsupported := false
	for _, failure := range reply.Errors {
		switch failure.Tag {
		case "access-denied":
			return ErrPermission
		case "operation-not-supported", "unknown-element", "unknown-namespace":
			unsupported = true
		default:
			return ErrRead
		}
	}
	if unsupported {
		return ErrUnsupported
	}
	if reply.Data == nil {
		return ErrProtocol
	}
	return nil
}

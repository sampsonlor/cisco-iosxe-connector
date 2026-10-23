package inventory

import (
	"bytes"
	"crypto/md5" // Cisco metadata correlation only; never a security decision.
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"io"
	"math/big"
	"strings"
)

const ncNS = "urn:ietf:params:xml:ns:netconf:base:1.0"
const pkiNS = "http://cisco.com/ns/yang/Cisco-IOS-XE-crypto-pki-oper"
const nativeNS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
const httpNS = "http://cisco.com/ns/yang/Cisco-IOS-XE-http"

type node struct {
	name     xml.Name
	text     strings.Builder
	children []*node
}

func (n *node) one(ns, name string) (*node, error) {
	var found *node
	for _, c := range n.children {
		if c.name == (xml.Name{Space: ns, Local: name}) {
			if found != nil {
				return nil, ErrIncomplete
			}
			found = c
		}
	}
	if found == nil {
		return nil, ErrIncomplete
	}
	return found, nil
}
func (n *node) value(ns, name string) (string, error) {
	c, err := n.one(ns, name)
	if err != nil || len(c.children) != 0 || strings.TrimSpace(c.text.String()) == "" {
		return "", ErrIncomplete
	}
	return strings.TrimSpace(c.text.String()), nil
}
func (n *node) only(ns string, names ...string) bool {
	if strings.TrimSpace(n.text.String()) != "" {
		return false
	}
	for _, c := range n.children {
		ok := false
		for _, name := range names {
			if c.name == (xml.Name{Space: ns, Local: name}) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// Independent semantic boundary: callers cannot bypass validation by setting
// Evidence.Complete. Bound depth/count, reject directives, duplicate attributes,
// mixed content, foreign namespaces and ambiguous/missing required nodes.
func dataXML(raw []byte) (*node, error) {
	if len(raw) > 4<<20 {
		return nil, ErrIncomplete
	}
	d := xml.NewDecoder(bytes.NewReader(raw))
	var root *node
	var stack []*node
	count := 0
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, ErrIncomplete
		}
		switch x := t.(type) {
		case xml.StartElement:
			count++
			if count > 100000 || len(stack) >= 64 {
				return nil, ErrIncomplete
			}
			attrs := map[xml.Name]bool{}
			for _, a := range x.Attr {
				if attrs[a.Name] {
					return nil, ErrIncomplete
				}
				attrs[a.Name] = true
				if !(a.Name.Space == "" && a.Name.Local == "xmlns") && a.Name.Space != "xmlns" && !(len(stack) == 0 && a.Name.Space == "" && a.Name.Local == "message-id" && a.Value != "") {
					return nil, ErrUnsupported
				}
			}
			n := &node{name: x.Name}
			if len(stack) == 0 {
				if root != nil {
					return nil, ErrIncomplete
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.children = append(p.children, n)
			}
			stack = append(stack, n)
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, ErrIncomplete
			}
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) == 0 {
				if strings.TrimSpace(string(x)) != "" {
					return nil, ErrIncomplete
				}
			} else {
				stack[len(stack)-1].text.Write(x)
			}
		case xml.Directive:
			return nil, ErrUnsupported
		case xml.ProcInst:
			if x.Target != "xml" || root != nil {
				return nil, ErrUnsupported
			}
		}
	}
	if root == nil || len(stack) != 0 || root.name != (xml.Name{Space: ncNS, Local: "rpc-reply"}) || !root.only(ncNS, "data") || len(root.children) != 1 {
		return nil, ErrIncomplete
	}
	return root.one(ncNS, "data")
}

func bindingXML(raw []byte) (string, error) {
	d, err := dataXML(raw)
	if err != nil {
		return "", err
	}
	for _, s := range []struct{ ns, name string }{{nativeNS, "native"}, {nativeNS, "ip"}, {httpNS, "http"}, {httpNS, "secure-trustpoint"}} {
		if !d.only(s.ns, s.name) || len(d.children) != 1 {
			return "", ErrIncomplete
		}
		d, err = d.one(s.ns, s.name)
		if err != nil {
			return "", err
		}
	}
	name := strings.TrimSpace(d.text.String())
	if len(d.children) != 0 || !namePattern.MatchString(name) {
		return "", ErrIncomplete
	}
	return name, nil
}

func checkPKIXML(raw []byte, groups map[string][]pemCertificate) error {
	d, err := dataXML(raw)
	if err != nil {
		return err
	}
	if !d.only(pkiNS, "crypto-pki-oper-data") || len(d.children) != 1 {
		return ErrIncomplete
	}
	d, err = d.one(pkiNS, "crypto-pki-oper-data")
	if err != nil || !d.only(pkiNS, "crypto-pki-bundle") {
		return ErrIncomplete
	}
	seen := map[string]bool{}
	for _, bundle := range d.children {
		if !bundle.only(pkiNS, "label", "mode", "tp-authenticated", "tp-keys-generated", "tp-enrolled", "tp-scep-enrollment-in-progress", "key-export", "cert") {
			return ErrUnsupported
		}
		name, err := bundle.value(pkiNS, "label")
		if err != nil || seen[name] || groups[name] == nil {
			return ErrIncomplete
		}
		seen[name] = true
		matched := map[int]bool{}
		for _, c := range bundle.children {
			if c.name.Local != "cert" {
				if len(c.children) != 0 {
					return ErrUnsupported
				}
				continue
			}
			if !c.only(pkiNS, "cert-avail", "cert-usage", "cert-key-type", "serial-number", "subject-name", "issuer-name", "storage", "md5-fp", "validity-start", "validity-end", "asc-tp", "is-ca-cert") {
				return ErrUnsupported
			}
			fp, err := c.value(pkiNS, "md5-fp")
			if err != nil {
				return err
			}
			fp = strings.NewReplacer(":", "", " ", "", "\t", "").Replace(fp)
			h, err := hex.DecodeString(fp)
			if err != nil || len(h) != 16 {
				return ErrIncomplete
			}
			serial, err := c.value(pkiNS, "serial-number")
			if err != nil {
				return err
			}
			number, ok := new(big.Int).SetString(serial, 16)
			if !ok || number.Sign() < 0 {
				return ErrIncomplete
			}
			isCA, err := c.value(pkiNS, "is-ca-cert")
			if err != nil || (isCA != "true" && isCA != "false") {
				return ErrIncomplete
			}
			index := -1
			for i, entry := range groups[name] {
				der := entry.der
				cert, _ := x509.ParseCertificate(der)
				m := md5.Sum(der)
				if bytes.Equal(h, m[:]) && cert.SerialNumber.Cmp(number) == 0 && cert.IsCA == (isCA == "true") {
					if index != -1 {
						return ErrIncomplete
					}
					index = i
				}
			}
			if index < 0 || matched[index] {
				return ErrIncomplete
			}
			matched[index] = true
			for _, a := range c.children {
				if a.name.Local != "asc-tp" {
					if len(a.children) != 0 {
						return ErrUnsupported
					}
					continue
				}
				if !a.only(pkiNS, "tp-name") || len(a.children) != 1 {
					return ErrIncomplete
				}
				tp, err := a.value(pkiNS, "tp-name")
				if err != nil {
					return err
				}
				found := false
				for _, entry := range groups[tp] {
					if bytes.Equal(entry.der, groups[name][index].der) {
						found = true
					}
				}
				if !found {
					return ErrIncomplete
				}
			}
		}
		if len(matched) != len(groups[name]) {
			return ErrIncomplete
		}
	}
	if len(seen) != len(groups) {
		return ErrIncomplete
	}
	return nil
}

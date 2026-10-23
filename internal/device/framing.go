package device

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"io"
	"strconv"
)

const eom = "]]>]]>"

func readFrame(r *bufio.Reader, chunked bool, limit int) ([]byte, error) {
	if !chunked {
		out := make([]byte, 0, 1024)
		for {
			b, err := r.ReadByte()
			if err != nil {
				return nil, ErrProtocol
			}
			out = append(out, b)
			if bytes.HasSuffix(out, []byte(eom)) {
				out = out[:len(out)-len(eom)]
				if len(out) > limit {
					return nil, ErrLimit
				}
				return out, nil
			}
			if len(out) > limit+len(eom) {
				return nil, ErrLimit
			}
		}
	}
	var out []byte
	for {
		for _, want := range []byte{'\n', '#'} {
			got, err := r.ReadByte()
			if err != nil || got != want {
				return nil, ErrProtocol
			}
		}
		b, err := r.ReadByte()
		if err != nil {
			return nil, ErrProtocol
		}
		if b == '#' {
			end, err := r.ReadByte()
			if err != nil || end != '\n' || len(out) == 0 {
				return nil, ErrProtocol
			}
			return out, nil
		}
		if b < '1' || b > '9' {
			return nil, ErrProtocol
		}
		digits := []byte{b}
		for {
			b, err = r.ReadByte()
			if err != nil {
				return nil, ErrProtocol
			}
			if b == '\n' {
				break
			}
			if b < '0' || b > '9' || len(digits) >= 10 {
				return nil, ErrProtocol
			}
			digits = append(digits, b)
		}
		n, err := strconv.ParseUint(string(digits), 10, 32)
		if err != nil || n > uint64(limit-len(out)) {
			return nil, ErrLimit
		}
		chunk := make([]byte, int(n))
		if _, err := io.ReadFull(r, chunk); err != nil {
			return nil, ErrProtocol
		}
		out = append(out, chunk...)
	}
}
func writeFrame(w io.Writer, raw []byte, chunked bool) error {
	var frame []byte
	if chunked {
		frame = []byte("\n#" + strconv.Itoa(len(raw)) + "\n" + string(raw) + "\n##\n")
	} else {
		frame = append(append([]byte{}, raw...), []byte(eom)...)
	}
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return ErrTransport
		}
		if n <= 0 {
			return ErrTransport
		}
		frame = frame[n:]
	}
	return nil
}

// Reject directives/entities, duplicate attributes, trailing roots and excessive
// nesting before typed XML decoding. No schema or URL is fetched from a device.
func validXML(raw []byte) bool {
	d := xml.NewDecoder(bytes.NewReader(raw))
	depth, roots := 0, 0
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return depth == 0 && roots == 1
		}
		if err != nil {
			return false
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 {
				roots++
			}
			depth++
			if roots > 1 || depth > 64 {
				return false
			}
			seen := map[xml.Name]bool{}
			for _, a := range t.Attr {
				if seen[a.Name] {
					return false
				}
				seen[a.Name] = true
			}
		case xml.EndElement:
			depth--
		case xml.Directive:
			return false
		case xml.ProcInst:
			if t.Target != "xml" || roots != 0 {
				return false
			}
		case xml.CharData:
			if depth == 0 && len(bytes.TrimSpace(t)) > 0 {
				return false
			}
		}
	}
}

// encoding/xml's ordinary field selection tolerates unknown and repeated
// elements. Protocol envelope fields must instead be unambiguous and in the
// NETCONF namespace; vendor payload inside data/error-info remains extensible.
func validEnvelope(raw []byte, root string) bool {
	d := xml.NewDecoder(bytes.NewReader(raw))
	stack := []xml.Name{}
	counts := map[string]int{}
	errorFields := map[string]bool{}
	for {
		token, err := d.Token()
		if err == io.EOF {
			return true
		}
		if err != nil {
			return false
		}
		switch t := token.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name)
			depth := len(stack)
			if depth == 1 && t.Name != (xml.Name{Space: netconfNS, Local: root}) {
				return false
			}
			if depth == 2 {
				if t.Name.Space != netconfNS {
					return false
				}
				name := t.Name.Local
				counts[name]++
				if root == "hello" {
					if (name != "capabilities" && name != "session-id") || counts[name] > 1 {
						return false
					}
				} else {
					if name != "data" && name != "rpc-error" {
						return false
					}
					if name == "data" && counts[name] > 1 {
						return false
					}
					if name == "rpc-error" {
						errorFields = map[string]bool{}
					}
				}
			}
			if depth == 3 && root == "hello" {
				if stack[1].Local != "capabilities" || t.Name != (xml.Name{Space: netconfNS, Local: "capability"}) {
					return false
				}
			}
			if depth == 3 && root == "rpc-reply" && stack[1].Local == "rpc-error" {
				if t.Name.Space != netconfNS || errorFields[t.Name.Local] {
					return false
				}
				switch t.Name.Local {
				case "error-type", "error-tag", "error-severity", "error-app-tag", "error-path", "error-message", "error-info":
				default:
					return false
				}
				errorFields[t.Name.Local] = true
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
}

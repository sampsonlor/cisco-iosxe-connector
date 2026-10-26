package device

import (
	"bytes"
	"context"
	"crypto/sha1" // legacy CLI display comparison only; trust uses approved DER/SHA256
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"io"
	"regexp"
	"strings"
)

const certificateInputEnd = `End with a blank line or the word "quit" on a line by itself`
const acceptCertificateQuestion = "% Do you accept this certificate? [yes/no]:"

func displayedIssuerMatches(raw, der []byte) bool {
	seen := map[string]bool{}
	matches := regexp.MustCompile(`(?im)^[ \t]*Fingerprint (SHA1|SHA256):[ \t]*([^\r\n]*)`).FindAllSubmatch(raw, -1)
	for _, m := range matches {
		algorithm := strings.ToUpper(string(m[1]))
		if seen[algorithm] {
			return false
		}
		seen[algorithm] = true
		got := strings.ToLower(strings.NewReplacer(" ", "", ":", "").Replace(string(m[2])))
		want := ""
		if algorithm == "SHA256" {
			h := sha256.Sum256(der)
			want = hex.EncodeToString(h[:])
		} else {
			h := sha1.Sum(der)
			want = hex.EncodeToString(h[:])
		}
		if got != want {
			return false
		}
	}
	return len(seen) > 0
}
func (s *csrShell) importPublic(ctx context.Context, name string, der []byte, isCA bool, authorize func(context.Context) error) error {
	if err := authorize(ctx); err != nil {
		return err
	}
	cmd := "crypto pki import " + name + " certificate"
	kind := ""
	if isCA {
		cmd = "crypto pki authenticate " + name
		kind = "CA "
	}
	if _, err := io.WriteString(s.in, cmd+"\n"); err != nil {
		return ErrTransport
	}
	raw, question, err := s.read(s.host+"(config)#", true)
	if err != nil {
		return err
	}
	intro := "Enter the base 64 encoded " + kind + "certificate."
	if question != certificateInputEnd || bytes.Count(raw, []byte(intro)) != 1 {
		return ErrProtocol
	}
	if err = authorize(ctx); err != nil {
		return err
	}
	payload := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if _, err = io.WriteString(s.in, string(payload)+"quit\n"); err != nil {
		return ErrTransport
	}
	raw, question, err = s.read(s.host+"(config)#", true)
	if err != nil {
		return err
	}
	if isCA {
		if question != acceptCertificateQuestion || !displayedIssuerMatches(raw, der) {
			return ErrProtocol
		}
		if err = authorize(ctx); err != nil {
			return err
		}
		if _, err = io.WriteString(s.in, "yes\n"); err != nil {
			return ErrTransport
		}
		raw, _, err = s.read(s.host+"(config)#", false)
		if err != nil {
			return err
		}
	} else if question != "" {
		return ErrProtocol
	}
	want := "% Router Certificate successfully imported"
	if isCA {
		want = "% Certificate successfully imported"
	}
	if bytes.Count(raw, []byte(want)) != 1 {
		return ErrProtocol
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "%") && line != want {
			return ErrProtocol
		}
	}
	return nil
}

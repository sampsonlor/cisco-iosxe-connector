package device

import (
	"bufio"
	"bytes"
	"io"
	"regexp"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/ssh"
)

const displayQuestion = "Display Certificate Request to terminal? [yes/no]:"
const redisplayQuestion = "Redisplay enrollment request? [yes/no]:"

type csrShell struct {
	client  *ssh.Client
	session *ssh.Session
	in      io.WriteCloser
	out     *bufio.Reader
	host    string
	limit   int
	stderr  atomic.Int64
	done    chan struct{}
}

func openCSRShell(client *ssh.Client, limit int) (*csrShell, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, ErrSessionRejected
	}
	s := &csrShell{client: client, session: session, limit: min(limit, 64<<10), done: make(chan struct{})}
	in, err := session.StdinPipe()
	if err != nil {
		_ = session.Close()
		return nil, ErrSessionRejected
	}
	s.in = in
	out, err := session.StdoutPipe()
	if err != nil {
		_ = session.Close()
		return nil, ErrSessionRejected
	}
	s.out = bufio.NewReader(out)
	stderr, err := session.StderrPipe()
	if err != nil {
		_ = session.Close()
		return nil, ErrSessionRejected
	}
	go func() {
		first := make([]byte, 1)
		n, _ := stderr.Read(first)
		s.stderr.Store(int64(n))
		if n > 0 {
			_ = client.Close()
		}
		close(s.done)
	}()
	if session.RequestPty("vt100", 512, 80, ssh.TerminalModes{ssh.ECHO: 0}) != nil || session.Shell() != nil {
		s.close()
		return nil, ErrSessionRejected
	}
	raw, _, err := s.read("", false)
	if err != nil {
		s.close()
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	prompt := strings.TrimSpace(lines[len(lines)-1])
	if !regexp.MustCompile(`^[A-Za-z0-9_.-]+#$`).MatchString(prompt) {
		s.close()
		return nil, ErrProtocol
	}
	s.host = strings.TrimSuffix(prompt, "#")
	return s, nil
}
func (s *csrShell) close() { _ = s.client.Close(); _ = s.session.Close(); <-s.done }
func (s *csrShell) read(expected string, questions bool) ([]byte, string, error) {
	var b bytes.Buffer
	for {
		ch, err := s.out.ReadByte()
		if err != nil {
			return nil, "", ErrRead
		}
		if b.Len() >= s.limit {
			return nil, "", ErrLimit
		}
		if ch < 32 && ch != '\n' && ch != '\r' && ch != '\t' || ch == 127 {
			return nil, "", ErrProtocol
		}
		_ = b.WriteByte(ch)
		tail := b.Bytes()
		if len(tail) > 512 {
			tail = tail[len(tail)-512:]
		}
		raw := string(tail)
		lower := strings.ToLower(raw)
		for _, denied := range []string{"authorization failed", "authorization denied", "access denied", "not authorized", "permission denied"} {
			if strings.Contains(lower, denied) {
				return nil, "", ErrPermission
			}
		}
		for _, bad := range []string{"replace", "overwrite", "challenge password", "private key", "--more--", "[confirm]", "invalid input", "unrecognized command", "% error"} {
			if strings.Contains(lower, bad) {
				return nil, "", ErrProtocol
			}
		}
		trimmed := strings.TrimRight(raw, " \r\n")
		for _, question := range []string{displayQuestion, redisplayQuestion, certificateInputEnd, acceptCertificateQuestion} {
			if strings.HasSuffix(trimmed, question) {
				if !questions {
					return nil, "", ErrProtocol
				}
				return b.Bytes(), question, nil
			}
		}
		last := trimmed
		if at := strings.LastIndexAny(last, "\r\n"); at >= 0 {
			last = last[at+1:]
		}
		last = strings.TrimSpace(last)
		if strings.HasSuffix(last, "#") || strings.HasSuffix(last, ">") {
			if expected == "" {
				if regexp.MustCompile(`^[A-Za-z0-9_.-]+#$`).MatchString(last) {
					return b.Bytes(), "", nil
				}
				return nil, "", ErrProtocol
			}
			if last == expected && s.stderr.Load() == 0 {
				return b.Bytes(), "", nil
			}
			return nil, "", ErrProtocol
		}
	}
}
func (s *csrShell) command(command, expected string) ([]byte, error) {
	if _, err := io.WriteString(s.in, command+"\n"); err != nil {
		return nil, ErrTransport
	}
	raw, _, err := s.read(expected, false)
	if err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "%") && !strings.HasPrefix(line, "% Generating ") && !strings.HasPrefix(line, "% The key modulus size is ") && !strings.HasPrefix(line, "% Key pair was generated at:") {
				return nil, ErrProtocol
			}
		}
	}
	return raw, err
}
func (s *csrShell) readKey(label string) (publicKey, error) {
	raw, err := s.command("show crypto key mypubkey rsa "+label, s.host+"#")
	if err != nil {
		return publicKey{}, err
	}
	text := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(string(raw)), s.host+"#"))
	keys, err := publicKeys([]byte(text))
	if err != nil || len(keys) != 1 {
		return publicKey{}, ErrPolicy
	}
	key, exists := keys[strings.ToLower(label)]
	if !exists || !key.NonExportable {
		return publicKey{}, ErrPolicy
	}
	return key, nil
}
func (s *csrShell) enroll(trustpoint string) ([]byte, error) {
	if _, err := io.WriteString(s.in, "crypto pki enroll "+trustpoint+"\n"); err != nil {
		return nil, ErrTransport
	}
	_, question, err := s.read(s.host+"(config)#", true)
	if err != nil || question != displayQuestion {
		return nil, ErrProtocol
	}
	if _, err := io.WriteString(s.in, "yes\n"); err != nil {
		return nil, ErrTransport
	}
	raw, question, err := s.read(s.host+"(config)#", true)
	if err != nil {
		return nil, err
	}
	if question == redisplayQuestion {
		if _, err := io.WriteString(s.in, "no\n"); err != nil {
			return nil, ErrTransport
		}
		if _, _, err := s.read(s.host+"(config)#", false); err != nil {
			return nil, err
		}
	} else if question != "" {
		return nil, ErrProtocol
	}
	start := bytes.Index(raw, []byte("-----BEGIN CERTIFICATE REQUEST-----"))
	end := bytes.Index(raw, []byte("-----END CERTIFICATE REQUEST-----"))
	if start < 0 || end < start || bytes.Count(raw, []byte("-----BEGIN")) != 1 {
		return nil, ErrProtocol
	}
	end += len("-----END CERTIFICATE REQUEST-----")
	return bytes.Clone(raw[start:end]), nil
}

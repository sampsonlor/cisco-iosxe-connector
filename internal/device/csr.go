package device

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/csr"
)

const (
	ReadTrustpointConfig Operation = "read-trustpoint-config"
	ReadRSAKeys          Operation = "read-rsa-public-keys"
	ReadECKeys           Operation = "read-ec-public-keys"
)

type CSRPolicy struct {
	AllowWrites                        bool
	Version, PolicySHA256              string
	Spec                               csr.Spec
	StagingTrustpoints, ProtectedNames []string
}
type CSRAdapter struct {
	client   *Client
	policies map[string]CSRPolicy
	verify   func(Evidence, csr.Request) error
}
type publicKey struct {
	DER           []byte
	NonExportable bool
}
type csrPreflight struct {
	config map[string]string
	keys   map[string]publicKey
}

// NewCSRAdapter is a separate opt-in write adapter. The trusted host supplies
// inventory.VerifyCSRBaseline; it must not replace semantic verification with
// transport success. No existing read-only Client/Provider enables this adapter.
func NewCSRAdapter(client *Client, policies map[string]CSRPolicy, verify func(Evidence, csr.Request) error) (*CSRAdapter, error) {
	if client == nil || verify == nil || len(policies) == 0 {
		return nil, ErrPolicy
	}
	out := map[string]CSRPolicy{}
	for id, p := range policies {
		target, ok := client.targets[id]
		spec, err := csr.Normalize(p.Spec)
		if !ok || target.CLI == nil || !p.AllowWrites || !regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.]*$`).MatchString(p.Version) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.PolicySHA256) || err != nil || len(p.StagingTrustpoints) < 1 || len(p.ProtectedNames) < 1 {
			return nil, ErrPolicy
		}
		seen := map[string]bool{}
		for _, name := range append(slices.Clone(p.ProtectedNames), p.StagingTrustpoints...) {
			if !deviceID.MatchString(name) || seen[strings.ToLower(name)] {
				return nil, ErrPolicy
			}
			seen[strings.ToLower(name)] = true
		}
		p.Spec = spec
		p.StagingTrustpoints = slices.Clone(p.StagingTrustpoints)
		p.ProtectedNames = slices.Clone(p.ProtectedNames)
		out[id] = p
	}
	return &CSRAdapter{client: client, policies: out, verify: verify}, nil
}
func (a *CSRAdapter) request(q csr.Request) (*Client, CSRPolicy, error) {
	if a == nil || a.client == nil {
		return nil, CSRPolicy{}, ErrPolicy
	}
	p, ok := a.policies[q.DeviceID]
	target := a.client.targets[q.DeviceID]
	spec, err := csr.Normalize(q.Spec)
	expected, _ := json.Marshal(p.Spec)
	actual, _ := json.Marshal(spec)
	if !ok || err != nil || !bytes.Equal(actual, expected) || q.KeyLabel() == "" || target.Address.String() != q.Target || q.PolicySHA256 != p.PolicySHA256 || !deviceID.MatchString(q.ActiveTrustpoint) || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(q.BaselineSHA256) || !slices.Contains(p.StagingTrustpoints, q.Trustpoint) || strings.EqualFold(q.Trustpoint, q.ActiveTrustpoint) || strings.EqualFold(q.Trustpoint, q.KeyLabel()) || q.HostKeySHA256 == "" {
		return nil, p, ErrPolicy
	}
	activeProtected := false
	for _, name := range p.ProtectedNames {
		if strings.EqualFold(name, q.Trustpoint) || strings.EqualFold(name, q.KeyLabel()) {
			return nil, p, ErrPolicy
		}
		activeProtected = activeProtected || strings.EqualFold(name, q.ActiveTrustpoint)
	}
	if !activeProtected {
		return nil, p, ErrPolicy
	}
	c := *a.client
	c.observer = nil
	c.requiredHostKey = q.HostKeySHA256
	target.NETCONF = Endpoint{}
	c.targets = map[string]Target{q.DeviceID: target}
	return &c, p, nil
}
func (a *CSRAdapter) preflight(ctx context.Context, c *Client, p CSRPolicy, q csr.Request, empty bool) (csrPreflight, error) {
	e, err := c.Collect(ctx, q.DeviceID)
	if err != nil {
		return csrPreflight{}, err
	}
	version := "Cisco IOS XE Software, Version " + p.Version
	found := false
	for _, line := range strings.Split(string(e.Raw[ReadVersion]), "\n") {
		found = found || strings.TrimSpace(line) == version
	}
	if !found || a.verify(e, q) != nil {
		return csrPreflight{}, ErrPolicy
	}
	extra := Evidence{Raw: map[Operation][]byte{}, Capabilities: map[Operation]Capability{}}
	if err := c.readCLIOperations(ctx, c.targets[q.DeviceID], &extra, []Operation{ReadTrustpointConfig, ReadRSAKeys, ReadECKeys, ReadNTP}); err != nil {
		return csrPreflight{}, err
	}
	if !strings.Contains(string(extra.Raw[ReadNTP]), "Clock is synchronized") {
		return csrPreflight{}, ErrPolicy
	}
	config, err := trustpointConfig(extra.Raw[ReadTrustpointConfig])
	if err != nil {
		return csrPreflight{}, err
	}
	keys, err := publicKeys(extra.Raw[ReadRSAKeys])
	if err != nil {
		return csrPreflight{}, err
	}
	ec, err := publicKeys(extra.Raw[ReadECKeys])
	if err != nil {
		return csrPreflight{}, err
	}
	for name, key := range ec {
		if _, duplicate := keys[name]; duplicate {
			return csrPreflight{}, ErrPolicy
		}
		keys[name] = key
	}
	if _, exists := config[strings.ToLower(q.ActiveTrustpoint)]; !exists {
		return csrPreflight{}, ErrPolicy
	}
	if empty {
		if _, exists := config[strings.ToLower(q.Trustpoint)]; exists {
			return csrPreflight{}, ErrPolicy
		}
		if _, exists := keys[strings.ToLower(q.KeyLabel())]; exists {
			return csrPreflight{}, ErrPolicy
		}
		if _, exists := keys[strings.ToLower(q.Trustpoint)]; exists {
			return csrPreflight{}, ErrPolicy
		}
		for _, body := range config {
			for _, field := range strings.Fields(body) {
				if strings.EqualFold(field, q.KeyLabel()) {
					return csrPreflight{}, ErrPolicy
				}
			}
		}
	}
	return csrPreflight{config: config, keys: keys}, nil
}

// Inspect only reads current public evidence. It cannot recover a lost CSR,
// approve regeneration or release the journal's KEY_CREATING ownership.
func (a *CSRAdapter) Inspect(ctx context.Context, q csr.Request) error {
	c, p, err := a.request(q)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	_, err = a.preflight(ctx, c, p, q, false)
	return err
}

func (a *CSRAdapter) Generate(ctx context.Context, q csr.Request) (result csr.Result, err error) {
	c, p, err := a.request(q)
	if err != nil {
		return result, err
	}
	q.Spec = p.Spec
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	before, err := a.preflight(ctx, c, p, q, true)
	if err != nil {
		return result, err
	}
	client, cleanup, err := c.connect(ctx, c.targets[q.DeviceID], *c.targets[q.DeviceID].CLI)
	if err != nil {
		return result, err
	}
	defer cleanup()
	defer client.Close()
	shell, err := openCSRShell(client, c.limit)
	if err != nil {
		return result, err
	}
	defer func() {
		shell.close()
		if shell.stderr.Load() > 0 {
			err = ErrProtocol
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
		if err != nil {
			result = csr.Result{}
		}
	}()
	if _, err = shell.command("configure terminal", shell.host+"(config)#"); err != nil {
		return result, err
	}
	generated, generateErr := shell.command(fmt.Sprintf("crypto key generate rsa general-keys modulus %d label %s", q.Spec.RSABits, q.KeyLabel()), shell.host+"(config)#")
	if generateErr != nil {
		return result, generateErr
	}
	if !bytes.Contains(generated, []byte("[OK]")) {
		return result, ErrProtocol
	}
	if ctx.Err() != nil {
		err = ctx.Err()
		return result, err
	}
	if _, err = shell.command("end", shell.host+"#"); err != nil {
		return result, err
	}
	key, err := shell.readKey(q.KeyLabel())
	if err != nil {
		return result, err
	}
	for _, existing := range before.keys {
		if bytes.Equal(existing.DER, key.DER) {
			return result, ErrPolicy
		}
	}
	// Key generation may take time. Re-observe the binding and reserved slot
	// before configuring a trustpoint; never reuse a newly appeared slot.
	middle, err := a.preflight(ctx, c, p, q, false)
	if err != nil {
		return result, err
	}
	if _, exists := middle.config[strings.ToLower(q.Trustpoint)]; exists {
		return result, ErrPolicy
	}
	if len(middle.config) != len(before.config) || len(middle.keys) != len(before.keys)+1 {
		return result, ErrPolicy
	}
	middleKey, exists := middle.keys[strings.ToLower(q.KeyLabel())]
	if !exists || !middleKey.NonExportable || !bytes.Equal(middleKey.DER, key.DER) {
		return result, ErrPolicy
	}
	for name, body := range before.config {
		if middle.config[name] != body {
			return result, ErrPolicy
		}
	}
	for name, old := range before.keys {
		current, exists := middle.keys[name]
		if !exists || !bytes.Equal(old.DER, current.DER) || old.NonExportable != current.NonExportable {
			return result, ErrPolicy
		}
	}
	if _, err = shell.command("configure terminal", shell.host+"(config)#"); err != nil {
		return result, err
	}
	if _, err = shell.command("crypto pki trustpoint "+q.Trustpoint, shell.host+"(ca-trustpoint)#"); err != nil {
		return result, err
	}
	subject := "CN=" + q.Spec.CommonName
	if q.Spec.Organization != "" {
		subject += ",O=" + q.Spec.Organization
	}
	if q.Spec.OrganizationalUnit != "" {
		subject += ",OU=" + q.Spec.OrganizationalUnit
	}
	commands := []string{"enrollment terminal pem", "serial-number none", "fqdn none", "ip-address none", "subject-name " + subject, "subject-alt-name " + strings.Join(q.Spec.DNSNames, ","), "rsakeypair " + q.KeyLabel(), "hash sha256"}
	for _, command := range commands {
		if _, err = shell.command(command, shell.host+"(ca-trustpoint)#"); err != nil {
			return result, err
		}
	}
	if _, err = shell.command("exit", shell.host+"(config)#"); err != nil {
		return result, err
	}
	raw, err := shell.enroll(q.Trustpoint)
	if err != nil {
		return result, err
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return result, ErrProtocol
	}
	if _, err = shell.command("end", shell.host+"#"); err != nil {
		return result, err
	}
	afterKey, err := shell.readKey(q.KeyLabel())
	if err != nil || !bytes.Equal(key.DER, afterKey.DER) {
		return result, ErrPolicy
	}
	after, err := a.preflight(ctx, c, p, q, false)
	if err != nil {
		return result, err
	}
	if len(after.config) != len(before.config)+1 || len(after.keys) != len(before.keys)+1 {
		return result, ErrPolicy
	}
	created, exists := after.keys[strings.ToLower(q.KeyLabel())]
	if !exists || !created.NonExportable || !bytes.Equal(created.DER, key.DER) {
		return result, ErrPolicy
	}
	for name, body := range before.config {
		if after.config[name] != body {
			return result, ErrPolicy
		}
	}
	for name, key := range before.keys {
		observed, exists := after.keys[name]
		if !exists || !bytes.Equal(key.DER, observed.DER) || key.NonExportable != observed.NonExportable {
			return result, ErrPolicy
		}
	}
	stageFields := map[string]bool{}
	for _, line := range strings.Split(after.config[strings.ToLower(q.Trustpoint)], "\n") {
		if line != "" {
			if stageFields[line] {
				return result, ErrPolicy
			}
			stageFields[line] = true
		}
	}
	for _, command := range commands {
		if !stageFields[command] {
			return result, ErrPolicy
		}
	}
	result = csr.Result{DER: slices.Clone(block.Bytes), PublicKeyDER: slices.Clone(key.DER), NonExportable: key.NonExportable}
	if csr.Validate(result, q.Spec) != nil {
		return csr.Result{}, ErrPolicy
	}
	return result, nil
}

func trustpointConfig(raw []byte) (map[string]string, error) {
	if !csrText(raw) {
		return nil, ErrProtocol
	}
	out := map[string]string{}
	name := ""
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" || strings.TrimSpace(line) == "!" {
			continue
		}
		if strings.HasPrefix(line, "crypto pki trustpoint ") {
			candidate := strings.TrimPrefix(line, "crypto pki trustpoint ")
			if !deviceID.MatchString(candidate) {
				return nil, ErrProtocol
			}
			name = strings.ToLower(candidate)
			if _, exists := out[name]; exists {
				return nil, ErrProtocol
			}
			out[name] = ""
			continue
		}
		if name == "" || (!strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t")) {
			return nil, ErrProtocol
		}
		out[name] += strings.TrimSpace(line) + "\n"
	}
	return out, nil
}
func publicKeys(raw []byte) (map[string]publicKey, error) {
	if !csrText(raw) {
		return nil, ErrProtocol
	}
	out := map[string]publicKey{}
	name := ""
	data := false
	nonExportable := false
	exportSeen := false
	var encoded strings.Builder
	flush := func() error {
		if name == "" {
			return nil
		}
		der, err := hex.DecodeString(encoded.String())
		if err != nil || len(der) == 0 || len(der) > 2048 {
			return ErrProtocol
		}
		if _, err := x509.ParsePKIXPublicKey(der); err != nil {
			return ErrProtocol
		}
		if _, exists := out[name]; exists {
			return ErrProtocol
		}
		out[name] = publicKey{DER: der, NonExportable: nonExportable}
		return nil
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "% Key pair was generated at:") {
			if err := flush(); err != nil {
				return nil, err
			}
			name = ""
			data = false
			encoded.Reset()
			nonExportable = false
			exportSeen = false
			continue
		}
		if strings.HasPrefix(line, "Key name:") {
			if name != "" {
				if err := flush(); err != nil {
					return nil, err
				}
				encoded.Reset()
				data = false
				nonExportable = false
				exportSeen = false
			}
			label := strings.TrimSpace(strings.TrimPrefix(line, "Key name:"))
			if !deviceID.MatchString(label) {
				return nil, ErrProtocol
			}
			name = strings.ToLower(label)
			continue
		}
		if name == "" {
			return nil, ErrProtocol
		}
		switch {
		case line == "Key Data:":
			data = true
		case line == "Key is not exportable." || line == "Key is not exportable. Redundancy enabled.":
			if exportSeen {
				return nil, ErrProtocol
			}
			exportSeen = true
			nonExportable = true
		case strings.HasPrefix(line, "Key is exportable."):
			if exportSeen {
				return nil, ErrProtocol
			}
			exportSeen = true
			nonExportable = false
		case strings.HasPrefix(line, "Key type:") || strings.HasPrefix(line, "Storage Device:") || strings.HasPrefix(line, "Usage:") || line == "Temporary key":
		case data:
			part := strings.Join(strings.Fields(line), "")
			if !regexp.MustCompile(`^[0-9A-Fa-f]+$`).MatchString(part) || encoded.Len()+len(part) > 4096 {
				return nil, ErrProtocol
			}
			encoded.WriteString(part)
		default:
			return nil, ErrProtocol
		}
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return out, nil
}
func csrText(raw []byte) bool {
	if len(raw) > 4<<20 {
		return false
	}
	s := strings.ToLower(string(raw))
	for _, word := range []string{"--more--", "authorization failed", "access denied", "invalid input", "private key"} {
		if strings.Contains(s, word) {
			return false
		}
	}
	for _, b := range raw {
		if b < 32 && b != '\r' && b != '\n' && b != '\t' || b == 127 {
			return false
		}
	}
	return true
}

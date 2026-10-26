package device

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
)

type StagePolicy struct {
	CSRPolicy
	Ancestors map[string]string // higher CA SHA256 -> existing protected trustpoint
}
type StageAdapter struct {
	client   *Client
	policies map[string]StagePolicy
	csrScope map[string]CSRPolicy
	verify   func(Evidence, staging.Request, map[string]string) (staging.Observation, error)
	settings map[string]string
}

func NewStageAdapter(c *Client, policies map[string]StagePolicy, verify func(Evidence, staging.Request, map[string]string) (staging.Observation, error)) (*StageAdapter, error) {
	if verify == nil {
		return nil, ErrPolicy
	}
	common := map[string]CSRPolicy{}
	for id, p := range policies {
		common[id] = p.CSRPolicy
	}
	scope, err := csrPolicies(c, common)
	if err != nil {
		return nil, err
	}
	a := &StageAdapter{client: c, policies: map[string]StagePolicy{}, csrScope: scope, verify: verify, settings: map[string]string{}}
	for id, p := range policies {
		p.CSRPolicy = scope[id]
		p.Ancestors = maps.Clone(p.Ancestors)
		seen := map[string]bool{}
		for h, name := range p.Ancestors {
			if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(h) || !deviceID.MatchString(name) || !slices.Contains(p.ProtectedNames, name) || slices.Contains(p.StagingTrustpoints, name) || seen[strings.ToLower(name)] {
				return nil, ErrPolicy
			}
			seen[strings.ToLower(name)] = true
		}
		a.policies[id] = p
		raw, _ := json.Marshal(struct {
			Policy  StagePolicy
			Target  Target
			Timeout int64
		}{p, c.targets[id], int64(c.timeout)})
		a.settings[id] = certpolicy.SHA256(raw)
	}
	return a, nil
}
func (a *StageAdapter) SettingsSHA256(id string) string {
	if a == nil {
		return ""
	}
	return a.settings[id]
}
func (a *StageAdapter) request(q staging.Request) (*Client, StagePolicy, error) {
	if a == nil || a.client == nil || staging.Validate(q) != nil {
		return nil, StagePolicy{}, ErrPolicy
	}
	c, _, err := scopedCSRClient(a.client, a.csrScope, q.CSR)
	return c, a.policies[q.CSR.DeviceID], err
}
func (a *StageAdapter) preflight(ctx context.Context, c *Client, p StagePolicy, q staging.Request) (staging.Observation, error) {
	e, err := c.Collect(ctx, q.CSR.DeviceID)
	if err != nil {
		return staging.Observation{}, err
	}
	version := "Cisco IOS XE Software, Version " + p.Version
	found := false
	for _, line := range strings.Split(string(e.Raw[ReadVersion]), "\n") {
		found = found || strings.TrimSpace(line) == version
	}
	if !found {
		return staging.Observation{}, ErrPolicy
	}
	o, err := a.verify(e, q, maps.Clone(p.Ancestors))
	if err != nil {
		return o, err
	}
	extra := Evidence{Raw: map[Operation][]byte{}, Capabilities: map[Operation]Capability{}}
	if err = c.readCLIOperations(ctx, c.targets[q.CSR.DeviceID], &extra, []Operation{ReadTrustpointConfig, ReadRSAKeys, ReadECKeys, ReadNTP}); err != nil {
		return o, err
	}
	if !strings.Contains(string(extra.Raw[ReadNTP]), "Clock is synchronized") {
		return o, ErrPolicy
	}
	config, err := trustpointConfig(extra.Raw[ReadTrustpointConfig])
	if err != nil {
		return o, err
	}
	keys, err := publicKeys(extra.Raw[ReadRSAKeys])
	if err != nil {
		return o, err
	}
	ec, err := publicKeys(extra.Raw[ReadECKeys])
	if err != nil {
		return o, err
	}
	for name, key := range ec {
		if _, ok := keys[name]; ok {
			return o, ErrPolicy
		}
		keys[name] = key
	}
	body, ok := config[strings.ToLower(q.CSR.Trustpoint)]
	if !ok {
		return o, ErrPolicy
	}
	actual := strings.Split(strings.TrimSpace(body), "\n")
	expected := csrTrustpointCommands(p.Spec, q.CSR.KeyLabel())
	slices.Sort(actual)
	slices.Sort(expected)
	if !slices.Equal(actual, expected) {
		return o, ErrPolicy
	}
	delete(config, strings.ToLower(q.CSR.Trustpoint))
	for _, body := range config {
		for _, field := range strings.Fields(body) {
			if strings.EqualFold(field, q.CSR.KeyLabel()) {
				return o, ErrPolicy
			}
		}
	}
	key, ok := keys[strings.ToLower(q.CSR.KeyLabel())]
	if !ok || !key.NonExportable || !bytes.Equal(key.DER, q.Material.PublicKeyDER) {
		return o, ErrPolicy
	}
	o.PublicKeyDER = bytes.Clone(key.DER)
	o.NonExportable = key.NonExportable
	raw, _ := json.Marshal(struct {
		Inventory string
		Config    map[string]string
		Keys      map[string]publicKey
	}{o.OtherStateSHA256, config, keys})
	o.OtherStateSHA256 = certpolicy.SHA256(raw)
	if err = o.Check(q, ""); err != nil {
		return o, err
	}
	return o, nil
}
func (a *StageAdapter) Inspect(ctx context.Context, q staging.Request) (staging.Observation, error) {
	c, p, err := a.request(q)
	if err != nil {
		return staging.Observation{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return a.preflight(ctx, c, p, q)
}

// Import writes only a public issuer and leaf to the already owned CSR slot.
// No key generation, trustpoint reconfiguration, HTTPS switch or save exists.
func (a *StageAdapter) Import(ctx context.Context, q staging.Request, authorize func(context.Context) error) (err error) {
	c, p, err := a.request(q)
	if err != nil {
		return err
	}
	if authorize == nil {
		return ErrPolicy
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	before, err := a.preflight(ctx, c, p, q)
	if err != nil {
		return err
	}
	if len(before.LeafDER) != 0 || len(before.IssuerDER) != 0 {
		return ErrPolicy
	}
	if err = authorize(ctx); err != nil {
		return err
	}
	client, cleanup, err := c.connect(ctx, c.targets[q.CSR.DeviceID], *c.targets[q.CSR.DeviceID].CLI)
	if err != nil {
		return err
	}
	defer cleanup()
	defer client.Close()
	shell, err := openCSRShell(client, c.limit)
	if err != nil {
		return err
	}
	defer func() {
		shell.close()
		if shell.stderr.Load() != 0 {
			err = ErrProtocol
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		}
	}()
	if _, err = shell.command("configure terminal", shell.host+"(config)#"); err != nil {
		return err
	}
	if err = shell.importPublic(ctx, q.CSR.Trustpoint, q.ChainDER[1], true, authorize); err != nil {
		return err
	}
	if _, err = shell.command("end", shell.host+"#"); err != nil {
		return err
	}
	middle, err := a.preflight(ctx, c, p, q)
	if err != nil {
		return err
	}
	if middle.OtherStateSHA256 != before.OtherStateSHA256 || len(middle.LeafDER) != 0 || !bytes.Equal(middle.IssuerDER, q.ChainDER[1]) {
		return ErrPolicy
	}
	if _, err = shell.command("configure terminal", shell.host+"(config)#"); err != nil {
		return err
	}
	if err = shell.importPublic(ctx, q.CSR.Trustpoint, q.LeafDER, false, authorize); err != nil {
		return err
	}
	if _, err = shell.command("end", shell.host+"#"); err != nil {
		return err
	}
	after, err := a.preflight(ctx, c, p, q)
	if err != nil {
		return err
	}
	if after.OtherStateSHA256 != before.OtherStateSHA256 || !after.Complete(q) {
		return ErrPolicy
	}
	return nil
}

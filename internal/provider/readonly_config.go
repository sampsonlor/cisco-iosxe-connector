package provider

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
)

// References are opaque identifiers resolved by a future adapter, never fetched
// as URLs by the provider. No credentials, userinfo, query strings or fragments.
var secretReference = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}://[A-Za-z0-9][A-Za-z0-9/_.-]{0,127}$`)

func LoadReadOnlyConfig(r io.Reader) (ReadOnlyConfig, error) {
	var cfg ReadOnlyConfig
	raw, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return cfg, errors.New("configuration unreadable or too large")
	}
	v, err := strictJSON(raw)
	if err != nil {
		return cfg, errors.New("invalid configuration JSON")
	}
	root, ok := object(v, []string{"devices"})
	if !ok {
		return cfg, errors.New("invalid configuration fields")
	}
	devices, ok := root["devices"].(map[string]any)
	if !ok {
		return cfg, errors.New("invalid devices configuration")
	}
	for _, v := range devices {
		d, ok := object(v, []string{"policy", "credentialRef", "hostKeyRef"})
		if !ok {
			return cfg, errors.New("invalid device fields")
		}
		if _, ok := object(d["policy"], []string{"target", "activeTrustpoint"}, "stagingTrustpoints"); !ok {
			return cfg, errors.New("invalid policy fields")
		}
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, errors.New("invalid configuration types")
	}
	validated, _, err := validateReadOnlyConfig(cfg)
	if err != nil {
		return ReadOnlyConfig{}, err
	}
	return ReadOnlyConfig{Devices: validated}, nil
}

func validateReadOnlyConfig(cfg ReadOnlyConfig) (map[string]ManagedDevice, Config, error) {
	policy := Config{Devices: map[string]DevicePolicy{}, ResolveEntity: func(_ context.Context, _ string) (string, error) { return "", nil }}
	for id, d := range cfg.Devices {
		if !secretReference.MatchString(d.CredentialRef) || !secretReference.MatchString(d.HostKeyRef) {
			return nil, policy, errors.New("credential and host identity references are required")
		}
		policy.Devices[id] = d.Policy
	}
	if err := validateConfig(http.NotFoundHandler(), &policy); err != nil {
		return nil, policy, err
	}
	out := make(map[string]ManagedDevice, len(cfg.Devices))
	for id, d := range cfg.Devices {
		d.Policy = policy.Devices[id]
		out[id] = d
	}
	return out, policy, nil
}

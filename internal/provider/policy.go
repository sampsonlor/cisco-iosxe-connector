package provider

import (
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

var (
	cliToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	uuidText = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

func canonicalUUID(s string) bool {
	return uuidText.MatchString(s) && s != "00000000-0000-0000-0000-000000000000"
}

func validateConfig(next http.Handler, cfg *Config) error {
	if next == nil || cfg.ResolveEntity == nil || len(cfg.Devices) == 0 {
		return errors.New("handler, entity resolver and approved devices are required")
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxBodyBytes < 1 || cfg.MaxBodyBytes > 4<<20 {
		return errors.New("request limit must be between 1 byte and 4 MiB")
	}
	devices := make(map[string]DevicePolicy, len(cfg.Devices))
	targets := make(map[netip.Addr]bool, len(cfg.Devices))
	for id, p := range cfg.Devices {
		if !cliToken.MatchString(id) || !p.Target.IsGlobalUnicast() || p.Target.IsLoopback() ||
			p.Target.Is4In6() || p.Target.Zone() != "" || targets[p.Target] || !cliToken.MatchString(p.ActiveTrustpoint) {
			return errors.New("invalid or duplicate device identity, target or active Trustpoint")
		}
		targets[p.Target] = true
		if len(p.StagingTrustpoints) > 16 {
			return errors.New("too many staging Trustpoints")
		}
		seen := map[string]bool{strings.ToLower(p.ActiveTrustpoint): true}
		for _, name := range p.StagingTrustpoints {
			folded := strings.ToLower(name)
			if !cliToken.MatchString(name) || seen[folded] {
				return errors.New("unsafe, duplicate or active staging Trustpoint")
			}
			seen[folded] = true
		}
		p.StagingTrustpoints = slices.Clone(p.StagingTrustpoints)
		devices[id] = p
	}
	cfg.Devices = devices
	return nil
}

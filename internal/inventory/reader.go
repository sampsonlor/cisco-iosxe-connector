package inventory

import (
	"context"
	"net/netip"
	"reflect"
	"slices"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/provider"
)

// Source must be constructed from an operator-approved transport registry.
type Source interface {
	ApprovedTarget(string, netip.Addr, string, string) bool
	Collect(context.Context, string) (device.Evidence, error)
}
type Reader struct {
	source      Source
	assignments map[string][]Assignment
}

func NewReader(source Source, assignments map[string][]Assignment) (*Reader, error) {
	if source == nil || (reflect.ValueOf(source).Kind() == reflect.Pointer && reflect.ValueOf(source).IsNil()) {
		return nil, device.ErrPolicy
	}
	out := map[string][]Assignment{}
	for id, list := range assignments {
		if !namePattern.MatchString(id) || len(list) > 32 {
			return nil, device.ErrPolicy
		}
		seen := map[string]bool{}
		for _, a := range list {
			if !namePattern.MatchString(a.Trustpoint) || !shaPattern.MatchString(a.SHA256) || (a.Role != "STAGED" && a.Role != "ROLLBACK") || seen[a.Trustpoint] {
				return nil, device.ErrPolicy
			}
			seen[a.Trustpoint] = true
		}
		out[id] = slices.Clone(list)
	}
	return &Reader{source: source, assignments: out}, nil
}
func (r *Reader) ReadHTTPS(ctx context.Context, a provider.DeviceAccess) (provider.InventorySnapshot, error) {
	if err := ctx.Err(); err != nil {
		return provider.InventorySnapshot{}, err
	}
	d := a.Device
	if !r.source.ApprovedTarget(a.DeviceID, d.Policy.Target, d.CredentialRef, d.HostKeyRef) {
		return provider.InventorySnapshot{}, device.ErrPolicy
	}
	for _, assignment := range r.assignments[a.DeviceID] {
		approved := slices.Contains(d.Policy.StagingTrustpoints, assignment.Trustpoint)
		if assignment.Role == "ROLLBACK" && assignment.Trustpoint == d.Policy.ActiveTrustpoint {
			approved = true
		}
		if !approved {
			return provider.InventorySnapshot{}, device.ErrPolicy
		}
	}
	e, err := r.source.Collect(ctx, a.DeviceID)
	if err != nil {
		return provider.InventorySnapshot{}, err
	}
	if err = ctx.Err(); err != nil {
		return provider.InventorySnapshot{}, err
	}
	s, err := Parse(e, r.assignments[a.DeviceID])
	if err != nil {
		return provider.InventorySnapshot{}, err
	}
	out := provider.InventorySnapshot{Complete: true}
	index := map[string]int{}
	for _, c := range s.Certificates {
		i, ok := index[c.SHA256]
		if !ok {
			i = len(out.Certificates)
			index[c.SHA256] = i
			out.Certificates = append(out.Certificates, provider.PublicCertificate{DER: slices.Clone(c.DER)})
		}
		out.Certificates[i].Bindings = append(out.Certificates[i].Bindings, provider.TrustpointBinding{Trustpoint: c.Trustpoint, Role: c.Role})
	}
	return out, nil
}

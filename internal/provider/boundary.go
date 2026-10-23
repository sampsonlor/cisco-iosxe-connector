// Package provider implements the connector's ILM v1 HTTP boundary.
package provider

import (
	"context"
	"net/http"
	"net/netip"
)

// Stable connector-owned attribute identities. Names and UUIDs must match.
const (
	DeviceIDAttribute          = "4c198a4c-0f9a-4b65-a378-1a8996a20101"
	TargetAddressAttribute     = "4c198a4c-0f9a-4b65-a378-1a8996a20102"
	ServiceAttribute           = "4c198a4c-0f9a-4b65-a378-1a8996a20103"
	StagingTrustpointAttribute = "4c198a4c-0f9a-4b65-a378-1a8996a20104"
	OperationIDAttribute       = "4c198a4c-0f9a-4b65-a378-1a8996a20105"
)

// DevicePolicy is supplied by an operator, never by an ILM request.
type DevicePolicy struct {
	Target             netip.Addr
	ActiveTrustpoint   string
	StagingTrustpoints []string
}

// EntityResolver returns the immutable device binding for a stored entity.
// An empty ID with a nil error means not found. Implementations must be safe
// for concurrent requests. Errors are not exposed to clients.
type EntityResolver func(context.Context, string) (deviceID string, err error)

type Config struct {
	Devices       map[string]DevicePolicy
	ResolveEntity EntityResolver
	MaxBodyBytes  int64 // Zero selects 1 MiB; the maximum is 4 MiB.
}

// NewBoundary wraps the SDK handler. Authentication belongs outside this layer;
// transaction authorization and live device preflight belong in the backend.
func NewBoundary(next http.Handler, cfg Config) (http.Handler, error) {
	return next, nil // Replaced after the strict boundary tests demonstrate failure.
}

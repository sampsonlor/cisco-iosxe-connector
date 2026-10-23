// Package provider implements the connector's ILM v1 HTTP boundary.
package provider

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"path"
	"strings"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
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
	Target             netip.Addr `json:"target"`
	ActiveTrustpoint   string     `json:"activeTrustpoint"`
	StagingTrustpoints []string   `json:"stagingTrustpoints,omitempty"`
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
	if err := validateConfig(next, &cfg); err != nil {
		return nil, err
	}
	return &boundary{next: next, cfg: cfg}, nil
}

type boundary struct {
	next http.Handler
	cfg  Config
}

func reject(w http.ResponseWriter, status int, message string) {
	var payload any = shared.V1ErrorMessageDto{Message: message}
	if status == http.StatusUnprocessableEntity {
		payload = []string{message}
	}
	// All messages are connector-owned constants, without request values,
	// backend errors, credentials or device output.
	_ = shared.WriteJSON(w, status, payload)
}

func (b *boundary) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Reject aliases before the SDK's router can clean or redirect a path.
	if r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path ||
		path.Clean(r.URL.Path) != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery {
		reject(w, 400, "non-canonical path or unsupported query")
		return
	}
	route, status := matchRoute(r.URL.Path, r.Method)
	if status != 0 {
		if status == 405 {
			w.Header().Set("Allow", route.methods)
		}
		reject(w, status, http.StatusText(status))
		return
	}
	deviceID := ""
	if route.entityID != "" {
		var err error
		deviceID, err = b.cfg.ResolveEntity(r.Context(), route.entityID)
		if err != nil {
			reject(w, 500, "entity binding lookup failed")
			return
		}
		if _, ok := b.cfg.Devices[deviceID]; !ok {
			reject(w, 404, "entity not found")
			return
		}
	}
	// Safe deletion requires journal ownership and protected-resource checks.
	// Do not pass removal to an SDK/backend that has not implemented them.
	if route.shape == "remove" {
		reject(w, 501, "certificate removal is not implemented")
		return
	}
	if route.shape == "" {
		if r.Body != nil {
			one, err := io.ReadAll(io.LimitReader(r.Body, 1))
			if err != nil || len(one) != 0 {
				reject(w, 400, "request body is not allowed")
				return
			}
		}
	} else {
		mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/json" || r.Header.Get("Content-Encoding") != "" {
			reject(w, 415, "expected unencoded application/json")
			return
		}
		var raw []byte
		if r.Body != nil {
			raw, err = io.ReadAll(io.LimitReader(r.Body, b.cfg.MaxBodyBytes+1))
		}
		if err != nil {
			reject(w, 400, "request body could not be read")
			return
		}
		if int64(len(raw)) > b.cfg.MaxBodyBytes {
			reject(w, 413, "request body exceeds the configured limit")
			return
		}
		value, err := strictJSON(raw)
		if err != nil {
			reject(w, 400, "invalid or ambiguous JSON request")
			return
		}
		if !b.validRequest(route.shape, deviceID, value) {
			reject(w, 422, "request does not match the connector attribute policy")
			return
		}
		// Forward the exact validated bytes, without using SDK-generated
		// AdditionalProperties decoding as a security decision.
		r.Body = io.NopCloser(bytes.NewReader(raw))
	}
	if route.noContent {
		adapted := &validationWriter{ResponseWriter: w}
		b.next.ServeHTTP(adapted, r)
		if !adapted.wrote {
			adapted.WriteHeader(http.StatusOK)
		}
		return
	}
	b.next.ServeHTTP(w, r)
}

type endpoint struct {
	entityID, methods, shape string
	noContent                bool
}

func matchRoute(p, method string) (endpoint, int) {
	var e endpoint
	switch p {
	case "/v1", "/v1/health":
		e.methods = "GET"
	case "/v1/entityProvider/iosxe/attributes":
		e.methods = "GET"
	case "/v1/entityProvider/iosxe/attributes/validate":
		e.methods, e.shape = "POST", "entityAttrs"
	case "/v1/entityProvider/entities":
		e.methods = "GET, POST"
		if method == "POST" {
			e.shape = "entity"
		}
	default:
		tail, ok := strings.CutPrefix(p, "/v1/entityProvider/entities/")
		if !ok {
			return e, 404
		}
		id, suffix, _ := strings.Cut(tail, "/")
		if !canonicalUUID(id) {
			return e, 400
		}
		e.entityID = id
		switch suffix {
		case "":
			e.methods = "GET, PUT, DELETE"
			if method == "PUT" {
				e.shape = "entity"
			}
		case "location/attributes", "locations/csr/attributes", "locations/push/attributes":
			e.methods = "GET"
		case "location/attributes/validate":
			e.methods, e.shape, e.noContent = "POST", "locationAttrs", true
		case "locations/csr/attributes/validate":
			e.methods, e.shape, e.noContent = "POST", "csrAttrs", true
		case "locations/push/attributes/validate":
			e.methods, e.shape, e.noContent = "POST", "pushAttrs", true
		case "locations":
			e.methods, e.shape = "POST", "location"
		case "locations/csr":
			e.methods, e.shape = "POST", "csr"
		case "locations/push":
			e.methods, e.shape = "POST", "push"
		case "locations/remove":
			e.methods, e.shape = "POST", "remove"
		default:
			return e, 404
		}
	}
	for _, allowed := range strings.Split(e.methods, ", ") {
		if method == allowed {
			return e, 0
		}
	}
	return e, 405
}

// Only the three per-entity validation routes use this writer. It streams
// errors unchanged and suppresses successful bodies without buffering them.
type validationWriter struct {
	http.ResponseWriter
	wrote, noBody bool
}

func (w *validationWriter) WriteHeader(status int) {
	if status < 200 {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.wrote {
		return
	}
	w.wrote = true
	if status == http.StatusOK || status == http.StatusNoContent {
		status, w.noBody = http.StatusNoContent, true
		w.Header().Del("Content-Length")
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *validationWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(http.StatusOK)
	}
	if w.noBody {
		return len(p), nil
	}
	return w.ResponseWriter.Write(p)
}

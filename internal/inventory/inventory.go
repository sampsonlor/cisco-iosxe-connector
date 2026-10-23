// Package inventory interprets public, read-only IOS XE evidence.
package inventory

import (
	"errors"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
)

var ErrIncomplete = errors.New("inventory evidence incomplete or inconsistent")
var ErrUnsupported = errors.New("inventory format unsupported")

type Assignment struct {
	Trustpoint, SHA256, Role string
}

type Certificate struct {
	Trustpoint, SHA256, Kind, Role string
	DER                            []byte
}

type Snapshot struct {
	Complete         bool
	ActiveTrustpoint string
	Certificates     []Certificate
}

func Parse(device.Evidence, []Assignment) (Snapshot, error) {
	return Snapshot{}, ErrIncomplete
}

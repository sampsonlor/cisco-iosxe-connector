package lab

import (
	"errors"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
)

// Replay validates captured public reply semantics only. It cannot establish
// current device state, rerun AAA/TLS, or turn a report into live acceptance.
func Replay(r Report) (inventory.Snapshot, error) {
	e := device.Evidence{Complete: true, Raw: map[device.Operation][]byte{}, Capabilities: map[device.Operation]device.Capability{}}
	for _, read := range r.WireReads {
		switch read.Operation {
		case device.ReadVersion, device.ReadPKI, device.ReadBinding, device.ReadCertificates, device.ReadHTTPSStatus:
			if !read.Complete {
				return inventory.Snapshot{}, errors.New("incomplete wire read cannot be replayed")
			}
			e.Raw[read.Operation] = read.Data
			e.Capabilities[read.Operation] = device.Capability{Available: true, Transport: "ssh"}
		}
	}
	return inventory.Parse(e, nil)
}

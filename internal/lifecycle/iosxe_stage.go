package lifecycle

import (
	"context"
	"encoding/json"
	"net"
	"strconv"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/certpolicy"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lab"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/staging"
)

// NewIOSXEStageGate fixes the production verifier/probe wiring. A new TLS
// handshake authenticates exact DER from pinned SSH plus the approved name;
// no management HTTP request or credential is sent to HTTPS.
func NewIOSXEStageGate(s *journal.Store, v *certpolicy.Validator, c *device.Client, policies map[string]device.StagePolicy, tlsPorts map[string]uint16) (*StageGate, error) {
	a, err := device.NewStageAdapter(c, policies, inventory.VerifyStageInventory)
	if err != nil {
		return nil, err
	}
	ports := map[string]uint16{}
	settings := map[string]string{}
	if len(tlsPorts) != len(policies) {
		return nil, device.ErrPolicy
	}
	for id := range policies {
		port := tlsPorts[id]
		if port == 0 {
			return nil, device.ErrPolicy
		}
		ports[id] = port
		raw, _ := json.Marshal(struct {
			Adapter string
			Port    uint16
			TLSMode string
		}{a.SettingsSHA256(id), port, "fresh-tls12-exact-baseline-der-and-csr-hostname"})
		settings[id] = certpolicy.SHA256(raw)
	}
	return NewStageGate(s, v, settings, a, func(ctx context.Context, q staging.Request, active []byte) error {
		_, err := lab.ProbeTLS(ctx, net.JoinHostPort(q.CSR.Target, strconv.Itoa(int(ports[q.CSR.DeviceID]))), q.CSR.Spec.CommonName, active, nil)
		return err
	})
}

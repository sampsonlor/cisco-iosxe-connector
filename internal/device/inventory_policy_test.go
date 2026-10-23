package device

import (
	"net/netip"
	"testing"
	"time"
)

func TestInventoryTargetBindingAndCANotices(t *testing.T) {
	for _, netconf := range []bool{false, true} {
		ep := Endpoint{22, "secret://test/reader", "hostkey://test/ssh"}
		target := Target{Address: netip.MustParseAddr("192.0.2.10"), CLI: &ep}
		pin := ep.HostKeyRef
		if netconf {
			target.NETCONF = Endpoint{830, ep.CredentialRef, "hostkey://test/netconf"}
			pin = target.NETCONF.HostKeyRef
		}
		c, err := NewClient(map[string]Target{"router-a": target}, testResolver{}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if !c.ApprovedTarget("router-a", target.Address, ep.CredentialRef, pin) || c.ApprovedTarget("router-b", target.Address, ep.CredentialRef, pin) || c.ApprovedTarget("router-a", netip.MustParseAddr("192.0.2.11"), ep.CredentialRef, pin) || c.ApprovedTarget("router-a", target.Address, "secret://other", pin) || c.ApprovedTarget("router-a", target.Address, ep.CredentialRef, "hostkey://other") {
			t.Fatal("inventory target check failed")
		}
	}
	if (*Client)(nil).ApprovedTarget("router-a", netip.Addr{}, "", "") {
		t.Fatal("nil client approved")
	}
	for _, s := range []string{"% The specified trustpoint is not enrolled (TEST).\n% Only export the CA certificate in PEM format.\n% CA certificate:", "% CA certificate:"} {
		if err := classifyCLI([]byte(s), nil, false); err != nil {
			t.Fatal("documented informational notice rejected")
		}
	}
	for _, s := range []string{"% Error: failed to get CA cert.", "% CA certificate: unknown error", "% The specified trustpoint is not enrolled (BAD;COMMAND)."} {
		if classifyCLI([]byte(s), nil, false) == nil {
			t.Fatal("unknown or failed read admitted")
		}
	}
}

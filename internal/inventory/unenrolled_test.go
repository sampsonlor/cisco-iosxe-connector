package inventory_test

import (
	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/inventory"
	"strings"
	"testing"
)

func TestExplicitUnenrolledStagingTrustpoint(t *testing.T) {
	f := synthetic(t, false)
	f.e.Raw[device.ReadPKI] = append(f.e.Raw[device.ReadPKI], []byte("Trustpoint NEW-STAGE:\n    Subject Name:\n    cn=router.example.test\n")...)
	f.e.Raw[device.ReadCertificates] = append(f.e.Raw[device.ReadCertificates], []byte("------Trustpoint: NEW-STAGE------\n% The specified trustpoint is not enrolled (NEW-STAGE).\n")...)
	s, err := inventory.Parse(f.e, nil)
	if err != nil || !s.Complete || len(s.Certificates) != 8 || len(s.UnenrolledTrustpoints) != 1 || s.UnenrolledTrustpoints[0] != "NEW-STAGE" {
		t.Fatal("explicit unenrolled staging slot broke inventory", err)
	}
	for _, notice := range []string{"", "% The specified trustpoint is not enrolled (OTHER)."} {
		f.e.Raw[device.ReadCertificates] = []byte(strings.ReplaceAll(string(f.e.Raw[device.ReadCertificates]), "% The specified trustpoint is not enrolled (NEW-STAGE).", notice))
		if _, err := inventory.Parse(f.e, nil); err == nil {
			t.Fatal("missing/wrong unenrolled proof accepted")
		}
	}
}

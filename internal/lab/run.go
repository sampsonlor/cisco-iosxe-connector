package lab

import (
	"context"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
)

type Collector interface {
	Collect(context.Context, string) (device.Evidence, error)
	Readiness(context.Context, string) (device.Evidence, error)
}
type Config struct {
	DeviceID, TLSAddress, Hostname string
	NETCONF                        func(context.Context) (device.Evidence, error)
}
type Report struct {
	Status                            string
	Checks                            map[string]bool
	Notes                             []string
	Readiness, Before, After, NETCONF device.Evidence
	TLSBefore, TLSAfter               TLSResult
}

func Run(context.Context, Collector, Config) Report {
	return Report{Status: "INCOMPLETE", Checks: map[string]bool{}}
}
func WriteReport(string, Report) (string, error) { return "", device.ErrRead }

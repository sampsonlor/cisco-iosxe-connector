// iosxe-lab is a manually invoked private-network read-only acceptance tool.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/device"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/lab"
	"golang.org/x/crypto/ssh"
)

type sessionResolver struct {
	username, password string
	key                ssh.PublicKey
}

func (s sessionResolver) Credentials(context.Context, string) (device.Credentials, error) {
	return device.Credentials{Username: s.username, Password: s.password}, nil
}
func (s sessionResolver) HostKey(context.Context, string) (ssh.PublicKey, error) { return s.key, nil }

func main() { os.Exit(run()) }
func run() int {
	address := flag.String("address", "", "approved literal management IP")
	hostname := flag.String("hostname", "", "approved HTTPS DNS name")
	username := flag.String("username", "", "SSH username")
	sshPort := flag.Uint("ssh-port", 22, "approved CLI port")
	netconfPort := flag.Uint("netconf-port", 0, "approved NETCONF port; zero selects CLI-only acceptance")
	httpsPort := flag.Uint("https-port", 443, "approved HTTPS port")
	keyPath := flag.String("host-key-file", "", "trusted OpenSSH public host key file")
	directory := flag.String("evidence-dir", "", "private absolute directory outside Git checkouts")
	flag.Parse()
	ip, err := netip.ParseAddr(*address)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Is4In6() || ip.Zone() != "" || *sshPort == 0 || *sshPort > 65535 || *httpsPort == 0 || *httpsPort > 65535 || *netconfPort > 65535 || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`).MatchString(*username) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`).MatchString(*hostname) || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "invalid approved lab policy")
		return 2
	}
	if err = lab.ValidateEvidenceDirectory(*directory); err != nil {
		fmt.Fprintln(os.Stderr, "private evidence directory must be new, absolute and outside a checkout")
		return 2
	}
	info, err := os.Stat(*keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		fmt.Fprintln(os.Stderr, "trusted host public key unavailable")
		return 2
	}
	raw, err := os.ReadFile(*keyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trusted host public key unreadable")
		return 2
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey(raw)
	if err != nil || len(options) != 0 || len(rest) != 0 {
		fmt.Fprintln(os.Stderr, "invalid trusted host public key")
		return 2
	}
	password, err := promptPassword(*username, *hostname+":"+strconv.FormatUint(uint64(*sshPort), 10))
	if err != nil || password == "" {
		fmt.Fprintln(os.Stderr, "password entry cancelled or unavailable")
		return 3
	}
	resolver := sessionResolver{username: *username, password: password, key: key}
	cli := device.Endpoint{Port: uint16(*sshPort), CredentialRef: "session://lab", HostKeyRef: "hostkey://lab"}
	var observations []lab.ReadObservation
	var observerMu sync.Mutex
	observer := device.WithReadObserver(func(op device.Operation, raw []byte, complete, accepted bool) {
		observerMu.Lock()
		defer observerMu.Unlock()
		observations = append(observations, lab.ReadObservation{Operation: op, Data: raw, Complete: complete, Accepted: accepted})
	})
	client, err := device.NewClient(map[string]device.Target{"router": {Address: ip, CLI: &cli}}, resolver, time.Minute, observer)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid read-only transport policy")
		return 2
	}
	cfg := lab.Config{DeviceID: "router", Hostname: *hostname, TLSAddress: net.JoinHostPort(ip.String(), strconv.FormatUint(uint64(*httpsPort), 10))}
	if *netconfPort != 0 {
		modelClient, err := device.NewClient(map[string]device.Target{"router": {Address: ip, NETCONF: device.Endpoint{Port: uint16(*netconfPort), CredentialRef: cli.CredentialRef, HostKeyRef: cli.HostKeyRef}}}, resolver, time.Minute)
		if err != nil {
			return 2
		}
		cfg.NETCONF = func(ctx context.Context) (device.Evidence, error) { return modelClient.Collect(ctx, "router") }
	}
	report := lab.Run(context.Background(), client, cfg)
	report.WireReads = observations
	report.Target = map[string]string{"address": ip.String(), "hostname": *hostname, "username": *username, "hostKeySHA256": ssh.FingerprintSHA256(key), "authentication": "password dialog; process memory only"}
	path, err := lab.WriteReport(*directory, report)
	if err != nil {
		fmt.Fprintln(os.Stderr, "private evidence could not be saved")
		return 4
	}
	fmt.Printf("Read-only lab result: %s\nPrivate evidence: %s\n", report.Status, path)
	if report.Status == "PASS" {
		return 0
	}
	return 1
}

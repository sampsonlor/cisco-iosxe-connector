// iosxe-lab-assess applies an explicit acceptance scope to a saved private run.
// It does not connect to a device, issuer or ILM.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/lab"
)

func main() { os.Exit(run()) }
func run() int {
	scope := flag.String("scope", "", "approved scope: cli-only or netconf-and-cli")
	flag.Parse()
	if flag.NArg() != 1 || (*scope != string(lab.CLIOnly) && *scope != string(lab.NETCONFAndCLI)) {
		fmt.Fprintln(os.Stderr, "supply explicit approved --scope and absolute private report path")
		return 2
	}
	path, err := lab.AssessFile(flag.Arg(0), lab.Scope(*scope))
	if err != nil {
		fmt.Fprintln(os.Stderr, "private assessment could not be saved:", err)
		return 2
	}
	data, err := os.ReadFile(path)
	var a lab.Assessment
	if err != nil || json.Unmarshal(data, &a) != nil {
		return 2
	}
	fmt.Printf("Recorded-evidence assessment: %s (%s)\nPrivate assessment: %s\nNo new live test was executed.\n", a.Status, a.Scope, path)
	if a.Status != "PASS" {
		return 1
	}
	return 0
}

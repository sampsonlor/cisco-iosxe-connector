// iosxe-lab-replay checks private captured replies without any network access.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/sampsonlor/cisco-iosxe-connector/internal/lab"
)

func main() {
	if len(os.Args) != 2 || !filepath.IsAbs(os.Args[1]) {
		fmt.Fprintln(os.Stderr, "provide an absolute private report path")
		os.Exit(2)
	}
	path, err := filepath.EvalSymlinks(os.Args[1])
	if err != nil {
		os.Exit(2)
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		if _, err := os.Lstat(filepath.Join(parent, ".git")); err == nil {
			fmt.Fprintln(os.Stderr, "private report cannot be in a checkout")
			os.Exit(2)
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	f, err := os.Open(path)
	if err != nil {
		os.Exit(2)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<20)+1))
	if err != nil || len(data) > 64<<20 {
		os.Exit(2)
	}
	var report lab.Report
	if json.Unmarshal(data, &report) != nil {
		fmt.Fprintln(os.Stderr, "invalid private report")
		os.Exit(2)
	}
	s, err := lab.Replay(report)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	active, aliases := 0, 0
	for _, c := range s.Certificates {
		if c.Role == "ACTIVE" {
			active++
		}
		if c.SelfSignedIdentity {
			aliases++
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"mode": "OFFLINE_REPLAY", "inventoryComplete": s.Complete, "certificateOccurrences": len(s.Certificates), "activeIdentities": active, "selfSignedAliases": aliases})
}

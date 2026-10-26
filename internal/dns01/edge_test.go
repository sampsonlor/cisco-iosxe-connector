package dns01

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/sampsonlor/cisco-iosxe-connector/internal/journal"
)

func TestDNSFailedAddIntentCannotMutateAuthoritativeData(t *testing.T) {
	f := newFixture(t)
	c := f.challenge(t, 0, "intent")
	db, err := sql.Open("sqlite", f.path)
	must(t, err)
	defer db.Close()
	_, err = db.Exec("CREATE TRIGGER deny_dns_add BEFORE UPDATE ON dns_claims WHEN NEW.state='ADDING' BEGIN SELECT RAISE(ABORT,'synthetic private storage diagnostic'); END")
	must(t, err)
	if err := f.p.Present(context.Background(), c); !errors.Is(err, journal.ErrStore) || strings.Contains(err.Error(), "private storage diagnostic") {
		t.Fatal("uncommitted intent authorized update or leaked diagnostics", err)
	}
	if f.wire.adds != 0 || f.wire.deletes != 0 {
		t.Fatal("side effect before committed intent")
	}
}

func TestDNSCleanupRequiresMarkerAndExactTXTEncoding(t *testing.T) {
	for _, mode := range []string{"missing-marker", "changed-TXT-chunks", "concurrent-write"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			c := f.challenge(t, 0, mode)
			must(t, f.p.Present(context.Background(), c))
			owner, marker := journal.DNSNames(c.Identifier)
			original := f.wire.records[marker]
			switch mode {
			case "missing-marker":
				f.wire.records[marker] = nil
			case "changed-TXT-chunks":
				f.wire.records[owner][0].(*dns.TXT).Txt = []string{c.TXTValue[:20], c.TXTValue[20:]}
			case "concurrent-write":
				f.wire.conflicts = 1
			}
			err := f.p.Cleanup(context.Background(), c)
			if mode == "concurrent-write" {
				must(t, err)
				if !has(f.wire.records[owner], "concurrent-0") || has(f.wire.records[owner], c.TXTValue) {
					t.Fatal("concurrent TXT erased")
				}
				return
			}
			if !errors.Is(err, ErrReconcile) || f.wire.deletes != 0 || !has(f.wire.records[owner], c.TXTValue) {
				t.Fatal("unproven ownership deleted", err)
			}
			// Explicit restored authoritative ownership/encoding permits cleanup.
			f.wire.records[marker] = original
			f.wire.records[owner][0].(*dns.TXT).Txt = []string{c.TXTValue}
			must(t, f.p.Cleanup(context.Background(), c))
		})
	}
}

func TestDNSConfigurationIsScopedFrozenAndRejectsRebinding(t *testing.T) {
	f := newFixture(t)
	for _, mutate := range []func(*Config){
		func(c *Config) { c.ServerAddress = "dns.example.test:53" },
		func(c *Config) { c.Resolvers = []string{"0.0.0.0:53"} },
		func(c *Config) { c.CredentialRef = "secret\nref" },
		func(c *Config) { c.ViewRef = "" },
		func(c *Config) { c.Mode = "unverified-mode" },
		func(c *Config) { c.Zone = "outside.test." },
		func(c *Config) { c.Targets[0].PolicySHA256 = strings.Repeat("z", 64) },
		func(c *Config) { c.Targets[0].LocationID = "not-a-location" },
		func(c *Config) { c.Targets[0].Identifier = "*.example.test" },
	} {
		c := f.cfg
		c.Targets = append([]Target(nil), c.Targets...)
		mutate(&c)
		if _, err := newWithWire(c, f.s, f.wire); !errors.Is(err, ErrPolicy) {
			t.Fatal("unsafe host configuration accepted", err)
		}
	}
	c := f.challenge(t, 0, "freeze")
	original := f.cfg.Targets[0]
	f.cfg.Targets[0].Identifier = "changed.example.test"
	must(t, f.p.Present(context.Background(), c))
	f.cfg.Targets[0] = original
	f.cfg.ViewRef = "view://changed"
	p, err := newWithWire(f.cfg, f.s, f.wire)
	must(t, err)
	if err := p.Cleanup(context.Background(), c); !errors.Is(err, ErrPolicy) {
		t.Fatal("unfinished challenge rebound to another view", err)
	}
	must(t, f.p.Cleanup(context.Background(), c))
}

func TestDNSCancelledACMEFlowAllowsOnlyRecordedCleanup(t *testing.T) {
	f := newFixture(t)
	c := f.challenge(t, 0, "cancelled-flow")
	must(t, f.p.Present(context.Background(), c))
	op, err := f.s.DNSOperation(context.Background(), request(c))
	must(t, err)
	flow, err := f.s.ACMEStatus(context.Background(), op.Ref())
	must(t, err)
	flow.CancelRequested = true
	_, err = f.s.SaveACME(context.Background(), op.Ref(), flow.Revision, flow)
	must(t, err)
	before := f.wire.opens
	if err := f.p.Present(context.Background(), c); !errors.Is(err, journal.ErrState) {
		t.Fatal("cancelled flow presented again", err)
	}
	if f.wire.opens != before {
		t.Fatal("cancelled presentation reached DNS")
	}
	must(t, f.p.Cleanup(context.Background(), c))
}
